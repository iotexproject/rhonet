"""RhoNet coordinator (v1: single operator).

Responsibilities, in the order a DP passes through them:
  admission  -> curve-native ticket replayed once per identity, slow-start quota
  intake     -> signature check, format check, uniqueness, retryable work identifiers
  ledger     -> credited_steps per miner (1 credit = 2^credit_unit_log2 steps)
  collision  -> same x from two different walks -> solve k, verify k*G == Q, end round
  epochs     -> every epoch_seconds: Merkle root over (payout_addr, credited_steps), the thing
                that would be posted to the L2 PrizeVault; proofs served to miners

The epoch root alone is insufficient when one participant dominates: that miner
can predict its balance and root before submitting. A post-seal external beacon,
or the single operator's private commit-then-reveal secret, closes that gap.
The fallback trusts the operator to keep its secret private until the batch is sealed;
it does not protect against an operator colluding with miners.

State lives in one sqlite file; the coordinator can be restarted at any time.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import multiprocessing
import json
import math
import os
import secrets
from urllib.request import urlopen
import sqlite3
import threading
import time
from contextlib import contextmanager
from collections import Counter, deque
from functools import wraps

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import ec, merkle

MAX_TELEMETRY_PER_SUBMISSION = 1 << 40

def _env_num(name, default, cast=float):
    return cast(os.environ.get(name, default))


# How many of one identity's points may sit in a still-open epoch, unverified.
# It bounds coordinator exposure, not fraud -- sampling bounds fraud whatever the
# volume, and unaudited points earn nothing until their epoch closes and is
# audited. It was 4096, which on Exercise 97 caps an identity near 600 M steps per
# second: below one current GPU, and so a throttle on exactly the contributors the
# round is trying to attract. Beyond the gate, the per-epoch quota still applies.
MAX_AUDIT_BACKLOG_DPS = _env_num("RHONET_AUDIT_BACKLOG_DPS", 65536, int)


STATUS_CACHE_SECONDS = _env_num("RHONET_STATUS_CACHE_SECONDS", 1.0)


# Per-key stops identity spam; the gate bounds work. Per-IP is a coarse guard
# that allows a small fleet sharing a home IP to start together.
TICKET_IP_RATE = _env_num("RHONET_TICKET_IP_RATE", 0.5)
TICKET_IP_BURST = _env_num("RHONET_TICKET_IP_BURST", 16, int)
TICKET_KEY_RATE = _env_num("RHONET_TICKET_KEY_RATE", 0.1)
TICKET_KEY_BURST = _env_num("RHONET_TICKET_KEY_BURST", 2, int)
SUBMIT_IP_RATE = _env_num("RHONET_SUBMIT_IP_RATE", 5)
SUBMIT_IP_BURST = _env_num("RHONET_SUBMIT_IP_BURST", 20, int)
SUBMIT_KEY_RATE = _env_num("RHONET_SUBMIT_KEY_RATE", 5)
SUBMIT_KEY_BURST = _env_num("RHONET_SUBMIT_KEY_BURST", 20, int)
# Answering an audit is an obligation with a deadline, so it must not share the
# submission bucket: an identity owing hundreds of openings would be rate limited
# into silence and slashed for it. The real cost here is the segment replay, which
# AUDIT_GATE bounds independently, so this bucket only sheds malformed floods.
AUDIT_IP_RATE = _env_num("RHONET_AUDIT_IP_RATE", 100)
AUDIT_IP_BURST = _env_num("RHONET_AUDIT_IP_BURST", 400, int)
AUDIT_KEY_RATE = _env_num("RHONET_AUDIT_KEY_RATE", 50)
AUDIT_KEY_BURST = _env_num("RHONET_AUDIT_KEY_BURST", 200, int)
# How fast we assume a client can answer, when deciding how long to give it.
AUDIT_ANSWER_RATE = _env_num("RHONET_AUDIT_ANSWER_RATE", 2.0)
TICKET_CONCURRENCY = _env_num("RHONET_TICKET_CONCURRENCY", 4, int)
# Sync FastAPI waiters occupy threadpool threads; keep this queue modest.
TICKET_QUEUE = _env_num("RHONET_TICKET_QUEUE", 64, int)
TICKET_WAIT_SECONDS = _env_num("RHONET_TICKET_WAIT_SECONDS", 30.0)


class TicketGate:
    """Bound verification concurrency and queued waiters; shed excess immediately."""
    def __init__(self, concurrency, max_queue, wait_seconds):
        self.slots = threading.BoundedSemaphore(concurrency)
        self.lock = threading.Lock()
        self.waiting = 0
        self.max_queue = max_queue
        self.wait_seconds = wait_seconds

    @contextmanager
    def enter(self):
        acquired = self.slots.acquire(blocking=False)
        if not acquired:
            with self.lock:
                if self.waiting >= self.max_queue:
                    raise HTTPException(503, "ticket queue full")
                self.waiting += 1
            try:
                acquired = self.slots.acquire(timeout=self.wait_seconds)
            finally:
                with self.lock:
                    self.waiting -= 1
            if not acquired:
                raise HTTPException(503, "ticket queue full")
        try:
            yield
        finally:
            self.slots.release()


TICKET_GATE = TicketGate(TICKET_CONCURRENCY, TICKET_QUEUE, TICKET_WAIT_SECONDS)


AUDIT_WORKERS = max(1, _env_num("RHONET_AUDIT_PROCESSES", min(4, os.cpu_count() or 1), int))
AUDIT_GATE = TicketGate(AUDIT_WORKERS, 64, 30)
_AUDIT_POOL = None
_AUDIT_POOL_LOCK = threading.Lock()


def run_audit_job(spec, table, pubkey, dp, segment, opening):
    started = time.monotonic()
    ok, steps = ec.verify_segment(spec, table, pubkey, dp, segment, opening)
    return ok, steps, time.monotonic()-started, os.getpid()


def audit_pool():
    global _AUDIT_POOL
    with _AUDIT_POOL_LOCK:
        if _AUDIT_POOL is None:
            _AUDIT_POOL = concurrent.futures.ProcessPoolExecutor(
                max_workers=AUDIT_WORKERS, mp_context=multiprocessing.get_context("spawn"))
        return _AUDIT_POOL


class RateLimiter:
    """Thread-safe token buckets; idle, fully refilled buckets are discarded."""
    def __init__(self, rate_per_sec, burst):
        self.rate = rate_per_sec
        self.burst = burst
        self.lock = threading.Lock()
        self.buckets = {}
        self.next_cleanup = 0.0

    def allow(self, key) -> bool:
        with self.lock:
            timestamp = time.monotonic()
            if timestamp >= self.next_cleanup:
                self.buckets = {k: (tokens, ts) for k, (tokens, ts) in self.buckets.items()
                                if tokens + (timestamp - ts) * self.rate < self.burst}
                self.next_cleanup = timestamp + 60
            tokens, ts = self.buckets.get(key, (self.burst, timestamp))
            tokens = min(self.burst, tokens + (timestamp - ts) * self.rate)
            allowed = tokens >= 1
            self.buckets[key] = (tokens - 1 if allowed else tokens, timestamp)
            return allowed


def db_locked(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return wrapped


STATIC = os.path.join(os.path.dirname(__file__), "static")

SCHEMA = """
CREATE TABLE IF NOT EXISTS miners (
  miner_idx INTEGER UNIQUE, pubkey TEXT PRIMARY KEY, payout_addr TEXT NOT NULL, ticket TEXT NOT NULL,
  admitted_at REAL NOT NULL, admitted_epoch INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', dps INTEGER NOT NULL DEFAULT 0,
  credited_steps INTEGER NOT NULL DEFAULT 0, spot_checks INTEGER NOT NULL DEFAULT 0,
  spot_fails INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0,
  epoch_dps INTEGER NOT NULL DEFAULT 0, epoch_dps_epoch INTEGER NOT NULL DEFAULT -1,
  next_t INTEGER NOT NULL DEFAULT 0,
  executed_steps INTEGER NOT NULL DEFAULT 0,
  abandoned_walks INTEGER NOT NULL DEFAULT 0,
  ticket_steps INTEGER NOT NULL DEFAULT 0,
  last_seq INTEGER NOT NULL DEFAULT -1,
  last_seen REAL, note TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS miners_idx ON miners(miner_idx);
CREATE TRIGGER IF NOT EXISTS assign_miner_idx AFTER INSERT ON miners
WHEN NEW.miner_idx IS NULL BEGIN
  UPDATE miners SET miner_idx=(SELECT COALESCE(MAX(miner_idx),0)+1 FROM miners)
  WHERE pubkey=NEW.pubkey;
END;
CREATE TABLE IF NOT EXISTS audit_candidates (
  epoch_idx INTEGER NOT NULL, tag TEXT NOT NULL, ordinal INTEGER NOT NULL,
  miner_idx INTEGER NOT NULL, t INTEGER NOT NULL,
  PRIMARY KEY(epoch_idx, tag, ordinal)
);
CREATE TABLE IF NOT EXISTS dps (
  x TEXT NOT NULL, y TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL,
  pubkey TEXT NOT NULL, t INTEGER NOT NULL, steps INTEGER NOT NULL,
  ts REAL NOT NULL, checked INTEGER NOT NULL DEFAULT 0,
  epoch INTEGER NOT NULL DEFAULT -1,
  slashed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (pubkey, t)
);
CREATE INDEX IF NOT EXISTS dps_x ON dps(x);
CREATE INDEX IF NOT EXISTS dps_epoch_checked ON dps(epoch, checked);
CREATE TABLE IF NOT EXISTS epochs (
  idx INTEGER PRIMARY KEY, ts REAL NOT NULL, root TEXT NOT NULL,
  total_steps INTEGER NOT NULL, n_miners INTEGER NOT NULL, leaves TEXT NOT NULL,
  sealed_root TEXT, audit_seed_root TEXT,
  beacon_commitment TEXT, beacon_reveal TEXT, beacon_source TEXT, audit_inputs TEXT, audit_counts TEXT NOT NULL DEFAULT '{}',
  audit_complete INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS checkpoints (
  pubkey TEXT NOT NULL, t INTEGER NOT NULL, root TEXT NOT NULL,
  PRIMARY KEY(pubkey,t)
);
CREATE TABLE IF NOT EXISTS withheld (
  epoch INTEGER NOT NULL, pubkey TEXT NOT NULL, steps INTEGER NOT NULL,
  PRIMARY KEY (epoch, pubkey)
);
CREATE TABLE IF NOT EXISTS challenges (
  epoch INTEGER NOT NULL, pubkey TEXT NOT NULL, t INTEGER NOT NULL,
  segment INTEGER NOT NULL, deadline REAL NOT NULL, result TEXT,
  PRIMARY KEY(epoch,pubkey,t)
);
CREATE TABLE IF NOT EXISTS audit_openings (
  epoch INTEGER NOT NULL, pubkey TEXT NOT NULL, t INTEGER NOT NULL, opening TEXT NOT NULL,
  PRIMARY KEY(epoch,pubkey,t)
);
CREATE TABLE IF NOT EXISTS epoch_payments (
  epoch INTEGER NOT NULL, pubkey TEXT NOT NULL, payout_addr TEXT NOT NULL,
  steps INTEGER NOT NULL, PRIMARY KEY(epoch,pubkey)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def migrate_schema(db):
    """Upgrade existing tables before SCHEMA creates indexes on new columns."""
    for table, column, default in (("dps", "epoch", -1), ("dps", "slashed", 0),
                                   ("miners", "last_seq", -1), ("miners", "next_t", 0),
                                   ("miners", "executed_steps", 0),
                                   ("miners", "abandoned_walks", 0), ("miners", "ticket_steps", 0)):
        try:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER NOT NULL DEFAULT {default}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc) and "no such table" not in str(exc):
                raise
    # A named column stays stable across VACUUM, unlike an implicit rowid.
    columns = {row[1] for row in db.execute("PRAGMA table_info(miners)")}
    if "t_gaps" in columns:
        db.execute("ALTER TABLE miners DROP COLUMN t_gaps")
    if columns and "miner_idx" not in columns:
        db.execute("ALTER TABLE miners ADD COLUMN miner_idx INTEGER")
    if columns:
        db.execute("UPDATE miners SET miner_idx=rowid WHERE miner_idx IS NULL")
    for column, definition in (("sealed_root", "TEXT"), ("audit_seed_root", "TEXT"), ("audit_counts", "TEXT NOT NULL DEFAULT '{}'"),
                               ("beacon_commitment", "TEXT"), ("beacon_reveal", "TEXT"),
                               ("beacon_source", "TEXT"), ("audit_inputs", "TEXT"),
                               ("audit_complete", "INTEGER NOT NULL DEFAULT 1")):
        try:
            db.execute(f"ALTER TABLE epochs ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc) and "no such table" not in str(exc):
                raise
    db.commit()


def valid_payout_addr(s) -> bool:
    if not isinstance(s, str) or not s.startswith("0x") or len(s) != 42:
        return False
    try:
        return len(bytes.fromhex(s[2:])) == 20
    except ValueError:
        return False


def now() -> float:
    return time.time()


class Coordinator:
    def __init__(self, spec: ec.RoundSpec, db_path: str):
        spec.validate()
        self._status_cache = None
        self.beacon_url = os.environ.get("RHONET_BEACON_URL", "")
        if spec.funded and not self.beacon_url:
            raise ValueError("funded round requires RHONET_BEACON_URL")
        self.spec = spec
        self.table = ec.walk_table(spec)
        # One shared sqlite connection remains; short DB sections use this lock.
        # A connection pool is deferred. Epoch serialization does not block intake.
        self.lock = threading.RLock()
        self.epoch_lock = threading.Lock()
        self.beacon_lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA busy_timeout=5000")
        migrate_schema(self.db)
        self.db.executescript(SCHEMA)
        fingerprint = spec.to_dict()
        previous_spec = self._get_state("round_spec")
        if previous_spec is not None:
            previous_spec = ec.RoundSpec.from_dict(previous_spec).to_dict()
        if previous_spec is not None and previous_spec != fingerprint:
            self.db.close()
            raise ValueError("database belongs to a different round specification")
        self._set_state("round_spec", fingerprint)
        self._migrate_audit_inputs()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.commit()
        self.epoch_loop_failures = 0
        self._last_epoch_error = float("-inf")
        self.db.execute("UPDATE dps SET slashed=1 WHERE pubkey IN (SELECT pubkey FROM miners WHERE status='slashed')")
        self.db.commit()
        self.registry_dir = os.environ.get("RHONET_REGISTRY", os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "contributors"))
        self.registry = {}
        self.devices = {}
        self.reload_registry()
        self.rate_window = deque(maxlen=600)  # (ts, steps) for live throughput
        self.started_at = float(self._get_state("started_at") or now())
        self._set_state("started_at", self.started_at)
        if not self._get_state("status"):
            self._set_state("status", "open")
            self.event("round_open", {"round_id": spec.round_id, "bits": spec.bits})

        self.current_epoch()  # Publish the opening commitment before intake.
        if self.status == "settling" and self._get_state("pending_solution"):
            self._finish(*self._get_state("pending_solution"))

    # ---------------------------------------------------------------- state helpers
    @db_locked
    def _get_state(self, k):
        row = self.db.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
        return json.loads(row[0]) if row else None

    @db_locked
    def _set_state(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO state(k, v) VALUES(?, ?)", (k, json.dumps(v)))
        self.db.commit()

    @property
    def status(self) -> str:
        return self._get_state("status")

    @db_locked
    def event(self, kind: str, detail: dict):
        self.db.execute("INSERT INTO events(ts, kind, detail) VALUES(?, ?, ?)", (now(), kind, json.dumps(detail)))
        self.db.commit()

    def current_epoch(self) -> int:
        idx = int((now() - self.started_at) // self.spec.epoch_seconds)
        self._open_epoch(idx)
        return idx

    @db_locked
    def _open_epoch(self, idx):
        if self.db.execute("SELECT 1 FROM epochs WHERE idx=?", (idx,)).fetchone():
            return
        source = self.beacon_url or "commit-reveal"
        secret = secrets.token_bytes(32) if not self.beacon_url else None
        if secret is not None:
            # Private durable state, deliberately excluded from all public views.
            self.db.execute("INSERT INTO state(k,v) VALUES(?,?)",
                            (f"beacon_secret:{idx}", json.dumps(secret.hex())))
        self.db.execute(
            "INSERT INTO epochs(idx,ts,root,total_steps,n_miners,leaves,beacon_commitment,beacon_source,audit_complete) "
            "VALUES(?,?,'',0,0,'[]',?,?,0)",
            (idx, now(), ec.H(secret).hex() if secret is not None else None, source))
        self.db.commit()

    def beacon_for(self, epoch) -> bytes:
        """Return cached per-epoch entropy. HTTP failures abort closure, never downgrade.

        The URL may contain {epoch} and {root}; it must return a 32-byte hex hash
        as plain text, a JSON string, or an object carrying it under "randomness"
        (drand) or "hash". Production must bind this to an external event after the
        sealed batch commitment, unknown at seal time.
        {root} is the sealed batch commitment, never the payment root.
        Fetch only after sealing. Publish the reveal with the durable challenge plan.
        """
        with self.beacon_lock:
            return self._beacon_for(epoch)

    def _beacon_for(self, epoch):
        with self.lock:
            self._open_epoch(epoch)
            root, source, reveal = self.db.execute(
                "SELECT sealed_root,beacon_source,beacon_reveal FROM epochs WHERE idx=?", (epoch,)).fetchone()
            cached = reveal or self._get_state(f"beacon_value:{epoch}")
        if cached is not None:
            return bytes.fromhex(cached)
        if source == "commit-reveal":
            return bytes.fromhex(self._get_state(f"beacon_secret:{epoch}"))
        if not root:
            raise RuntimeError("external beacon requires a sealed batch commitment")
        with urlopen(source.format(epoch=epoch, root=root), timeout=5) as response:
            raw = response.read(4097)
        if len(raw) > 4096:
            raise ValueError("beacon response too large")
        value = raw.decode().strip()
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
        if isinstance(value, dict):
            # drand publishes the value under "randomness"; prefer it. Its /info
            # endpoint also carries a "hash", which is the *chain* identifier and
            # never changes, so reading "hash" first would silently turn a
            # misconfigured URL into a constant beacon.
            value = value.get("randomness") or value.get("hash")
        if not isinstance(value, str):
            raise ValueError("beacon must return a hex hash")
        beacon = bytes.fromhex(value.removeprefix("0x"))
        if len(beacon) != 32:
            raise ValueError("beacon must be 32 bytes")
        # A beacon that repeats is not a beacon. Whatever the cause -- a pinned
        # URL, a cached response, an endpoint returning a constant -- the audit
        # becomes predictable, so refuse to close the epoch rather than run an
        # audit that guarantees nothing.
        previous = self.db.execute(
            "SELECT beacon_reveal FROM epochs WHERE idx<? AND beacon_reveal IS NOT NULL "
            "ORDER BY idx DESC LIMIT 1", (epoch,)).fetchone()
        if previous and previous[0] == beacon.hex():
            raise ValueError("external beacon repeated the previous epoch's value; "
                             "the audit would be predictable, so the epoch stays open")
        self._set_state(f"beacon_value:{epoch}", beacon.hex())
        return beacon

    # ---------------------------------------------------------------- crypto
    @staticmethod
    def verify_sig(pubkey_hex: str, body: dict, sig_hex: str):
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
            pk.verify(bytes.fromhex(sig_hex), ec.sign_bytes_for(body))
        except (ValueError, TypeError, KeyError, InvalidSignature):
            raise HTTPException(401, "bad signature")

    def _check_freshness(self, pubkey, freshness):
        # Called under the DB lock; HTTP always supplies both signed fields.
        epoch, seq = freshness
        # Epoch is unsigned on the wire, so the window is clamped at zero rather
        # than reaching -1 in the first epoch of a round.
        if type(epoch) is not int or epoch < 0 or abs(epoch - self.current_epoch()) > 1:
            raise HTTPException(400, "stale submission")
        if type(seq) is not int or not 0 <= seq < (1 << 63):
            raise HTTPException(400, "invalid seq")
        row = self.db.execute("SELECT last_seq FROM miners WHERE pubkey=?", (pubkey,)).fetchone()
        if row and seq <= row[0]:
            raise HTTPException(400, "replayed submission")

    def _accept_seq(self, pubkey, freshness):
        if freshness is not None:
            self.db.execute("UPDATE miners SET last_seq=? WHERE pubkey=?", (freshness[1], pubkey))
            self.db.commit()

    def rotate(self, body: dict):
        body = dict(body)
        sig = body.pop("sig", "")
        if body.get("round_id") != self.spec.round_id:
            raise HTTPException(400, "wrong round_id")
        self.verify_sig(body.get("pubkey"), body, sig)
        pk = body["pubkey"]
        address = body.get("payout_addr")
        if not valid_payout_addr(address):
            raise HTTPException(400, "payout_addr must be a 20-byte hex address")
        with self.lock:
            row = self.db.execute("SELECT status, payout_addr FROM miners WHERE pubkey=?", (pk,)).fetchone()
            if not row or row[0] == "slashed":
                raise HTTPException(403, "identity slashed or unknown")
            freshness = (body.get("epoch"), body.get("seq"))
            self._check_freshness(pk, freshness)
            # Rotates the payout target, not the identity key. Already-closed
            # epoch leaves retain the old address because they are committed.
            self.db.execute("UPDATE miners SET payout_addr=? WHERE pubkey=?", (address.lower(), pk))
            self._accept_seq(pk, freshness)
            self.event("payout_rotated", {"pubkey": pk[:16], "old": row[1], "new": address.lower()})
            return {"rotated": True, "epoch": self.current_epoch(), "payout_addr": address.lower()}

    # ---------------------------------------------------------------- admission
    def admit(self, pubkey: str, payout_addr: str, ticket: dict, freshness=None, device=None):
        spec = self.spec
        with self.lock:
            if self.status != "open":
                raise HTTPException(409, f"round is {self.status}")
            if not valid_payout_addr(payout_addr):
                raise HTTPException(400, "payout_addr must be a 20-byte hex address")
            if freshness is not None:
                self._check_freshness(pubkey, freshness)
            row = self.db.execute("SELECT status FROM miners WHERE pubkey=?", (pubkey,)).fetchone()
            if row:
                if row[0] == "slashed":
                    raise HTTPException(403, "identity slashed; mint a new ticket with a new key")
                self._accept_seq(pubkey, freshness)
                return {"admitted": True, "already": True, "epoch": self.current_epoch()}
        t0 = time.time()
        try:
            ok = ec.ticket_verify(spec, self.table, pubkey, ticket)
        except (KeyError, TypeError, ValueError, OverflowError):
            ok = False
        if not ok:
            self.event("ticket_rejected", {"pubkey": pubkey[:16]})
            raise HTTPException(400, "ticket does not replay")
        with self.lock:
            if self.status != "open":
                raise HTTPException(409, f"round is {self.status}")
            if freshness is not None:
                self._check_freshness(pubkey, freshness)
            row = self.db.execute("SELECT status FROM miners WHERE pubkey=?", (pubkey,)).fetchone()
            if row:
                if row[0] == "slashed":
                    raise HTTPException(403, "identity slashed; mint a new ticket with a new key")
                self._accept_seq(pubkey, freshness)
                return {"admitted": True, "already": True, "epoch": self.current_epoch()}
            ep = self.current_epoch()
            self.db.execute(
                "INSERT INTO miners(pubkey, payout_addr, ticket, admitted_at, admitted_epoch, last_seen, ticket_steps) VALUES(?,?,?,?,?,?,?)",
                # Successful verification independently recomputed this exact count.
                (pubkey, payout_addr.lower(), json.dumps(ticket), now(), ep, now(), int(ticket["steps"])),
            )
            if isinstance(device, str) and 0 < len(device) <= 80:
                self.devices[pubkey] = device
            self.db.commit()
            self._accept_seq(pubkey, freshness)
            self.event("miner_admitted", {"pubkey": pubkey[:16], "ticket_steps": ticket["steps"], "verify_ms": round((time.time() - t0) * 1000)})
            return {"admitted": True, "already": False, "epoch": ep}

    def quota(self, admitted_epoch: int) -> int:
        """Slow start: doubles every epoch since admission, capped."""
        age = max(0, self.current_epoch() - admitted_epoch)
        return min(self.spec.quota_dps_per_epoch_base << min(age, 10), 1 << 30)

    # ---------------------------------------------------------------- intake
    def submit(self, pubkey: str, dps: list[dict], steps_done=0, abandoned=0, freshness=None):
        spec = self.spec
        if len(dps) > 5000:
            raise HTTPException(413, "batch too large")
        # Untrusted telemetry never participates in DP validation or payment credit.
        def telemetry(value):
            if type(value) is not int:
                raise HTTPException(400, "telemetry counters must be integers")
            return max(0, min(value, MAX_TELEMETRY_PER_SUBMISSION))

        executed, abandoned = telemetry(steps_done), telemetry(abandoned)
        p, n, w = spec.curve.p, spec.curve.n, spec.w
        validated, rejected = [], []
        for i, dp in enumerate(dps):
            try:
                x, y, a, b, t, steps = (int(dp[k]) for k in ("x", "y", "a", "b", "t", "steps"))
            except (KeyError, ValueError, TypeError, OverflowError):
                rejected.append((i, "malformed")); continue
            if not (0 <= x < p and 0 <= y < p and 0 <= a < n and 0 <= b < n and 0 < steps and 0 <= t < (1 << 63)):
                rejected.append((i, "range")); continue
            if steps > ec.MAX_REPLAY_STEPS(spec):
                rejected.append((i, "walk too long")); continue
            if not ec.is_dp(x, w):
                rejected.append((i, "not a distinguished point")); continue
            if not spec.curve.on_curve((x, y)):
                rejected.append((i, "not on curve")); continue
            root = dp.get("checkpoint_root")
            try:
                if not isinstance(root, str) or len(root) != 64 or len(bytes.fromhex(root)) != 32:
                    raise ValueError()
            except ValueError:
                rejected.append((i, "missing or invalid checkpoint commitment")); continue
            validated.append((i, dict(x=x, y=y, a=a, b=b, t=t, steps=steps, checkpoint_root=root)))
        with self.lock:
            if freshness is not None:
                self._check_freshness(pubkey, freshness)
            if self.status != "open":
                self._accept_seq(pubkey, freshness)
                return {"accepted": 0, "rejected": [], "status": self.status, "solved": self._get_state("solution")}
            m = self.db.execute(
                "SELECT status, admitted_epoch, epoch_dps, epoch_dps_epoch, next_t FROM miners WHERE pubkey=?", (pubkey,)
            ).fetchone()
            if not m:
                raise HTTPException(403, "no ticket for this identity")
            status, admitted_epoch, epoch_dps, epoch_dps_epoch, next_t = m
            if status == "slashed":
                raise HTTPException(403, "identity slashed")
            self._accept_seq(pubkey, freshness)
            ep = self.current_epoch()
            if epoch_dps_epoch != ep:
                epoch_dps, epoch_dps_epoch = 0, ep
            q = self.quota(admitted_epoch)

            backlog = self.db.execute(
                "SELECT COUNT(*) FROM dps WHERE pubkey=? AND checked=0 AND slashed=0 AND epoch NOT IN (SELECT idx FROM epochs WHERE audit_complete=1)", (pubkey,)).fetchone()[0]
            paused = bool(self._get_state(f"intake_paused:{pubkey}"))
            if paused and backlog <= MAX_AUDIT_BACKLOG_DPS // 2:
                paused = False
            accepted, checked = 0, 0
            credited = 0
            solved = None
            slashed = halted = False
            for i, dp in validated:
                x, y, a, b, t, steps = (dp[k] for k in ("x", "y", "a", "b", "t", "steps"))
                # Duplicate delivery (including a lost HTTP response) is harmless.
                if self.db.execute("SELECT 1 FROM dps WHERE pubkey=? AND t=?", (pubkey, t)).fetchone():
                    rejected.append((i, "duplicate")); continue
                if paused or backlog >= MAX_AUDIT_BACKLOG_DPS:
                    paused = True
                    rejected.append((i, "audit backlog")); continue
                if epoch_dps >= q:
                    rejected.append((i, "quota")); continue

                # collision check against every earlier walk that hit this x
                prior = self.db.execute("SELECT pubkey, t, x, y, a, b, steps FROM dps WHERE x=?", (str(x),)).fetchall()
                self.db.execute(
                    "INSERT INTO dps(x, y, a, b, pubkey, t, steps, ts, checked, epoch) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (str(x), str(y), str(a), str(b), pubkey, t, steps, now(), 0, ep),
                )
                self.db.execute("INSERT INTO checkpoints VALUES(?,?,?)", (pubkey, t, dp["checkpoint_root"]))
                # Arbitrary identifiers are safe: each identity owes ceil(k/N)
                # challenges regardless of which identifiers it chooses.
                # Never retire missing identifiers: workers finish out of order,
                # abandon walks, and retry capacity-deferred work. The database
                # primary key supplies deduplication without an in-memory window.
                while self.db.execute("SELECT 1 FROM dps WHERE pubkey=? AND t=?",
                                      (pubkey, next_t)).fetchone():
                    next_t += 1
                accepted += 1
                backlog += 1
                epoch_dps += 1
                credited += 1 << w
                for (ppk, pt, px, py, pa, pb, psteps) in prior:
                    other = dict(t=pt, x=px, y=py, a=pa, b=pb, steps=psteps)
                    # Collision replay stays locked to preserve atomic resolution;
                    # a successful collision is a once-per-round event.
                    # Never trust a stored row's checked flag for a collision.
                    ok_new = self._full_verify(pubkey, dp)
                    ok_prior = self._full_verify(ppk, other)
                    if not ok_new or not ok_prior:
                        failures = []
                        for pk, segment, ok in ((pubkey, dp, ok_new), (ppk, other, ok_prior)):
                            if not ok:
                                failures.append(self._collision_evidence(pk, segment))
                                self.db.execute("DELETE FROM dps WHERE pubkey=? AND t=?", (pk, int(segment["t"])))
                                self._slash(pk, f"collision replay failed t={segment['t']}")
                        if not ok_new and not ok_prior:
                            self.event("collision_both_invalid", {"segments": failures})
                        else:
                            self.event("collision_replay_failed", failures[0])
                        if not ok_new or ppk == pubkey:
                            # A failed earlier segment can also implicate the sender.
                            slashed = True
                            break
                        continue
                    self.db.executemany("UPDATE dps SET checked=1 WHERE pubkey=? AND t=?",
                                        [(pubkey, t), (ppk, pt)])
                    result = ec.solve_collision_detail(spec, dp, other)
                    kind = result["kind"]
                    if kind == "solved":
                        solved = (result["k"], pubkey, ppk, x)
                        break
                    if kind in ("degenerate_same_y", "degenerate_opposite_y"):
                        self._set_state("degenerate_collisions", (self._get_state("degenerate_collisions") or 0) + 1)
                        self.event("degenerate_collision", {"kind": kind, "x": str(x), "pubkeys": [pubkey[:16], ppk[:16]]})
                        continue
                    if kind == "bad_k":
                        self._set_state("status", "halted_for_review")
                        self.event("halted_for_review", {
                            "segments": [self._collision_evidence(pubkey, dp), self._collision_evidence(ppk, other)],
                            "k": str(result["k"]),
                        })
                        halted = True
                        break
                if slashed:
                    # Keep a valid new row if a failed earlier row slashed this
                    # same identity. Only failed replay rows are removed.
                    if not self.db.execute("SELECT 1 FROM dps WHERE pubkey=? AND t=?", (pubkey, t)).fetchone():
                        accepted -= 1
                        epoch_dps -= 1
                    credited = 0  # Slashing forfeits all credit, including this batch.
                if solved or slashed or halted:
                    break

            self.db.execute(
                "UPDATE miners SET dps=dps+?, credited_steps=credited_steps+?, spot_checks=spot_checks+?, rejected=rejected+?, "
                "epoch_dps=?, epoch_dps_epoch=?, last_seen=?, next_t=?, "
                "executed_steps=executed_steps+?, abandoned_walks=abandoned_walks+? WHERE pubkey=?",
                (accepted, credited, checked, len(rejected), epoch_dps, epoch_dps_epoch, now(), next_t, executed, abandoned, pubkey),
            )
            self.db.commit()
            self.rate_window.append((now(), executed))
            if slashed:
                return {"accepted": accepted, "rejected": rejected, "slashed": True}
            if halted:
                return {"accepted": accepted, "rejected": rejected, "checked": checked, "status": self.status}
            self._set_state(f"intake_paused:{pubkey}", paused)
            retry_indices = [i for i, reason in rejected if reason in ("audit backlog", "quota")]
            out = {"retry_indices": retry_indices,
                   "retry_after": min(2.0, self.spec.epoch_seconds) if retry_indices else 0,
                   "batch_limit": 1 if paused else max(1, min(256, MAX_AUDIT_BACKLOG_DPS - backlog, q - epoch_dps)),
                   "accepted": accepted, "rejected": rejected, "checked": checked, "quota_left": q - epoch_dps, "epoch": ep}
            if solved:
                self._set_state("status", "settling")
                self._set_state("pending_solution", solved)
        if solved:
            out["solved"] = self._finish(*solved)
        return out

    def _collision_evidence(self, pubkey: str, dp: dict) -> dict:
        start = ec.derive_start(self.spec, pubkey, int(dp["t"]))
        steps = int(dp["steps"])
        result = (ec.replay(self.spec, self.table, *start, steps)
                  if 0 < steps <= ec.MAX_REPLAY_STEPS(self.spec) else None)
        if result is not None:
            self._count_replay(steps)
        replayed = dict.fromkeys(("a", "b", "x", "y"), "None")
        if result is not None:
            a, b, point = result
            replayed.update(a=str(a), b=str(b))
            if point is not ec.INF:
                replayed.update(x=str(point[0]), y=str(point[1]))
        return {"pubkey": pubkey[:16], "t": int(dp["t"]), "steps": int(dp["steps"]),
                "claimed": {k: str(dp[k]) for k in ("a", "b", "x", "y")}, "replayed": replayed}

    @db_locked
    def _slash(self, pubkey: str, why: str, detail=None):
        if self.db.execute("SELECT status FROM miners WHERE pubkey=?", (pubkey,)).fetchone() == ("slashed",):
            return
        # Retain slashed identities' DPs to advance honest search, but mark them
        # untrusted. C-2 replays both collision sides; failed replay rows are deleted.
        # Only pending credit can be forfeited. epoch_payments is immutable.
        self.db.execute("UPDATE dps SET slashed=1 WHERE pubkey=?", (pubkey,))
        self.db.execute("UPDATE miners SET status='slashed', spot_fails=spot_fails+1, credited_steps=COALESCE((SELECT SUM(steps) FROM epoch_payments WHERE pubkey=miners.pubkey),0), note=? WHERE pubkey=?", (why, pubkey))
        self.db.commit()
        self.event("slashed", {"pubkey": pubkey[:16], "why": why, **(detail or {})})

    def _finish(self, k: int, finder: str, partner: str, x: int) -> dict:
        with self.lock:
            if self.status == "solved":
                return self._get_state("solution")
            self._set_state("status", "settling")
            self._set_state("pending_solution", [k, finder, partner, x])
        # Never wait for the epoch lock while holding the DB lock: replay needs it.
        self.close_epoch(final=True)
        with self.lock:
            return self._finalize_solution(k, finder, partner, x)

    def _finalize_solution(self, k, finder, partner, x):
        end = self._get_state("settlement_epoch")
        if end is None or self.db.execute("SELECT 1 FROM epochs WHERE idx<=? AND audit_complete=0", (end,)).fetchone():
            return None
        spec = self.spec
        self._settlement_sweep()
        total = self.db.execute("SELECT COALESCE(SUM(steps),0) FROM epoch_payments").fetchone()[0]
        rows = self.db.execute("SELECT pubkey,payout_addr,SUM(steps) FROM epoch_payments GROUP BY pubkey,payout_addr HAVING SUM(steps)>0").fetchall()
        payouts = [
            {"pubkey": pk, "payout_addr": addr, "credited_steps": st, "credits": st / (1 << spec.credit_unit_log2),
             "share": st / total if total else 0, "usdc": spec.prize_pool_usdc * st / total if total else 0}
            for pk, addr, st in rows
        ]
        payouts.sort(key=lambda r: -r["credited_steps"])
        work = self._work_totals(total)
        sol = {
            "k": k, "k_hex": hex(k), "found_at": now(), "collision_x": x,
            "finder": finder, "partner": partner, "total_credited_steps": total,
            "expected_steps": spec.expected_steps, "ratio": total / spec.expected_steps,
            "ratio_credited": total / spec.expected_steps,
            "ratio_executed": work["total_executed_steps"] / spec.expected_steps,
            **work,
            "verified": spec.curve.mul(k, spec.curve.G) == spec.Q,
            "payouts": payouts,
        }
        self._set_state("solution", sol)
        self._set_state("status", "solved")
        self.event("solved", {"k_hex": hex(k), "finder": finder[:16], "partner": partner[:16], "ratio": round(sol["ratio"], 3)})
        return sol

    def _settlement_sweep(self):
        """Bounded integrity sweep of durable finalized payment commitments.

        Sampled segment coverage is a prerequisite. Replaying unpaid points here
        would quietly turn sampled verification back into exhaustive verification.
        This final sweep checks the persisted ledger against its public roots;
        its wall-clock budget does not depend on N or on the unselected DP count.
        It never reopens immutable contributor payments.
        """
        if self._get_state("settlement_sweep_complete"):
            return
        started = time.monotonic()
        checked = 0
        cursor = self.db.execute("SELECT idx,root,leaves,total_steps FROM epochs WHERE audit_complete=1 ORDER BY idx DESC")
        for idx, root, raw, total in cursor:
            if time.monotonic()-started >= self.spec.settlement_sweep_seconds:
                break
            leaves = json.loads(raw)
            actual, _ = merkle.build([merkle.leaf_hash(addr, steps) for addr, steps in leaves])
            if actual.hex() != root or sum(steps for _, steps in leaves) != total:
                self._set_state("status", "halted_for_review")
                raise RuntimeError(f"epoch {idx} durable payment commitment mismatch")
            checked += 1
        self._set_state("settlement_sweep_complete", True)
        self._set_state("settlement_sweep", {"seconds": time.monotonic()-started,
            "budget_seconds": self.spec.settlement_sweep_seconds, "epochs_checked": checked})

    # ---------------------------------------------------------------- epochs
    def audit_epoch(self, idx, root_bytes, final=False):
        with self.lock:
            rows = self.db.execute(
                "SELECT pubkey, t, x, y, a, b, steps FROM dps WHERE epoch=? AND checked=0 AND slashed=0 ORDER BY pubkey,t",
                (idx,),
            ).fetchall()
        self._audit_rows(idx, root_bytes, rows, "spot", self.spec.spot_check_rate,
                         "epoch_audit")

    def audit_delayed(self, idx, root_bytes, final=False):
        # Mature credit is final. Do not turn later epochs into exhaustive
        # replays of previously paid populations.
        return

    def _audit_rows(self, idx, root_bytes, rows, tag, rate, event_kind):
        beacon = self.beacon_for(idx)
        pressure = set()
        targets = self._select_targets(root_bytes, beacon, rows, tag, rate)
        with self.lock:
            inputs = json.loads(self.db.execute(
                "SELECT audit_inputs FROM epochs WHERE idx=?", (idx,)).fetchone()[0] or "{}")
            if inputs.get(tag, {}).get("complete"):
                return
            if tag not in inputs:
                indices = dict(self.db.execute("SELECT pubkey,miner_idx FROM miners"))
                self.db.executemany(
                    "INSERT INTO audit_candidates VALUES(?,?,?,?,?)",
                    [(idx, tag, i, indices[r[0]], r[1]) for i, r in enumerate(rows)])
                inputs[tag] = {"rate": rate, "cap": len(targets), "total": len(targets),
                               "selection": "per-identity-fraction-v1",
                               "pressure_identities": sorted(pressure), "pressure_rate": min(rate, 2),
                               "candidate_total": len(rows), "failed": 0,
                               "pairs": [[indices[r[0]], r[1]] for r in targets],
                               "fraud_bounds": [{"miner_idx": indices[pk], "k": count,
                                   "audited": (count+rate-1)//rate,
                                   "forged": max(1, math.ceil(count*.1)),
                                   "phi": max(1, math.ceil(count*.1))/count,
                                   "fraud_bound": ec.audit_fraud_bound(count, max(1, math.ceil(count*.1)),
                                       (count+rate-1)//rate, ec.MAX_REPLAY_STEPS(self.spec)//(1<<self.spec.v))}
                                   for pk, count in Counter(row[0] for row in rows).items()]}
                self._store_audit_inputs(idx, inputs)
            # Resume the persisted plan, even if checked flags changed on retry.
            targets = self.db.execute(
                "SELECT m.pubkey,d.t,d.x,d.y,d.a,d.b,d.steps FROM "
                "json_each(?) p JOIN miners m ON m.miner_idx=json_extract(p.value,'$[0]') "
                "JOIN dps d ON d.pubkey=m.pubkey AND d.t=json_extract(p.value,'$[1]') "
                "ORDER BY CAST(p.key AS INTEGER)",
                (json.dumps(inputs[tag]["pairs"], separators=(",", ":")),)).fetchall()
        with self.lock:
            # One flat window for every identity was wrong, and it slashed two
            # honest walkers in rehearsal. An identity that submitted more owes
            # more openings, and each opening is a round trip and a replay, so a
            # fixed window silently demands an unbounded answer rate. Give each
            # identity the base window plus time proportional to what we asked of
            # it. Persisted with the plan, so a restart does not shorten it.
            deadline_key = f"audit_deadlines:{idx}"
            deadlines = self._get_state(deadline_key)
            if not isinstance(deadlines, dict):
                base = now() + self.spec.audit_response_seconds
                owed = Counter(row[0] for row in targets)
                deadlines = {pk: base + count / AUDIT_ANSWER_RATE for pk, count in owed.items()}
                self._set_state(deadline_key, deadlines)
                if owed:
                    self.event("audit_window", {"epoch": idx, "challenges": sum(owed.values()),
                                                "identities": len(owed),
                                                "longest_seconds": round(max(deadlines.values()) - now())})
            for pk, t, x, y, a, b, steps in targets:
                segments = (steps + (1 << self.spec.v) - 1) >> self.spec.v
                segment = int.from_bytes(ec.H(root_bytes, beacon, "segment-v1", pk, t), "big") % segments
                self.db.execute("INSERT OR IGNORE INTO challenges VALUES(?,?,?,?,?,NULL)",
                                (idx, pk, t, segment, deadlines.get(pk, now() + self.spec.audit_response_seconds)))
            # Publishing entropy is safe now: all memberships and commitments
            # have been sealed and the plan is durable before any response.
            self.db.execute("UPDATE epochs SET beacon_reveal=? WHERE idx=?", (beacon.hex(), idx))
            self.db.commit()

    @db_locked
    def audit_targets(self, pubkey):
        return [{"epoch": ep, "t": t, "segment": seg, "deadline": deadline}
                for ep, t, seg, deadline in self.db.execute(
                    "SELECT epoch,t,segment,deadline FROM challenges WHERE pubkey=? AND result IS NULL "
                    "AND deadline>=? ORDER BY epoch,t LIMIT 512", (pubkey, now()))]

    def answer_audit(self, pubkey, epoch, t, opening):
        with self.lock:
            row = self.db.execute("SELECT segment,deadline,result FROM challenges WHERE epoch=? AND pubkey=? AND t=?",
                                  (epoch, pubkey, t)).fetchone()
            if row is None:
                raise HTTPException(404, "unknown challenge")
            segment, deadline, result = row
            if result is not None:
                return {"result": result}
            late = now() > deadline
            if late and result is None:
                # The window has closed, but an opening that verifies still proves the
                # work. Accept it and release what silence withheld, rather than
                # keeping a contributor unpaid for work it can demonstrate it did.
                pass
            record = self.db.execute("SELECT d.x,d.y,d.a,d.b,d.steps,c.root FROM dps d "
                                     "LEFT JOIN checkpoints c USING(pubkey,t) WHERE d.pubkey=? AND d.t=?",
                                     (pubkey, t)).fetchone()
            if record is None:
                raise HTTPException(409, "point removed by collision verification")
            x, y, a, b, steps, root = record
            dp = dict(t=t, x=int(x), y=int(y), a=int(a), b=int(b), steps=steps, checkpoint_root=root)
        started = time.monotonic()
        ok, work = self._segment_verify(pubkey, dp, segment, opening)
        with self.lock:
            self._count_replay(work, time.monotonic()-started)
            # Idempotent application, even if HTTP retries race.
            changed = self.db.execute(
                "UPDATE challenges SET result=? WHERE epoch=? AND pubkey=? AND t=? "
                "AND (result IS NULL OR result='silent')",
                ("passed" if ok else "failed", epoch, pubkey, t)).rowcount
            if changed:
                self.db.execute("INSERT OR IGNORE INTO audit_openings VALUES(?,?,?,?)", (epoch, pubkey, t, json.dumps(opening)))
                self.db.execute("UPDATE miners SET spot_checks=spot_checks+1 WHERE pubkey=?", (pubkey,))
                if ok:
                    self.db.execute("UPDATE dps SET checked=1 WHERE pubkey=? AND t=?", (pubkey, t))
                    # If every challenge for that epoch is now answered, release the
                    # credit that silence was holding back.
                    outstanding = self.db.execute(
                        "SELECT 1 FROM challenges WHERE epoch=? AND pubkey=? AND "
                        "(result IS NULL OR result='silent')", (epoch, pubkey)).fetchone()
                    if not outstanding:
                        released = self.db.execute(
                            "DELETE FROM withheld WHERE epoch=? AND pubkey=?", (epoch, pubkey)).rowcount
                        if released:
                            self.event("credit_released", {"epoch": epoch, "pubkey": pubkey[:16]})
                else:
                    self._slash(pubkey, f"epoch {epoch} segment audit failed t={t}")
                    self.event("audit_failed", {"epoch": epoch, "pubkey": pubkey[:16], "first_failing_t": t})
            self.db.commit()
        return {"result": "passed" if ok else "failed"}

    def _segment_verify(self, pubkey, dp, segment, opening):
        # Independent CPU work goes to processes, outside the database lock.
        # Bound queued jobs as well as active processes under hostile intake.
        with AUDIT_GATE.enter():
            ok, work, elapsed, pid = audit_pool().submit(run_audit_job, self.spec, self.table,
                                       pubkey, dp, segment, opening).result(timeout=30)
        with self.lock:
            self._set_state("audit_worker_steps", (self._get_state("audit_worker_steps") or 0)+work)
            self._set_state("audit_worker_seconds", (self._get_state("audit_worker_seconds") or 0)+elapsed)
            self._set_state("audit_worker_pids", sorted(set(self._get_state("audit_worker_pids") or []) | {pid}))
        return ok, work

    @db_locked
    def _count_replay(self, steps, seconds=0):
        self._set_state("verification_replay_steps", (self._get_state("verification_replay_steps") or 0) + steps)
        self._set_state("verification_seconds", (self._get_state("verification_seconds") or 0) + seconds)

    def _full_verify(self, pk, dp):
        started = time.monotonic()
        ok = ec.dp_verify(self.spec, self.table, pk, dp)
        self._count_replay(int(dp["steps"]), time.monotonic()-started)
        return ok

    @db_locked
    def _resolve_challenges(self, idx):
        outstanding = self.db.execute("SELECT pubkey,t,deadline FROM challenges WHERE epoch=? AND result IS NULL", (idx,)).fetchall()
        for pk, t, deadline in outstanding:
            # A proved forgery already forfeits the pending epoch; do not hold
            # everyone else's maturity window open waiting for its other answers.
            slashed = self.db.execute("SELECT status FROM miners WHERE pubkey=?", (pk,)).fetchone()[0] == "slashed"
            if slashed or now() >= deadline:
                self.db.execute("UPDATE challenges SET result=? WHERE epoch=? AND pubkey=? AND t=?",
                                ("forfeited" if slashed else "silent", idx, pk, t))
        if self.db.execute("SELECT 1 FROM challenges WHERE epoch=? AND result IS NULL", (idx,)).fetchone():
            self.db.commit()
            return False
        silent = [pk for pk, in self.db.execute("SELECT DISTINCT pubkey FROM challenges WHERE epoch=? AND result='silent'", (idx,))]
        for pk in silent:
            applied = self.db.execute("INSERT OR IGNORE INTO state(k,v) VALUES(?, 'true')",
                                      (f"silence_applied:{idx}:{pk}",)).rowcount
            if not applied:
                continue
            # Silence is not fraud. An identity that never opens its challenge has
            # work nobody can verify, so that epoch cannot be paid, but the credit is
            # withheld rather than destroyed: a late opening matures it, and only
            # repeated silence, below, costs the identity its standing. Destroying
            # credit is reserved for an answer that is wrong.
            count_steps = self.db.execute(
                "SELECT COUNT(*) FROM dps WHERE epoch=? AND pubkey=? AND slashed=0",
                (idx, pk)).fetchone()[0] << self.spec.w
            self.db.execute(
                "INSERT OR REPLACE INTO withheld(epoch, pubkey, steps) VALUES(?,?,?)",
                (idx, pk, count_steps))
            count = self.db.execute("SELECT COUNT(DISTINCT epoch) FROM challenges WHERE pubkey=? AND result='silent'", (pk,)).fetchone()[0]
            if count >= self.spec.silence_epochs:
                self._slash(pk, f"silent in {count} audit epochs")
        inputs = json.loads(self.db.execute("SELECT audit_inputs FROM epochs WHERE idx=?", (idx,)).fetchone()[0] or "{}")
        for value in inputs.values():
            value.update(complete=True, failed=self.db.execute(
                "SELECT COUNT(*) FROM challenges WHERE epoch=? AND result='failed'", (idx,)).fetchone()[0])
        self._store_audit_inputs(idx, inputs)
        self.db.commit()
        return True

    @staticmethod
    def _select_targets(root, beacon, rows, tag, rate):
        groups = {}
        for row in rows:
            groups.setdefault(row[0], []).append(row)
        targets = []
        for pk, group in sorted(groups.items()):
            count = (len(group) + rate - 1) // rate
            ranked = sorted(group, key=lambda row: (ec.H(root, beacon, tag, pk, row[1]), row[1]))
            if tag == "spot2":
                # Reserve one slot for the oldest identifier. Other slots retain
                # beacon ranking; pressure drainage keeps the backlog bounded.
                oldest = min(group, key=lambda row: row[1])
                ranked = [oldest] + [row for row in ranked if row[1] != oldest[1]]
            targets.extend(ranked[:count])
        return targets

    @staticmethod
    def _legacy_targets(root, beacon, rows, tag, rate):
        ranked = [(int.from_bytes(ec.H(root, beacon, tag, row[0], row[1]), "big"), row) for row in rows]
        return [row for score, row in sorted(ranked) if score % rate == 0]

    def _store_audit_inputs(self, idx, inputs):
        counts = {tag: {"audited": len(v["pairs"]), "total": v["total"],
                        "failed": v.get("failed", 0)} for tag, v in inputs.items()}
        self.db.execute("UPDATE epochs SET audit_inputs=?,audit_counts=? WHERE idx=?",
                        (json.dumps(inputs, separators=(",", ":")),
                         json.dumps(counts, separators=(",", ":")), idx))
        self.db.commit()

    def _migrate_audit_inputs(self):
        """Move legacy candidate blobs to indexed rows and cap selected-pair JSON."""
        indices = dict(self.db.execute("SELECT pubkey,miner_idx FROM miners"))
        for idx, root, reveal, raw in self.db.execute(
                "SELECT idx,root,beacon_reveal,audit_inputs FROM epochs WHERE audit_inputs IS NOT NULL").fetchall():
            inputs = json.loads(raw)
            if all("total" in v for v in inputs.values()):
                continue
            if not reveal:
                for key in (f"beacon_value:{idx}", f"beacon_secret:{idx}"):
                    record = self.db.execute("SELECT v FROM state WHERE k=?", (key,)).fetchone()
                    if record:
                        reveal = json.loads(record[0])
                        break
            if not reveal:
                raise RuntimeError(f"cannot migrate epoch {idx} audit without its beacon")
            for tag, v in inputs.items():
                if "total" in v:
                    continue
                rows = v["pairs"]
                self.db.executemany("INSERT OR IGNORE INTO audit_candidates VALUES(?,?,?,?,?)",
                                    [(idx, tag, i, indices[pk], t) for i, (pk, t) in enumerate(rows)])
                targets = self._legacy_targets(bytes.fromhex(root), bytes.fromhex(reveal), rows, tag, v["rate"])
                # Legacy failure totals are recorded in audit events.
                kind = "epoch_audit" if tag == "spot" else "delayed_audit"
                event = self.db.execute(
                    "SELECT detail FROM events WHERE kind=? AND json_extract(detail,'$.epoch')=? ORDER BY id DESC LIMIT 1",
                    (kind, idx)).fetchone()
                v.update(total=len(targets), candidate_total=len(rows),
                         failed=json.loads(event[0])["failed"] if event else 0,
                         complete=event is not None,
                         pairs=[[indices[pk], t] for pk, t in targets[:v["cap"]]])
            self._store_audit_inputs(idx, inputs)

    def close_epoch(self, final=False):
        with self.epoch_lock:
            final = final or self.status == "settling"
            with self.lock:
                last = self.db.execute("SELECT MAX(idx) FROM epochs WHERE audit_complete=1").fetchone()[0]
            # Freeze the final epoch index durably: a failed beacon fetch/restart
            # must resume this seal even if wall time advances.
            end = self.current_epoch()
            if final:
                end = self._get_state("settlement_epoch")
                if end is None:
                    end = self.current_epoch()
                    self._set_state("settlement_epoch", end)
                end += 1
            # Catch up every sealed batch if the timer or coordinator was paused.
            for idx in range(0 if last is None else last + 1, end):
                self._open_epoch(idx)
                with self.lock:
                    snapshot = self._get_state(f"epoch_snapshot:{idx}")
                    if snapshot is None:
                        # Freeze membership/address and exclude work from later, still
                        # open epochs. This is a batch seal, NOT a payment commitment.
                        snapshot = self.db.execute(
                            "SELECT pubkey,payout_addr,(SELECT COUNT(*) FROM dps d WHERE d.pubkey=m.pubkey AND d.epoch=? AND d.slashed=0)*? "
                            "FROM miners m WHERE status='active' ORDER BY pubkey",
                            (idx, 1 << self.spec.w)).fetchall()
                        seal = ec.H("epoch-seal", self.spec.round_id, idx, ec.canonical(snapshot))
                        previous = self.db.execute(
                            "SELECT root FROM epochs WHERE idx<? AND audit_complete=1 ORDER BY idx DESC LIMIT 1",
                            (idx,)).fetchone()
                        # The payment root depends on the audit, so cannot seed it.
                        # Use the previous completed root (empty Merkle root at genesis)
                        # plus fresh post-seal entropy. The private opening commitment
                        # still hides that entropy from miners throughout this epoch.
                        seed_root = previous[0] if previous else merkle.build([])[0].hex()
                        self.db.execute("UPDATE epochs SET sealed_root=?,audit_seed_root=? WHERE idx=?",
                                        (seal.hex(), seed_root, idx))
                        self._set_state(f"epoch_snapshot:{idx}", snapshot)
                    seed_root = self.db.execute("SELECT audit_seed_root FROM epochs WHERE idx=?", (idx,)).fetchone()[0]
                beacon = self.beacon_for(idx)
                if final and idx == end - 1:
                    self.audit_epoch(idx, bytes.fromhex(seed_root), final=True)
                    self.audit_delayed(idx, bytes.fromhex(seed_root), final=True)
                else:
                    self.audit_epoch(idx, bytes.fromhex(seed_root))
                    self.audit_delayed(idx, bytes.fromhex(seed_root))
                if not self._resolve_challenges(idx):
                    return
                with self.lock:
                    balances = dict(self.db.execute("SELECT pubkey,credited_steps FROM miners WHERE status='active'"))
                    by_address = {}
                    for pk, addr, st in snapshot:
                        failed = self.db.execute("SELECT 1 FROM challenges WHERE epoch=? AND pubkey=? AND result='failed'", (idx, pk)).fetchone()
                        held = self.db.execute("SELECT COALESCE(SUM(steps),0) FROM withheld WHERE pubkey=?",
                                               (pk,)).fetchone()[0]
                        # A wrong answer forfeits the epoch. Silence only withholds:
                        # the steps stay on the identity's balance and are subtracted
                        # here, so they are unpayable until the opening arrives.
                        survived = 0 if failed else max(0, min(st, balances.get(pk, 0)) - held)
                        self.db.execute("INSERT OR IGNORE INTO epoch_payments VALUES(?,?,?,?)", (idx, pk, addr, survived))
                        if survived > 0:
                            by_address[addr] = by_address.get(addr, 0) + survived
                    rows = sorted(by_address.items())
                    root, _ = merkle.build([merkle.leaf_hash(addr, st) for addr, st in rows])
                    total = sum(st for _, st in rows)
                    self.db.execute(
                        "UPDATE epochs SET ts=?,root=?,total_steps=?,n_miners=?,leaves=?,beacon_reveal=?,audit_complete=1 WHERE idx=?",
                        (now(), root.hex(), total, len(rows), json.dumps(rows), beacon.hex(), idx))
                    self.db.commit()
                self.event("epoch_closed", {"epoch": idx, "root": root.hex()[:16], "total_steps": total, "miners": len(rows)})

    @db_locked
    def epochs_for(self, payout_addr: str):
        """Closed epochs containing this address, in ascending order."""
        address = payout_addr.lower()
        return [idx for idx, leaves in self.db.execute("SELECT idx, leaves FROM epochs WHERE audit_complete=1 ORDER BY idx")
                if any(a == address for a, _ in json.loads(leaves))]

    @db_locked
    def proof(self, payout_addr: str, epoch: int | None = None):
        if epoch is None:
            row = self.db.execute("SELECT idx, root, leaves FROM epochs WHERE audit_complete=1 ORDER BY idx DESC LIMIT 1").fetchone()
        else:
            row = self.db.execute("SELECT idx, root, leaves FROM epochs WHERE idx=? AND audit_complete=1", (epoch,)).fetchone()
        if not row:
            raise HTTPException(404, "no epoch closed yet" if epoch is None else f"epoch {epoch} is not closed")
        idx, root, leaves = row
        leaves = json.loads(leaves)
        addrs = [a for a, _ in leaves]
        if payout_addr.lower() not in addrs:
            available = self.epochs_for(payout_addr)
            hint = (f"most recent epoch containing this address is {available[-1]}" if available
                    else "address does not appear in any closed epoch")
            raise HTTPException(404, f"address has no leaf in epoch {idx}; {hint}")
        i = addrs.index(payout_addr.lower())
        lh = [merkle.leaf_hash(a, s) for a, s in leaves]
        _, layers = merkle.build(lh)
        pf = merkle.proof(layers, i)
        return {"epoch": idx, "root": "0x" + root, "payout_addr": payout_addr.lower(), "credited_steps": leaves[i][1],
                "proof": ["0x" + p.hex() for p in pf], "verifies": merkle.verify(bytes.fromhex(root), lh[i], pf)}

    def eta_posterior(self, total_steps, rate):
        """Rayleigh remaining-work posterior, conditional on no collision yet.

        The 5th/95th percentiles form a central 90% interval. Inputs used by
        status are reported search steps and their recent rate; ticket work
        mints identities and is not part of the collision search.
        """
        s0 = max(0.0, float(total_steps))
        rate = max(0.0, float(rate))
        n_eff = (1.25 ** 2 * 2 / math.pi) * self.spec.curve.n
        scale = math.sqrt(2 * n_eff)
        z = s0 / scale

        def quantile(p):
            c = 2 * n_eff * -math.log1p(-p)
            # Rationalized sqrt(s0**2 + c) - s0 avoids cancellation.
            return c / (math.hypot(s0, math.sqrt(c)) + s0)

        out = {}
        for name, p in (("median", 0.5), ("p05", 0.05), ("p95", 0.95)):
            steps = quantile(p)
            out[name + "_remaining_steps"] = steps
            out[name + "_remaining_seconds"] = steps / rate if rate else None
        # Integral of conditional survival is already the mean residual life;
        # subtracting s0 again would produce negative remaining work.
        out["expected_remaining_steps"] = (
            math.sqrt(math.pi * n_eff / 2) * math.exp(z * z) * math.erfc(z)
            if z < 26 else n_eff / s0)
        u = rate * 3600
        out["p_complete_next_hour"] = -math.expm1(-(u / scale) * (2 * z + u / scale)) if rate else None
        return out

    def _work_totals(self, credited):
        # Include slashed identities: forfeiting payment does not undo work.
        search, tickets, abandoned = self.db.execute(
            "SELECT COALESCE(SUM(executed_steps),0), COALESCE(SUM(ticket_steps),0), "
            "COALESCE(SUM(abandoned_walks),0) FROM miners"
        ).fetchone()
        executed = search + tickets
        return {"total_executed_steps": executed, "total_ticket_steps": tickets,
                "total_abandoned_walks": abandoned,
                "executed_to_credited": executed / credited if credited else None}

    def _audit_backlogs(self):
        return {pk: count * (1 << self.spec.w) for pk, count in self.db.execute(
            "SELECT d.pubkey,COUNT(*) FROM dps d JOIN miners m ON m.pubkey=d.pubkey "
            "WHERE d.checked=0 AND d.slashed=0 AND m.status='active' AND d.epoch NOT IN (SELECT idx FROM epochs WHERE audit_complete=1) GROUP BY d.pubkey")}

    # ---------------------------------------------------------------- reads
    @db_locked
    def status_view(self):
        """Several aggregates, an epoch list and an ETA posterior. Every walker
        polls it, so it is served from a one-second cache: the numbers are already
        sampled over a sixty-second window and nothing here is a decision input."""
        # Keyed on the write counter as well as the clock, so the cache only ever
        # absorbs repeated reads. A contributor that just submitted and immediately
        # asks for its balance sees the submission, not a second-old view of it.
        # The epoch loop's failure count lives in memory, not in the database, so
        # it goes in the key too: "degraded" is the one field a stale read would
        # hide at exactly the moment somebody is looking for it.
        key = (self.db.total_changes, self.epoch_loop_failures, self.status)
        cached = self._status_cache
        if cached is not None and cached[2] == key and now() - cached[0] < STATUS_CACHE_SECONDS:
            return cached[1]
        view = self._status_view()
        self._status_cache = (now(), view, key)
        return view

    def _status_view(self):
        spec = self.spec
        current_epoch = self.current_epoch()
        total, n_dps, n_miners, n_active = self.db.execute(
            "SELECT COALESCE(SUM(credited_steps),0), COALESCE(SUM(dps),0), COUNT(*), SUM(status='active') FROM miners"
        ).fetchone()
        work = self._work_totals(total)
        cutoff = now() - 60
        recent = [(ts, s) for ts, s in self.rate_window if ts > cutoff]
        rate = sum(s for _, s in recent) / 60 if recent else 0
        eta = self.eta_posterior(work["total_executed_steps"] - work["total_ticket_steps"], rate)
        slashed = self.db.execute("SELECT COUNT(*) FROM miners WHERE status='slashed'").fetchone()[0]
        checks = self.db.execute("SELECT COALESCE(SUM(spot_checks),0) FROM miners").fetchone()[0]
        last_epoch = self.db.execute("SELECT idx, root, ts, total_steps, n_miners FROM epochs WHERE audit_complete=1 ORDER BY idx DESC LIMIT 1").fetchone()
        return {
            "settlement_sweep": self._get_state("settlement_sweep"),
            "beacon_mode": "external" if self.beacon_url else "fallback",
            "fraud_bound_assumption": "unpredictable post-commitment entropy; one bad segment per forged walk",
            "operator_collusion_fraud_bound": 1.0,
            "verifier_processes": AUDIT_WORKERS,
            "verifier_worker_pids": self._get_state("audit_worker_pids") or [],
            "verifier_steps_per_second": ((self._get_state("audit_worker_steps") or 0) * AUDIT_WORKERS / (self._get_state("audit_worker_seconds") or 1)),
            "verifier_to_network_throughput_ratio": (((self._get_state("audit_worker_steps") or 0) * AUDIT_WORKERS / (self._get_state("audit_worker_seconds") or 1)) / rate if rate else None),
            "verification_replay_steps": self._get_state("verification_replay_steps") or 0,
            "detection": spec.detection,
            "audit_backlog_steps": sum(self._audit_backlogs().values()),
            "audit_backlog_by_identity": self._audit_backlogs(),
            "audit_backlog_limit_steps": MAX_AUDIT_BACKLOG_DPS * (1 << spec.w),
            "epochs": self.epochs_view(),
            "round": spec.to_dict(),
            "status": self.status,
            "epoch_loop_failures": self.epoch_loop_failures,
            "degraded": self.epoch_loop_failures >= 3,
            "dps_from_slashed": self.db.execute("SELECT COUNT(*) FROM dps WHERE slashed=1").fetchone()[0],
            "halted": self.status == "halted_for_review",
            "degenerate_collisions": self._get_state("degenerate_collisions") or 0,
            "started_at": self.started_at,
            "now": now(),
            "epoch": current_epoch,
            "total_payable_steps": self.db.execute("SELECT COALESCE(SUM(steps),0) FROM epoch_payments").fetchone()[0],
            "total_credited_steps": total,
            **work,
            "total_credits": total / (1 << spec.credit_unit_log2),
            "progress": total / spec.expected_steps,  # Legacy payment-accounting ratio.
            "progress_executed": work["total_executed_steps"] / spec.expected_steps,
            "dps": n_dps,
            "contributors": n_miners,
            "active_contributors": n_active or 0,
            "slashed": slashed,
            "spot_checks": checks,
            "steps_per_sec": rate,
            "eta": eta,
            "eta_seconds": eta["median_remaining_seconds"],
            "last_epoch": None if not last_epoch else {"idx": last_epoch[0], "root": "0x" + last_epoch[1], "ts": last_epoch[2], "total_steps": last_epoch[3], "contributors": last_epoch[4]},
            "solution": self._get_state("solution"),
        }

    @db_locked
    def miners_view(self):
        rows = self.db.execute(
            "SELECT pubkey, payout_addr, status, dps, credited_steps, spot_checks, spot_fails, rejected, admitted_at, last_seen, note, executed_steps, abandoned_walks, ticket_steps FROM miners ORDER BY credited_steps DESC"
        ).fetchall()
        total = sum(r[4] for r in rows if r[2] == "active") or 1
        return [
            {"pubkey": r[0], "payout_addr": r[1], "status": r[2], "dps": r[3], "credited_steps": r[4],
             "credits": r[4] / (1 << self.spec.credit_unit_log2), "share": (r[4] / total) if r[2] == "active" else 0,
             "spot_checks": r[5], "spot_fails": r[6], "rejected": r[7], "admitted_at": r[8], "last_seen": r[9], "note": r[10],
             "executed_steps": r[11], "abandoned_walks": r[12], "ticket_steps": r[13],
             "total_executed_steps": r[11] + r[13],
             "executed_to_credited": (r[11] + r[13]) / r[4] if r[4] else None,
             # A key becomes a name only if its holder registered it publicly; an
             # unregistered key is shown as a key, never as somebody's account.
             "github": (self.registry.get(r[0]) or {}).get("github"),
             # Self-reported at admission, falling back to whatever the registry
             # claims. Never a measured fact, so it is labelled as reported.
             "device": self.devices.get(r[0]) or (self.registry.get(r[0]) or {}).get("device")}
            for r in rows
        ]

    def reload_registry(self):
        """Re-read the public contributor registry (pubkey -> GitHub account)."""
        try:
            from tools.contributor import load_registry
            self.registry = load_registry(self.registry_dir)
        except Exception as e:  # a broken registry must never stop a round
            self.event("registry_error", {"err": str(e)})
            self.registry = getattr(self, "registry", {})
        return len(self.registry)

    @db_locked
    def epochs_view(self, limit=50, before=None):
        """Newest first; default 50, maximum 100. before is an exclusive index."""
        limit = max(1, min(limit, 100))
        where, params = ("", []) if before is None else ("WHERE idx<?", [before])
        rows = self.db.execute(
            "SELECT idx,ts,root,total_steps,n_miners,beacon_commitment,beacon_reveal,"
            f"beacon_source,audit_complete,audit_counts,sealed_root,audit_seed_root FROM epochs {where} ORDER BY idx DESC LIMIT ?",
            (*params, limit)).fetchall()
        # An epoch row exists from the moment the epoch opens, so that its beacon
        # commitment is published before any submission can land in it. Until the
        # batch is sealed it holds no root and is not a ledger checkpoint, so it is
        # reported as open rather than as an epoch with an empty root.
        return [{"idx": r[0], "ts": r[1], "root": ("0x" + r[2]) if r[2] else None,
                 "sealed": bool(r[10] or r[2]), "sealed_root": ("0x" + r[10]) if r[10] else None,
                 "audit_seed_root": "0x" + (r[11] or r[2]) if (r[11] or r[2]) else None, "total_steps": r[3], "miners": r[4],
                 "beacon_commitment": r[5], "beacon_reveal": r[6], "beacon_source": r[7],
                 "credit_unit": "epoch-final steps",
                 "detection": self.spec.detection,
                 "audit_complete": bool(r[8]), "audit_counts": json.loads(r[9])} for r in rows]

    @db_locked
    def epoch_audit(self, idx, limit=50, offset=0, kind="audited"):
        row = self.db.execute(
            "SELECT root,beacon_reveal,audit_complete,audit_inputs,audit_seed_root FROM epochs WHERE idx=?", (idx,)).fetchone()
        if row is None:
            raise HTTPException(404, "unknown epoch")
        if not row[2]:
            raise HTTPException(409, "epoch audit is not complete")
        inputs = json.loads(row[3] or "{}")
        result = {}
        for tag, v in inputs.items():
            if kind == "candidates":
                pairs = self.db.execute(
                    "SELECT m.pubkey,c.t FROM audit_candidates c JOIN miners m USING(miner_idx) "
                    "WHERE c.epoch_idx=? AND c.tag=? ORDER BY c.ordinal LIMIT ? OFFSET ?",
                    (idx, tag, limit, offset)).fetchall()
                total = stored = v["candidate_total"]
            else:
                pairs = self.db.execute(
                    "SELECT m.pubkey,json_extract(p.value,'$[1]') FROM json_each(?) p "
                    "JOIN miners m ON m.miner_idx=json_extract(p.value,'$[0]') "
                    "ORDER BY CAST(p.key AS INTEGER) LIMIT ? OFFSET ?",
                    (json.dumps(v["pairs"], separators=(",", ":")), limit, offset)).fetchall()
                total, stored = v["total"], len(v["pairs"])
            result[tag] = {"tag": tag, "rate": v["rate"], "cap": v["cap"],
                           "fraud_bounds": v.get("fraud_bounds", [])[offset:offset+limit],
                           "fraud_bounds_total": len(v.get("fraud_bounds", [])),
                           "selection": v.get("selection", "legacy-modulo"),
                           "pressure_rate": v.get("pressure_rate", v["rate"]),
                           "pressure_identities": sorted({pk for pk, _ in pairs} &
                                                         set(v.get("pressure_identities", []))),
                           "pairs": pairs, "total": total, "stored_count": stored,
                           "truncated": stored < total, "failed": v.get("failed", 0),
                           "next_offset": offset + len(pairs) if offset + len(pairs) < stored else None}
        return {"idx": idx, "root": "0x" + row[0], "audit_seed_root": "0x" + (row[4] or row[0]), "beacon_reveal": row[1],
                "kind": kind, "limit": limit, "offset": offset, "audit_inputs": result}

    @db_locked
    def events_view(self, limit=60):
        rows = self.db.execute("SELECT ts, kind, detail FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r[0], "kind": r[1], "detail": json.loads(r[2])} for r in rows]


# -------------------------------------------------------------------- HTTP


def build_app(coord: Coordinator) -> FastAPI:
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app):
        stop = threading.Event()
        worker = threading.Thread(target=_epoch_loop, args=(coord, stop), daemon=True)
        worker.start()
        try:
            yield
        finally:
            stop.set()
            worker.join()

    app = FastAPI(title="RhoNet coordinator", version="0.1", lifespan=lifespan)

    # The public board is served from rhonet.dev and reads this API cross-origin.
    # Only reads are granted, and only to the site's own origins: there are no
    # cookies or ambient credentials here, so this widens nothing that a client
    # outside a browser could not already do, and a browser cannot be induced to
    # submit on someone's behalf. RHONET_ALLOWED_ORIGINS overrides for a mirror.
    origins = [o.strip() for o in os.environ.get(
        "RHONET_ALLOWED_ORIGINS",
        "https://rhonet.dev,https://www.rhonet.dev").split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins,
                       allow_methods=["GET"], allow_headers=[], max_age=600)

    @app.get("/healthz")
    def healthz():
        """Cheap liveness for the tunnel and the monitor: no replay, no scan."""
        with coord.lock:
            epoch = coord.current_epoch()
            behind = coord.db.execute(
                "SELECT COUNT(*) FROM epochs WHERE audit_complete=0 AND idx<?", (epoch,)).fetchone()[0]
        ok = coord.epoch_loop_failures < 3
        return JSONResponse({"ok": ok, "status": coord.status, "epoch": epoch,
                             "epochs_awaiting_close": behind,
                             "epoch_loop_failures": coord.epoch_loop_failures,
                             "round_id": coord.spec.round_id},
                            status_code=200 if ok else 503)

    @app.get("/")
    def index():
        return FileResponse(os.path.join(STATIC, "index.html"))

    @app.get("/api/round")
    def round_spec():
        return coord.spec.to_dict()

    @app.get("/api/status")
    def status():
        return coord.status_view()

    @app.get("/api/contributors")
    def miners():
        return coord.miners_view()

    @app.get("/api/epochs")
    def epochs(limit: int = Query(50, ge=1, le=100), before: int | None = None):
        """Listing only, newest first. Default limit 50 (maximum 100).

        Pass the last idx as exclusive `before` to retrieve the next page.
        Audit counts: audited = capped replay plan, total = matching targets
        before the cap, failed = failed replays.
        """
        return coord.epochs_view(limit, before)

    @app.get("/api/epochs/{idx}/audit")
    def epoch_audit(idx: int, limit: int = Query(50, ge=1, le=512),
                    offset: int = Query(0, ge=0),
                    kind: str = Query("audited", pattern="^(audited|candidates)$")):
        """Public audit inputs; default 50 pairs per tag, maximum 512.

        `audited` returns the capped replay plan in selector order. total counts
        all matching targets before the cap; stored_count counts retained pairs.
        next_offset pages the retained pairs; truncated explicitly reports capping.
        `candidates` pages the full original population, including removed DPs.
        To reproduce: group by identity, rank H(seed_root, beacon, tag, pubkey, t),
        then take ceil(identity_count/rate) from each group. Both kinds apply
        limit/offset independently to each tag. Pending plans are published via
        /api/audit/targets; this endpoint reports completed audit outcomes.
        """
        return coord.epoch_audit(idx, limit, offset, kind)

    @app.get("/api/events")
    def events():
        return coord.events_view()

    @app.get("/api/proof")
    def proof(payout_addr: str, epoch: int | None = None):
        return coord.proof(payout_addr, epoch)

    @app.get("/api/proof/epochs")
    def proof_epochs(payout_addr: str):
        return coord.epochs_for(payout_addr)

    ticket_ip = RateLimiter(TICKET_IP_RATE, TICKET_IP_BURST)
    ticket_key = RateLimiter(TICKET_KEY_RATE, TICKET_KEY_BURST)
    submit_ip = RateLimiter(SUBMIT_IP_RATE, SUBMIT_IP_BURST)
    submit_key = RateLimiter(SUBMIT_KEY_RATE, SUBMIT_KEY_BURST)
    audit_ip = RateLimiter(AUDIT_IP_RATE, AUDIT_IP_BURST)
    audit_key = RateLimiter(AUDIT_KEY_RATE, AUDIT_KEY_BURST)

    def limit(req, body, ip_limiter, key_limiter):
        if not ip_limiter.allow(req.client.host if req.client else "unknown"):
            raise HTTPException(429, "rate limited", headers={"Retry-After": "1"})
        if not isinstance(body.get("pubkey"), str):
            raise HTTPException(400, "missing pubkey")
        if not key_limiter.allow(body["pubkey"].lower()):
            raise HTTPException(429, "rate limited", headers={"Retry-After": "1"})

    @app.post("/api/ticket")
    def ticket(req: Request, body: dict):
        limit(req, body, ticket_ip, ticket_key)
        sig = body.pop("sig", None)
        for k in ("pubkey", "payout_addr", "ticket"):
            if k not in body:
                raise HTTPException(400, f"missing {k}")
        if body.get("round_id") != coord.spec.round_id:
            raise HTTPException(400, "wrong round_id")
        Coordinator.verify_sig(body["pubkey"], body, sig or "")
        with TICKET_GATE.enter():
            return coord.admit(body["pubkey"], body["payout_addr"], body["ticket"],
                               freshness=(body.get("epoch"), body.get("seq")),
                               device=body.get("device"))

    @app.post("/api/submit")
    def submit(req: Request, body: dict):
        limit(req, body, submit_ip, submit_key)
        sig = body.pop("sig", None)
        if body.get("round_id") != coord.spec.round_id:
            raise HTTPException(400, "wrong round_id")
        if "pubkey" not in body or not isinstance(body.get("dps"), list):
            raise HTTPException(400, "missing pubkey/dps")
        Coordinator.verify_sig(body["pubkey"], body, sig or "")
        return JSONResponse(coord.submit(body["pubkey"], body["dps"],
                                         steps_done=body.get("steps_done", 0), abandoned=body.get("abandoned", 0),
                                         freshness=(body.get("epoch"), body.get("seq"))))

    @app.get("/api/audit/targets")
    def audit_targets(pubkey: str):
        return coord.audit_targets(pubkey)

    @app.post("/api/audit/open")
    def audit_open(req: Request, body: dict):
        limit(req, body, audit_ip, audit_key)
        body = dict(body)
        sig = body.pop("sig", "")
        Coordinator.verify_sig(body["pubkey"], body, sig)
        if body.get("round_id") != coord.spec.round_id:
            raise HTTPException(400, "wrong round_id")
        if type(body.get("audit_epoch")) is not int or type(body.get("t")) is not int or not isinstance(body.get("opening"), dict):
            raise HTTPException(400, "invalid audit opening")
        return coord.answer_audit(body["pubkey"], body["audit_epoch"], body["t"], body["opening"])

    @app.post("/api/rotate")
    def rotate(req: Request, body: dict):
        # Share submission buckets so rotation cannot bypass per-IP/key limits.
        limit(req, body, submit_ip, submit_key)
        return coord.rotate(body)

    return app


def _epoch_loop(coord: Coordinator, stop: threading.Event):
    while not stop.wait(1):
        try:
            if coord.status == "settling" and coord._get_state("pending_solution"):
                coord._finish(*coord._get_state("pending_solution"))
            else:
                coord.close_epoch()
            with coord.lock:
                coord.epoch_loop_failures = 0
        except Exception as e:  # Keep serving, but expose persistent failure.
            with coord.lock:
                coord.epoch_loop_failures += 1
                timestamp = time.monotonic()
                if coord.epoch_loop_failures == 3:
                    coord.event("epoch_loop_degraded", {"err": str(e), "failures": 3})
                if timestamp - coord._last_epoch_error >= 60:
                    coord._last_epoch_error = timestamp
                    coord.event("epoch_error", {"err": str(e), "failures": coord.epoch_loop_failures})


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", required=True, help="round spec json")
    ap.add_argument("--db", default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8642)
    args = ap.parse_args(argv)
    spec = ec.RoundSpec.load(args.round)
    db = args.db or os.path.join("data", spec.round_id + ".sqlite")
    os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
    coord = Coordinator(spec, db)
    import uvicorn

    print("WARNING: this round MUST be fronted by TLS in production.", flush=True)
    uvicorn.run(build_app(coord), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
