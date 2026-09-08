"""RhoWalkers coordinator (v1: single operator).

Responsibilities, in the order a DP passes through them:
  admission  -> curve-native ticket replayed once per identity, slow-start quota
  intake     -> signature check, format check, uniqueness, bounded sequential work identifiers
  ledger     -> credited_steps per miner (1 credit = 2^credit_unit_log2 steps)
  collision  -> same x from two different walks -> solve k, verify k*G == Q, end round
  epochs     -> every epoch_seconds: Merkle root over (payout_addr, credited_steps), the thing
                that would be posted to the L2 PrizeVault; proofs served to miners

State lives in one sqlite file; the coordinator can be restarted at any time.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
import time
from collections import deque

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from . import ec, merkle

T_WINDOW = 4096
MAX_AUDITS_PER_EPOCH = 512
MAX_DELAYED_AUDITS_PER_EPOCH = 64

STATIC = os.path.join(os.path.dirname(__file__), "static")

SCHEMA = """
CREATE TABLE IF NOT EXISTS miners (
  pubkey TEXT PRIMARY KEY, payout_addr TEXT NOT NULL, ticket TEXT NOT NULL,
  admitted_at REAL NOT NULL, admitted_epoch INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', dps INTEGER NOT NULL DEFAULT 0,
  credited_steps INTEGER NOT NULL DEFAULT 0, spot_checks INTEGER NOT NULL DEFAULT 0,
  spot_fails INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0,
  epoch_dps INTEGER NOT NULL DEFAULT 0, epoch_dps_epoch INTEGER NOT NULL DEFAULT -1,
  next_t INTEGER NOT NULL DEFAULT 0, t_gaps INTEGER NOT NULL DEFAULT 0,
  last_seen REAL, note TEXT
);
CREATE TABLE IF NOT EXISTS dps (
  x TEXT NOT NULL, y TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL,
  pubkey TEXT NOT NULL, t INTEGER NOT NULL, steps INTEGER NOT NULL,
  ts REAL NOT NULL, checked INTEGER NOT NULL DEFAULT 0,
  epoch INTEGER NOT NULL DEFAULT -1,
  PRIMARY KEY (pubkey, t)
);
CREATE INDEX IF NOT EXISTS dps_x ON dps(x);
CREATE INDEX IF NOT EXISTS dps_epoch_checked ON dps(epoch, checked);
CREATE TABLE IF NOT EXISTS epochs (
  idx INTEGER PRIMARY KEY, ts REAL NOT NULL, root TEXT NOT NULL,
  total_steps INTEGER NOT NULL, n_miners INTEGER NOT NULL, leaves TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def migrate_schema(db):
    """Upgrade existing tables before SCHEMA creates indexes on new columns."""
    for table, column, default in (("dps", "epoch", -1), ("miners", "next_t", 0),
                                   ("miners", "t_gaps", 0)):
        try:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER NOT NULL DEFAULT {default}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc) and "no such table" not in str(exc):
                raise
    db.commit()


def now() -> float:
    return time.time()


class Coordinator:
    def __init__(self, spec: ec.RoundSpec, db_path: str):
        self.spec = spec
        self.table = ec.walk_table(spec)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        migrate_schema(self.db)
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.commit()
        self.rate_window = deque(maxlen=600)  # (ts, steps) for live throughput
        self.started_at = float(self._get_state("started_at") or now())
        self._set_state("started_at", self.started_at)
        if not self._get_state("status"):
            self._set_state("status", "open")
            self.event("round_open", {"round_id": spec.round_id, "bits": spec.bits})

    # ---------------------------------------------------------------- state helpers
    def _get_state(self, k):
        row = self.db.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
        return json.loads(row[0]) if row else None

    def _set_state(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO state(k, v) VALUES(?, ?)", (k, json.dumps(v)))
        self.db.commit()

    @property
    def status(self) -> str:
        return self._get_state("status")

    def event(self, kind: str, detail: dict):
        self.db.execute("INSERT INTO events(ts, kind, detail) VALUES(?, ?, ?)", (now(), kind, json.dumps(detail)))
        self.db.commit()

    def current_epoch(self) -> int:
        return int((now() - self.started_at) // self.spec.epoch_seconds)

    # ---------------------------------------------------------------- crypto
    @staticmethod
    def verify_sig(pubkey_hex: str, body: dict, sig_hex: str):
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
            pk.verify(bytes.fromhex(sig_hex), ec.canonical(body))
        except (ValueError, InvalidSignature):
            raise HTTPException(401, "bad signature")

    # ---------------------------------------------------------------- admission
    def admit(self, pubkey: str, payout_addr: str, ticket: dict):
        spec = self.spec
        if self.status != "open":
            raise HTTPException(409, f"round is {self.status}")
        if not (payout_addr.startswith("0x") and len(payout_addr) == 42 and int(payout_addr, 16) >= 0):
            raise HTTPException(400, "payout_addr must be a 20-byte hex address")
        with self.lock:
            row = self.db.execute("SELECT status FROM miners WHERE pubkey=?", (pubkey,)).fetchone()
            if row:
                if row[0] == "slashed":
                    raise HTTPException(403, "identity slashed; mint a new ticket with a new key")
                return {"admitted": True, "already": True, "epoch": self.current_epoch()}
            t0 = time.time()
            ok = ec.ticket_verify(spec, self.table, pubkey, ticket)
            if not ok:
                self.event("ticket_rejected", {"pubkey": pubkey[:16]})
                raise HTTPException(400, "ticket does not replay")
            ep = self.current_epoch()
            self.db.execute(
                "INSERT INTO miners(pubkey, payout_addr, ticket, admitted_at, admitted_epoch, last_seen) VALUES(?,?,?,?,?,?)",
                (pubkey, payout_addr.lower(), json.dumps(ticket), now(), ep, now()),
            )
            self.db.commit()
            self.event("miner_admitted", {"pubkey": pubkey[:16], "ticket_steps": ticket["steps"], "verify_ms": round((time.time() - t0) * 1000)})
            return {"admitted": True, "already": False, "epoch": ep}

    def quota(self, admitted_epoch: int) -> int:
        """Slow start: doubles every epoch since admission, capped."""
        age = max(0, self.current_epoch() - admitted_epoch)
        return min(self.spec.quota_dps_per_epoch_base << min(age, 10), 1 << 30)

    # ---------------------------------------------------------------- intake
    def submit(self, pubkey: str, dps: list[dict]):
        spec = self.spec
        if self.status != "open":
            return {"accepted": 0, "rejected": [], "status": self.status, "solved": self._get_state("solution")}
        if len(dps) > 5000:
            raise HTTPException(413, "batch too large")
        with self.lock:
            m = self.db.execute(
                "SELECT status, admitted_epoch, epoch_dps, epoch_dps_epoch, next_t, t_gaps, dps FROM miners WHERE pubkey=?", (pubkey,)
            ).fetchone()
            if not m:
                raise HTTPException(403, "no ticket for this identity")
            status, admitted_epoch, epoch_dps, epoch_dps_epoch, next_t, t_gaps, total_dps = m
            if status == "slashed":
                raise HTTPException(403, "identity slashed")
            ep = self.current_epoch()
            if epoch_dps_epoch != ep:
                epoch_dps, epoch_dps_epoch = 0, ep
            q = self.quota(admitted_epoch)
            used = {r[0] for r in self.db.execute(
                "SELECT t FROM dps WHERE pubkey=? AND t>=?", (pubkey, next_t))}

            accepted, rejected, checked = 0, [], 0
            credited = 0
            solved = None
            p, n, w = spec.curve.p, spec.curve.n, spec.w
            for i, dp in enumerate(dps):
                try:
                    x, y, a, b, t, steps = (int(dp[k]) for k in ("x", "y", "a", "b", "t", "steps"))
                except (KeyError, ValueError, TypeError):
                    rejected.append((i, "malformed")); continue
                if not (0 <= x < p and 0 <= y < p and 0 <= a < n and 0 <= b < n and 0 < steps <= (1 << spec.max_walk_len_log2) and 0 <= t < (1 << 63)):
                    rejected.append((i, "range")); continue
                if not ec.is_dp(x, w):
                    rejected.append((i, "not a distinguished point")); continue
                if not spec.curve.on_curve((x, y)):
                    rejected.append((i, "not on curve")); continue
                if epoch_dps >= q:
                    rejected.append((i, "quota")); continue
                if t < next_t:
                    rejected.append((i, "t reused/too old")); continue
                if t in used:
                    rejected.append((i, "duplicate")); continue
                if t >= next_t + T_WINDOW:
                    # Retire only missing slots; already accepted out-of-order work
                    # must not count as gaps.
                    floor = t - T_WINDOW + 1
                    retired = {v for v in used if v < floor}
                    t_gaps += floor - next_t - len(retired)
                    used.difference_update(retired)
                    next_t = floor

                # collision check against every earlier walk that hit this x
                prior = self.db.execute("SELECT a, b, y, pubkey, t FROM dps WHERE x=?", (str(x),)).fetchall()
                self.db.execute(
                    "INSERT INTO dps(x, y, a, b, pubkey, t, steps, ts, checked, epoch) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (str(x), str(y), str(a), str(b), pubkey, t, steps, now(), 0, ep),
                )
                used.add(t)
                while next_t in used:
                    used.remove(next_t)
                    next_t += 1
                accepted += 1
                epoch_dps += 1
                credited += 1 << w
                if total_dps + accepted >= 64 and t_gaps * 4 > total_dps + accepted:
                    # Stop at the offending prefix, before later rows in this
                    # batch could dilute the gap ratio. Persist counters below.
                    break
                for (pa, pb, py, ppk, pt) in prior:
                    if (pa, pb) == (str(a), str(b)):
                        # identical coefficients at the same x from a different PRF start cannot happen
                        # honestly: this DP was copied from the public table
                        self._slash(pubkey, f"copied DP (same a,b as {ppk[:16]}) t={t}")
                        return {"accepted": accepted, "rejected": rejected, "slashed": True}
                    other = {"a": pa, "b": pb, "y": py}
                    # the colliding pair is worth verifying fully before we trust it
                    if not ec.dp_verify(spec, self.table, pubkey, dp):
                        self._slash(pubkey, f"collision DP failed replay t={t}")
                        return {"accepted": accepted, "rejected": rejected, "slashed": True}
                    k = ec.solve_collision(spec, {"a": a, "b": b, "y": y}, other)
                    if k is not None:
                        solved = (k, pubkey, ppk, x)
                        break
                if solved:
                    break

            self.db.execute(
                "UPDATE miners SET dps=dps+?, credited_steps=credited_steps+?, spot_checks=spot_checks+?, rejected=rejected+?, "
                "epoch_dps=?, epoch_dps_epoch=?, last_seen=?, next_t=?, t_gaps=? WHERE pubkey=?",
                (accepted, credited, checked, len(rejected), epoch_dps, epoch_dps_epoch, now(), next_t, t_gaps, pubkey),
            )
            self.db.commit()
            if total_dps + accepted >= 64 and t_gaps * 4 > total_dps + accepted:
                self._slash(pubkey, "excessive t gaps")
                return {"accepted": accepted, "rejected": rejected, "slashed": True}
            self.rate_window.append((now(), credited))
            out = {"accepted": accepted, "rejected": rejected, "checked": checked, "quota_left": q - epoch_dps, "epoch": ep}
            if solved:
                out["solved"] = self._finish(*solved)
            return out

    def _slash(self, pubkey: str, why: str):
        self.db.execute("UPDATE miners SET status='slashed', spot_fails=spot_fails+1, credited_steps=0, note=? WHERE pubkey=?", (why, pubkey))
        self.db.commit()
        self.event("slashed", {"pubkey": pubkey[:16], "why": why})

    def _finish(self, k: int, finder: str, partner: str, x: int) -> dict:
        spec = self.spec
        total = self.db.execute("SELECT COALESCE(SUM(credited_steps),0) FROM miners WHERE status='active'").fetchone()[0]
        rows = self.db.execute("SELECT pubkey, payout_addr, credited_steps FROM miners WHERE status='active' AND credited_steps>0").fetchall()
        payouts = [
            {"pubkey": pk, "payout_addr": addr, "credited_steps": st, "credits": st / (1 << spec.credit_unit_log2),
             "share": st / total if total else 0, "usdc": spec.prize_pool_usdc * st / total if total else 0}
            for pk, addr, st in rows
        ]
        payouts.sort(key=lambda r: -r["credited_steps"])
        sol = {
            "k": k, "k_hex": hex(k), "found_at": now(), "collision_x": x,
            "finder": finder, "partner": partner, "total_credited_steps": total,
            "expected_steps": spec.expected_steps, "ratio": total / spec.expected_steps,
            "verified": spec.curve.mul(k, spec.curve.G) == spec.Q,
            "payouts": payouts,
        }
        self._set_state("solution", sol)
        self._set_state("status", "solved")
        self.event("solved", {"k_hex": hex(k), "finder": finder[:16], "partner": partner[:16], "ratio": round(sol["ratio"], 3)})
        return sol

    # ---------------------------------------------------------------- epochs
    def audit_epoch(self, idx, root_bytes):
        rows = self.db.execute(
            "SELECT pubkey, t, x, y, a, b, steps FROM dps WHERE epoch=? AND checked=0",
            (idx,),
        ).fetchall()
        self._audit_rows(idx, root_bytes, rows, "spot", self.spec.spot_check_rate,
                         MAX_AUDITS_PER_EPOCH, "epoch_audit")

    def audit_delayed(self, idx, root_bytes):
        rows = self.db.execute(
            "SELECT pubkey, t, x, y, a, b, steps FROM dps WHERE epoch<? AND checked=1",
            (idx,),
        ).fetchall()
        self._audit_rows(idx, root_bytes, rows, "spot2", self.spec.spot_check_rate * 8,
                         MAX_DELAYED_AUDITS_PER_EPOCH, "delayed_audit")

    def _audit_rows(self, idx, root_bytes, rows, tag, rate, cap, event_kind):
        targets = []
        for row in rows:
            selector = int.from_bytes(ec.H(root_bytes, tag, row[0], row[1]), "big")
            if selector % rate == 0:
                targets.append((selector, row))
        targets.sort()  # Full selector, then row as deterministic tie breaker.
        passed = failed = 0
        for _, (pk, t, x, y, a, b, steps) in targets[:cap]:
            dp = dict(t=t, x=x, y=y, a=a, b=b, steps=steps)
            if ec.dp_verify(self.spec, self.table, pk, dp):
                self.db.execute("UPDATE dps SET checked=1 WHERE pubkey=? AND t=?", (pk, t))
                self.db.execute("UPDATE miners SET spot_checks=spot_checks+1 WHERE pubkey=?", (pk,))
                passed += 1
            else:
                self._slash(pk, f"epoch {idx} audit failed on t={t}")
                self.event("audit_failed", {"epoch": idx, "pubkey": pk[:16], "t": t})
                failed += 1
        self.db.commit()
        self.event(event_kind, {"epoch": idx, "targets": min(len(targets), cap),
                                "passed": passed, "failed": failed})

    def close_epoch(self):
        with self.lock:
            last = self.db.execute("SELECT MAX(idx) FROM epochs").fetchone()[0]
            # Catch up every sealed batch if the timer or coordinator was paused.
            for idx in range(0 if last is None else last + 1, self.current_epoch()):
                rows = self.db.execute(
                    "SELECT payout_addr, SUM(credited_steps) FROM miners WHERE status='active' AND credited_steps>0 GROUP BY payout_addr ORDER BY payout_addr"
                ).fetchall()
                leaves = [merkle.leaf_hash(addr, st) for addr, st in rows]
                root, _ = merkle.build(leaves)
                total = sum(st for _, st in rows)
                self.db.execute(
                    "INSERT INTO epochs(idx, ts, root, total_steps, n_miners, leaves) VALUES(?,?,?,?,?,?)",
                    (idx, now(), root.hex(), total, len(rows), json.dumps([[a, s] for a, s in rows])),
                )
                self.db.commit()
                self.audit_epoch(idx, root)
                self.audit_delayed(idx, root)
                self.event("epoch_closed", {"epoch": idx, "root": root.hex()[:16], "total_steps": total, "miners": len(rows)})

    def proof(self, payout_addr: str):
        row = self.db.execute("SELECT idx, root, leaves FROM epochs ORDER BY idx DESC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(404, "no epoch closed yet")
        idx, root, leaves = row
        leaves = json.loads(leaves)
        addrs = [a for a, _ in leaves]
        if payout_addr.lower() not in addrs:
            raise HTTPException(404, "address has no credited steps in latest epoch")
        i = addrs.index(payout_addr.lower())
        lh = [merkle.leaf_hash(a, s) for a, s in leaves]
        _, layers = merkle.build(lh)
        pf = merkle.proof(layers, i)
        return {"epoch": idx, "root": "0x" + root, "payout_addr": payout_addr.lower(), "credited_steps": leaves[i][1],
                "proof": ["0x" + p.hex() for p in pf], "verifies": merkle.verify(bytes.fromhex(root), lh[i], pf)}

    # ---------------------------------------------------------------- reads
    def status_view(self):
        spec = self.spec
        total, n_dps, n_miners, n_active = self.db.execute(
            "SELECT COALESCE(SUM(credited_steps),0), COALESCE(SUM(dps),0), COUNT(*), SUM(status='active') FROM miners"
        ).fetchone()
        cutoff = now() - 60
        recent = [(ts, s) for ts, s in self.rate_window if ts > cutoff]
        rate = sum(s for _, s in recent) / 60 if recent else 0
        slashed = self.db.execute("SELECT COUNT(*) FROM miners WHERE status='slashed'").fetchone()[0]
        checks = self.db.execute("SELECT COALESCE(SUM(spot_checks),0) FROM miners").fetchone()[0]
        last_epoch = self.db.execute("SELECT idx, root, ts, total_steps, n_miners FROM epochs ORDER BY idx DESC LIMIT 1").fetchone()
        return {
            "round": spec.to_dict(),
            "status": self.status,
            "started_at": self.started_at,
            "now": now(),
            "epoch": self.current_epoch(),
            "total_credited_steps": total,
            "total_credits": total / (1 << spec.credit_unit_log2),
            "progress": total / spec.expected_steps,
            "dps": n_dps,
            "miners": n_miners,
            "active_miners": n_active or 0,
            "slashed": slashed,
            "spot_checks": checks,
            "steps_per_sec": rate,
            "eta_seconds": (spec.expected_steps - total) / rate if rate > 0 and total < spec.expected_steps else None,
            "last_epoch": None if not last_epoch else {"idx": last_epoch[0], "root": "0x" + last_epoch[1], "ts": last_epoch[2], "total_steps": last_epoch[3], "miners": last_epoch[4]},
            "solution": self._get_state("solution"),
        }

    def miners_view(self):
        rows = self.db.execute(
            "SELECT pubkey, payout_addr, status, dps, credited_steps, spot_checks, spot_fails, rejected, admitted_at, last_seen, note FROM miners ORDER BY credited_steps DESC"
        ).fetchall()
        total = sum(r[4] for r in rows if r[2] == "active") or 1
        return [
            {"pubkey": r[0], "payout_addr": r[1], "status": r[2], "dps": r[3], "credited_steps": r[4],
             "credits": r[4] / (1 << self.spec.credit_unit_log2), "share": (r[4] / total) if r[2] == "active" else 0,
             "spot_checks": r[5], "spot_fails": r[6], "rejected": r[7], "admitted_at": r[8], "last_seen": r[9], "note": r[10]}
            for r in rows
        ]

    def epochs_view(self, limit=50):
        rows = self.db.execute("SELECT idx, ts, root, total_steps, n_miners FROM epochs ORDER BY idx DESC LIMIT ?", (limit,)).fetchall()
        return [{"idx": r[0], "ts": r[1], "root": "0x" + r[2], "total_steps": r[3], "miners": r[4]} for r in rows]

    def events_view(self, limit=60):
        rows = self.db.execute("SELECT ts, kind, detail FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r[0], "kind": r[1], "detail": json.loads(r[2])} for r in rows]


# -------------------------------------------------------------------- HTTP


def build_app(coord: Coordinator) -> FastAPI:
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app):
        threading.Thread(target=_epoch_loop, args=(coord,), daemon=True).start()
        yield

    app = FastAPI(title="RhoWalkers coordinator", version="0.1", lifespan=lifespan)

    @app.get("/")
    def index():
        return FileResponse(os.path.join(STATIC, "index.html"))

    @app.get("/api/round")
    def round_spec():
        return coord.spec.to_dict()

    @app.get("/api/status")
    def status():
        return coord.status_view()

    @app.get("/api/miners")
    def miners():
        return coord.miners_view()

    @app.get("/api/epochs")
    def epochs():
        return coord.epochs_view()

    @app.get("/api/events")
    def events():
        return coord.events_view()

    @app.get("/api/proof")
    def proof(payout_addr: str):
        return coord.proof(payout_addr)

    @app.post("/api/ticket")
    async def ticket(req: Request):
        body = await req.json()
        sig = body.pop("sig", None)
        for k in ("pubkey", "payout_addr", "ticket"):
            if k not in body:
                raise HTTPException(400, f"missing {k}")
        if body.get("round_id") != coord.spec.round_id:
            raise HTTPException(400, "wrong round_id")
        Coordinator.verify_sig(body["pubkey"], body, sig or "")
        return coord.admit(body["pubkey"], body["payout_addr"], body["ticket"])

    @app.post("/api/submit")
    async def submit(req: Request):
        body = await req.json()
        sig = body.pop("sig", None)
        if body.get("round_id") != coord.spec.round_id:
            raise HTTPException(400, "wrong round_id")
        if "pubkey" not in body or not isinstance(body.get("dps"), list):
            raise HTTPException(400, "missing pubkey/dps")
        Coordinator.verify_sig(body["pubkey"], body, sig or "")
        return JSONResponse(coord.submit(body["pubkey"], body["dps"]))

    return app


def _epoch_loop(coord: Coordinator):
    while True:
        time.sleep(1)
        try:
            coord.close_epoch()
        except Exception as e:  # keep the loop alive
            coord.event("epoch_error", {"err": str(e)})


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

    uvicorn.run(build_app(coord), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
