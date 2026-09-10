"""RhoNet walker: Ed25519 identity -> curve-native admission -> N worker processes
running batched rho walks -> signed DP batches every few seconds.

    python -m rhonet.walker --coordinator http://127.0.0.1:8642 --procs 4 --payout 0x...

--cheat submits fabricated DPs (valid-looking points with made-up coefficients)
to demonstrate that the coordinator's epoch audit catches and slashes it.
"""
from __future__ import annotations

import argparse
import itertools
import json
import multiprocessing as mp
import os
import queue
import re
import random
import secrets
import signal
import sys
import time

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import ec


RETRYABLE = {429, 503, 502, 504}


def retryable_response(response, on_stale=None):
    if response.status_code in RETRYABLE:
        return True
    if response.status_code == 400:
        try:
            if response.json().get("detail") == "stale submission":
                # Our epoch clock disagrees with the coordinator's. Resync before
                # the retry, or every attempt repeats the same rejected epoch.
                if on_stale is not None:
                    on_stale()
                return True
        except (ValueError, AttributeError):
            pass
    return False


def post_with_retry(client, path, build_body, *, budget=300.0, label="request", on_stale=None):
    """Rebuild each attempt; return the last response (None on transport exhaustion)."""
    started = time.monotonic()
    backoff = 0.5
    response = None
    while True:
        try:
            response = client.post(path, json=build_body())
            if not retryable_response(response, on_stale):
                return response
            reason = f"rate limited/unavailable ({response.status_code})"
        except httpx.TransportError as exc:
            response = None
            reason = f"transport error ({type(exc).__name__})"
        waited = time.monotonic() - started
        remaining = budget - waited
        if remaining <= 0:
            print(f"[walker] {path} {label}: retry budget exhausted after {waited:.1f}s",
                  file=sys.stderr)
            return response
        delay = min(remaining, backoff * random.uniform(0.75, 1.25))
        print(f"[walker] {path} {reason}, retrying in {delay:.1f}s "
              f"(waited {waited:.1f}s of {budget:g}s budget)", file=sys.stderr)
        time.sleep(delay)
        backoff = min(10.0, backoff * 2)
        if time.monotonic() - started >= budget:
            print(f"[walker] {path} {label}: retry budget exhausted after {budget:g}s",
                  file=sys.stderr)
            return response


def retain_deferred(pending, batch, result):
    """Capacity responses acknowledge only part of a batch; preserve original DPs."""
    retry = set(result.get("retry_indices", []))
    retry.update(i for i, reason in result.get("rejected", [])
                 if reason in ("audit backlog", "quota", "rate limit"))
    return sorted([dp for i, dp in enumerate(batch) if i in retry] + pending[len(batch):],
                  key=lambda dp: dp["t"])


AUDIT_DRAIN_SECONDS = 120.0


def detect_device() -> str:
    """A short, self-reported label for the hardware doing the work.

    Advisory only: it is not signed by anything and a walker can claim whatever it
    likes, so the board must present it as self-reported rather than as a fact.
    It exists so a search can show what kind of machines are actually contributing.
    """
    import platform, subprocess
    try:
        if platform.system() == "Darwin":
            chip = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                  capture_output=True, text=True, timeout=3).stdout.strip()
            model = subprocess.run(["sysctl", "-n", "hw.model"],
                                   capture_output=True, text=True, timeout=3).stdout.strip()
            if chip:
                return (chip + (f" ({model})" if model and model not in chip else ""))[:80]
        if platform.system() == "Linux":
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()[:80]
    except Exception:
        pass
    return f"{platform.system()} {platform.machine()}"[:80]


def registered_payout(pubkey: str, directory: str = None) -> str | None:
    """The address this key already registered, if it did.

    Passing --payout every run is easy to get wrong and the failure is silent: a
    random address is a valid address, so the work is credited to somebody who does
    not exist. If the key is in the public registry, use what it registered there.
    """
    directory = directory or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "contributors")
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return None
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name)) as f:
                entry = json.load(f)
        except (OSError, ValueError):
            continue
        if entry.get("pubkey") == pubkey and isinstance(entry.get("payout"), str):
            return entry["payout"]
    return None


def load_or_create_key(path: str) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    try:
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def pubkey_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def signed(key: Ed25519PrivateKey, body: dict) -> dict:
    """Sign the binary encoding of an explicit field list, not the JSON we send."""
    body = dict(body)
    body.pop("sig", None)
    body["sig"] = key.sign(ec.sign_bytes_for(body)).hex()
    return body


def worker(spec_dict, pk: str, batch: int, q: mp.Queue, stop: mp.Event, cheat: bool, wid: int, nprocs: int, cheat_evasive: bool = False):
    """One process, `batch` walks in lock-step. Ships (dps, steps, abandoned) to the parent
    twice a second in a single message: a put per DP starves the queue feeder
    thread of the GIL and throttles the whole worker."""
    spec = ec.RoundSpec.from_dict(spec_dict)
    table = ec.walk_table(spec)
    rng = itertools.count(wid, nprocs).__next__
    bw = ec.BatchWalker(spec, table, pk, batch, rng)
    buf = []
    last = time.time()
    while not stop.is_set():
        found = bw.step()
        if cheat_evasive:
            found = [dp for dp in found if int.from_bytes(
                ec.H(spec.round_id, "spot", pk, dp["t"]), "big") % spec.spot_check_rate != 0]
        if cheat or cheat_evasive:
            # fabricate: keep the real DP-shaped point, lie about the coefficients
            for dp in found:
                dp["a"] = secrets.randbelow(spec.curve.n)
                dp["b"] = secrets.randbelow(spec.curve.n)
        for dp in found:
            dp["_checkpoints"] = bw.checkpoints.pop(dp["t"])
        buf.extend(found)
        if time.time() - last > 0.5:
            q.put((buf, bw.steps_done, bw.abandoned))
            buf, bw.steps_done, bw.abandoned = [], 0, 0
            last = time.time()


def fmt(n: float) -> str:
    for unit in ("", "K", "M", "G", "T"):
        if abs(n) < 1000:
            return f"{n:.1f}{unit}"
        n /= 1000
    return f"{n:.1f}P"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--coordinator", default="http://127.0.0.1:8642")
    ap.add_argument("--key", default="walker.key")
    ap.add_argument("--payout", default=None, help="20-byte hex address credits are settled to")
    ap.add_argument("--procs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--flush", type=float, default=2.0, help="seconds between signed submissions")
    ap.add_argument("--device", default=None, help="hardware label to report; detected if omitted")
    ap.add_argument("--cheat", action="store_true")
    ap.add_argument("--cheat-evasive", action="store_true", help="fabricate only DPs skipped by the old audit selector")
    ap.add_argument("--max-seconds", type=float, default=None)
    args = ap.parse_args(argv)

    key = load_or_create_key(args.key)
    pk = pubkey_hex(key)
    payout = args.payout or registered_payout(pk)
    if payout is None:
        print("[walker] no --payout, and this key is not in contributors/.\n"
              "         Credit accrues to an address; inventing a random one would\n"
              "         quietly pay a stranger. Either pass --payout 0x<address>, or\n"
              "         register the key first:\n"
              f"           python -m tools.contributor sign --github <you> --key {args.key} \\\n"
              "               --payout 0x<address> > contributors/<you>.json\n"
              "         See docs/JOIN.md.", file=sys.stderr)
        return 2
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", payout):
        print(f"[walker] --payout must be a 20-byte hex address, got {payout!r}", file=sys.stderr)
        return 2
    client = httpx.Client(base_url=args.coordinator, timeout=60)

    # Reach the coordinator before spending anything. Minting a ticket costs about
    # 2^ticket_d steps -- twenty minutes of a core on Exercise 97 -- and a volunteer
    # who spends that and then meets a DNS failure has no way to tell a project-side
    # outage from a mistake of their own. Say which it is, before the cost.
    try:
        # A non-200 answers with something that is not a round, and is caught below
        # as such; the distinction that matters to a volunteer is reachable or not.
        spec_dict = client.get("/api/round").json()
        spec = ec.RoundSpec.from_dict(spec_dict)
    except httpx.HTTPError as exc:
        print(f"[walker] cannot reach the coordinator at {args.coordinator}: "
              f"{type(exc).__name__}.\n"
              "         The round may not be open yet. Nothing has been computed and\n"
              "         nothing has been lost. Check https://rhonet.dev for the round\n"
              "         status, or pass --coordinator for a different one.", file=sys.stderr)
        return 6
    except (ValueError, KeyError, TypeError) as exc:
        print(f"[walker] {args.coordinator} answered, but not with a round this client "
              f"understands: {exc}", file=sys.stderr)
        return 6
    table = ec.walk_table(spec)
    print(f"[walker] round {spec.round_id} ({spec.bits}-bit), w={spec.w}, expected {spec.expected_steps:.2e} steps; identity {pk[:16]}…", file=sys.stderr)

    t0 = time.time()
    device = args.device or detect_device()
    ticket = ec.ticket_solve(spec, table, pk)
    print(f"[walker] ticket minted in {time.time()-t0:.1f}s ({ticket['steps']} steps, nonce {ticket['nonce']})", file=sys.stderr)
    # Timestamp seed avoids resetting seq to zero when reusing an identity.
    seq = itertools.count(time.time_ns())
    # The epoch is a clock, not a fact to be fetched. Asking the coordinator for it
    # before every signed message doubles the request rate of the whole network and
    # makes the most expensive read the hottest one. Derive it locally from the
    # round's own start time, and resync only when the server says we are stale.
    clock = {"started_at": None, "skew": 0.0}
    def local_epoch():
        if clock["started_at"] is None:
            state = client.get("/api/status").json()
            if not isinstance(state.get("started_at"), (int, float)):
                # A coordinator that does not publish its clock still publishes the
                # epoch. Fall back to asking, rather than guessing and being stale.
                return max(0, int(state.get("epoch", 0)))
            clock["started_at"] = state["started_at"]
            clock["skew"] = state.get("now", time.time()) - time.time()
        return max(0, int((time.time() + clock["skew"] - clock["started_at"])
                          // spec.epoch_seconds))
    def resync():
        clock["started_at"] = None
    def fresh_body(**fields):
        return signed(key, {"round_id": spec.round_id, "pubkey": pk, **fields,
                            "epoch": local_epoch(), "seq": next(seq)})

    r = post_with_retry(client, "/api/ticket",
                        lambda: fresh_body(payout_addr=payout, ticket=ticket, device=device),
                        label="admission", on_stale=resync)
    if r is None or r.status_code != 200:
        print(f"[walker] admission unsuccessful: {r.status_code if r is not None else 'transport failure'}", file=sys.stderr)
        return 2
    epoch = r.json()["epoch"]
    print(f"[walker] admitted (epoch {r.json()['epoch']}); payout {payout}", file=sys.stderr)

    ctx = mp.get_context("fork")
    q = ctx.Queue(maxsize=max(2, args.procs * 2))
    stop = ctx.Event()
    procs = [ctx.Process(target=worker, args=(spec_dict, pk, args.batch, q, stop, args.cheat, i, args.procs, args.cheat_evasive), daemon=True) for i in range(args.procs)]
    for p in procs:
        p.start()

    checkpoints = {}
    checkpoint_epochs = {}
    # A tenth of the response window: prompt enough that a challenge is answered
    # long before it expires, slow enough that a thousand walkers polling this
    # endpoint is not itself the load. Toy rounds with a ten-second window still
    # poll about once a second.
    audit_poll_seconds = max(0.5, min(20.0, spec.audit_response_seconds / 10))
    last_audit_poll = 0.0
    pending, steps_local, sent_dps, credited_steps = [], 0, 0, 0
    steps_pending, abandoned_pending = 0, 0
    last_flush = time.time()
    started = time.time()
    rc = 0
    retry_at, batch_limit = 0.0, 256
    def shutdown(signum, frame):
        raise KeyboardInterrupt
    old_term = signal.signal(signal.SIGTERM, shutdown)
    try:
        while True:
            if time.time() - last_audit_poll >= audit_poll_seconds:
                try:
                    targets = client.get("/api/audit/targets", params={"pubkey": pk}).json()
                    for target in targets:
                        points = checkpoints.get(target["t"])
                        if points is None:
                            continue
                        # An unanswered challenge withholds this epoch's credit and,
                        # repeated, costs the identity its standing. A rate-limit
                        # response is not a reason to give up on one.
                        opening = ec.checkpoint_opening(points, target["segment"])
                        post_with_retry(client, "/api/audit/open", lambda t=target, o=opening:
                            signed(key, {"round_id": spec.round_id, "pubkey": pk,
                                         "audit_epoch": t["epoch"], "t": t["t"], "opening": o}),
                            budget=max(10.0, target["deadline"] - time.time()), label="audit opening")
                    state = client.get("/api/status").json()
                    matured = {ep["idx"] for ep in state.get("epochs", []) if ep["audit_complete"]}
                    for t in list(checkpoint_epochs):
                        if checkpoint_epochs[t] in matured:
                            checkpoints.pop(t, None)
                            checkpoint_epochs.pop(t)
                    if state["status"] == "solved":
                        # Do not walk away from outstanding challenges. Credit that
                        # is never opened cannot be verified and so cannot be paid,
                        # and the round ending is not a reason to abandon work that
                        # has already been done. Drain the targets, then leave.
                        stop.set()
                        drain_deadline = time.time() + AUDIT_DRAIN_SECONDS
                        while time.time() < drain_deadline:
                            try:
                                remaining = client.get("/api/audit/targets",
                                                       params={"pubkey": pk}).json()
                            except httpx.HTTPError:
                                time.sleep(0.5)
                                continue
                            if not remaining:
                                break
                            answered = 0
                            for target in remaining:
                                points = checkpoints.get(target["t"])
                                if points is None:
                                    continue
                                body = signed(key, {"round_id": spec.round_id, "pubkey": pk,
                                    "audit_epoch": target["epoch"], "t": target["t"],
                                    "opening": ec.checkpoint_opening(points, target["segment"])})
                                try:
                                    post_with_retry(client, "/api/audit/open",
                                                    lambda b=body: b, budget=15.0,
                                                    label="audit opening (drain)")
                                    answered += 1
                                except httpx.HTTPError:
                                    pass
                            if not answered:
                                time.sleep(0.5)
                        print("[walker] ROUND SOLVED", file=sys.stderr)
                        break
                    if state["status"] == "settling":
                        stop.set()
                        time.sleep(.1)
                        continue
                except httpx.HTTPError:
                    pass
                last_audit_poll = time.time()
            try:
                if len(pending) >= 5000:
                    time.sleep(0.2)
                    raise queue.Empty
                items, s, abandoned = q.get(timeout=0.2)
                for dp in items:
                    if "_checkpoints" in dp:
                        checkpoints[dp["t"]] = dp.pop("_checkpoints")
                pending.extend(items)
                steps_local += s
                steps_pending += s
                abandoned_pending += abandoned
            except queue.Empty:
                pass
            if time.time() >= retry_at and time.time() - last_flush >= args.flush and (pending or steps_pending or abandoned_pending):
                pending.sort(key=lambda dp: dp["t"])
                batch = pending[:batch_limit]
                r = post_with_retry(client, "/api/submit",
                                    lambda: fresh_body(dps=batch, steps_done=steps_pending,
                                                       abandoned=abandoned_pending),
                                    label="submission", on_stale=resync)
                if r is None or retryable_response(r):
                    print("[walker] retaining pending work; will retry submission", file=sys.stderr)
                    last_flush = time.time()
                    continue
                if r.status_code != 200:
                    print(f"[walker] submit failed: {r.status_code} {r.text}", file=sys.stderr)
                    rc = 3
                    break
                res = r.json()
                rejected_indices = {i for i, _ in res.get("rejected", [])}
                for i, dp in enumerate(batch):
                    if i not in rejected_indices:
                        checkpoint_epochs[dp["t"]] = res.get("epoch", epoch)
                pending = retain_deferred(pending, batch, res)
                retry_at = time.time() + max(0, float(res.get("retry_after", 0)))
                batch_limit = max(1, min(5000, int(res.get("batch_limit", 256))))
                epoch = res.get("epoch", epoch)
                steps_pending, abandoned_pending = 0, 0
                sent_dps += res.get("accepted", 0)
                credited_steps += res.get("accepted", 0) << spec.w
                el = time.time() - started
                # Show the ceiling when we are near it, so being ramped up does not
                # look like being rejected.
                capacity = ""
                if res.get("quota") and res.get("quota_used", 0) >= 0.8 * res["quota"]:
                    capacity = (f"  quota {res['quota_used']}/{res['quota']}"
                                f" ({res.get('quota_source', 'slow-start')})")
                if res.get("audit_backlog_limit") and res.get("audit_backlog", 0) >= (
                        0.8 * res["audit_backlog_limit"]):
                    capacity += f"  backlog {res['audit_backlog']}/{res['audit_backlog_limit']}"
                print(f"[walker] {el:6.0f}s  local {fmt(steps_local/el)} steps/s  sent {sent_dps} DPs  credited {credited_steps/(1<<spec.credit_unit_log2):.3f} credits  "
                      f"rejected {len(res.get('rejected', []))}{capacity}", file=sys.stderr)
                if res.get("slashed"):
                    print(f"[walker] SLASHED: {res['rejected'][-1:] }", file=sys.stderr)
                    rc = 4
                    break
                if res.get("solved") or res.get("status") == "solved":
                    sol = res.get("solved")
                    if sol:
                        print(f"[walker] ROUND SOLVED  k = {sol['k']}  (verified={sol['verified']}, credited/expected = {sol['ratio']:.2f})", file=sys.stderr)
                        me = [p for p in sol["payouts"] if p["pubkey"] == pk]
                        if me:
                            print(f"[walker] my share {me[0]['share']*100:.2f}% -> {me[0]['usdc']:.2f} USDC", file=sys.stderr)
                    else:
                        print("[walker] round already solved", file=sys.stderr)
                    break
                last_flush = time.time()
            if args.max_seconds and time.time() - started > args.max_seconds:
                print("[walker] time limit reached", file=sys.stderr)
                rc = 5
                break
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, old_term)
        stop.set()
        for p in procs:
            p.terminate()
        for p in procs:
            p.join(timeout=2)
    return rc


if __name__ == "__main__":
    sys.exit(main())
