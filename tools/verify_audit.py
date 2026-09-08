"""Re-derive a published epoch's audit and fail if it does not match.

This is the check that turns "the operator says it audited the work" into
something a stranger, or a CI job, can confirm. For every published epoch it:

  1. checks the beacon reveal really opens the commitment published beforehand,
     so the entropy that chose the audit targets was fixed before the batch was
     sealed rather than picked afterwards to suit somebody;
  2. recomputes, for each contributor, which of its work identifiers the rule
     selects over the range it submitted, and compares that with the identifiers
     the operator says it replayed.

A missing target means the operator skipped work it was supposed to check. An
extra one is harmless but is reported, because it means the published rule is
not the rule that ran.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rhonet import ec


def rank_and_take(seed: bytes, beacon: bytes, tag: str, pubkey: str,
                  ts: list[int], rate: int) -> list[int]:
    """The rule the coordinator runs: rank an identity's candidates by a hash of
    the seed, the beacon, the pass and the identifier, then take a fraction. The
    delayed pass additionally reserves the oldest identifier, so a point can never
    sit unaudited forever just because its hash ranks badly."""
    count = (len(ts) + rate - 1) // rate
    ranked = sorted(ts, key=lambda t: (ec.H(seed, beacon, tag, pubkey, t), t))
    if tag == "spot2" and ts:
        oldest = min(ts)
        ranked = [oldest] + [t for t in ranked if t != oldest]
    return ranked[:count]


def check(path: str) -> list[str]:
    problems = []
    with open(path) as f:
        d = json.load(f)
    where = os.path.basename(path)

    beacon_block = d.get("beacon") or {}
    reveal, commitment = beacon_block.get("reveal"), beacon_block.get("commitment")
    if beacon_block.get("source") == "commit-reveal":
        if not reveal or not commitment:
            problems.append(f"{where}: commit-reveal beacon is missing its commitment or reveal")
        elif ec.H(bytes.fromhex(reveal)).hex() != commitment:
            problems.append(f"{where}: beacon reveal does not open the published commitment")
    elif not reveal:
        problems.append(f"{where}: external beacon has no recorded value")

    seed_hex = (d.get("audit_seed_root") or "").removeprefix("0x")
    if not seed_hex or not reveal:
        problems.append(f"{where}: cannot re-derive the audit; seed root or beacon missing")
        return problems
    seed, beacon = bytes.fromhex(seed_hex), bytes.fromhex(reveal)
    index = {str(k): v for k, v in (d.get("index_to_pubkey") or {}).items()}

    for tag, block in (d.get("audit") or {}).items():
        if block.get("selection") != "per-identity-fraction-v1":
            problems.append(f"{where}: {tag} declares selection rule "
                            f"{block.get('selection')!r}, which this checker does not know")
            continue
        rate = block.get("rate")
        pressure = set(block.get("pressure_identities") or [])
        pressure_rate = block.get("pressure_rate") or rate
        groups = {}
        for i, t in block.get("candidates", []):
            groups.setdefault(index.get(str(i), str(i)), []).append(int(t))
        expected = set()
        for pk, ts in groups.items():
            r = pressure_rate if pk in pressure else rate
            for t in rank_and_take(seed, beacon, tag, pk, sorted(ts), r):
                expected.add((pk, t))
        claimed = {(index.get(str(i), str(i)), int(t)) for i, t in block.get("selected", [])}
        missing, extra = expected - claimed, claimed - expected
        if missing:
            problems.append(f"{where}: {tag} skipped {len(missing)} of {len(expected)} "
                            f"identifiers the published rule selects")
        if extra:
            problems.append(f"{where}: {tag} replayed {len(extra)} identifiers the rule "
                            f"does not select")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=["public/epochs"])
    a = ap.parse_args(argv)
    files = []
    for p in a.paths:
        files.extend(sorted(glob.glob(os.path.join(p, "*.json")) if os.path.isdir(p) else glob.glob(p)))
    if not files:
        print("no published epochs to check")
        return 0
    problems = []
    for f in files:
        problems += check(f)
    for p in problems:
        print("FAIL " + p)
    print(f"checked {len(files)} epoch(s); {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
