"""Publish the per-epoch audit trail so anyone can check the audit was not steered.

The operator runs this against a round's database. It writes one JSON file per
closed epoch containing everything a third party needs to re-derive that epoch's
audit selection: the seed root, the beacon commitment and its reveal, the audit
rate, and for each contributor the range of work identifiers it submitted in that
epoch together with the identifiers that were actually replayed.

Publishing the ranges rather than every identifier keeps the file small while
keeping the check complete: a contributor's own range is short, and anyone can
recompute the selection over it and see whether the published set matches. An
operator that quietly skipped a target is then visible in CI, not merely
detectable in principle.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def publish(db_path: str, out_dir: str, round_id: str | None = None) -> list[str]:
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cols = {r[1] for r in db.execute("PRAGMA table_info(epochs)")}
    need = {"idx", "root", "audit_seed_root", "beacon_commitment", "beacon_reveal",
            "beacon_source", "audit_complete", "audit_inputs"}
    missing = need - cols
    if missing:
        raise SystemExit(f"database predates the audit trail: missing {sorted(missing)}")
    spec = json.loads(db.execute("SELECT v FROM state WHERE k='round_spec'").fetchone()[0]) \
        if db.execute("SELECT 1 FROM state WHERE k='round_spec'").fetchone() else {}
    rid = round_id or spec.get("round_id") or os.path.basename(db_path).split(".")[0]
    if "audit_candidates" not in {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}:
        raise SystemExit("database predates the recorded audit candidate list")
    idx_to_pk = {i: pk for pk, i in db.execute("SELECT pubkey, miner_idx FROM miners")}

    os.makedirs(out_dir, exist_ok=True)
    written = []
    for row in db.execute(
            "SELECT idx, root, audit_seed_root, beacon_commitment, beacon_reveal, beacon_source, "
            "audit_inputs FROM epochs WHERE audit_complete=1 ORDER BY idx"):
        idx, root, seed_root, commitment, reveal, source, inputs = row
        inputs = json.loads(inputs or "{}")
        ranges = {}
        for pk, lo, hi, n in db.execute(
                "SELECT pubkey, MIN(t), MAX(t), COUNT(*) FROM dps WHERE epoch=? GROUP BY pubkey", (idx,)):
            ranges[pk] = {"t_lo": lo, "t_hi": hi, "submitted": n}

        # The rule ranks each identity's candidates by a hash of the seed, the
        # beacon, the pass and the identifier, then replays a fraction of them.
        # Re-deriving that needs the candidate list the pass actually ranked over.
        # The coordinator records it when the pass runs; it cannot be recovered
        # from the database afterwards, because the checked flags have moved on.
        passes = {}
        for tag, block in inputs.items():
            passes[tag] = {
                "rate": block.get("rate"),
                "selection": block.get("selection"),
                "pressure_identities": block.get("pressure_identities", []),
                "pressure_rate": block.get("pressure_rate"),
                "candidates": [[i2, t] for i2, t in db.execute(
                    "SELECT miner_idx, t FROM audit_candidates WHERE epoch_idx=? AND tag=? ORDER BY ordinal",
                    (idx, tag))],
                "selected": block.get("pairs", []),
                "failed": block.get("failed", 0),
            }

        doc = {
            "round_id": rid, "epoch": idx, "root": "0x" + root,
            "audit_seed_root": "0x" + (seed_root or ""),
            "beacon": {"source": source, "commitment": commitment, "reveal": reveal},
            "index_to_pubkey": {str(k): v for k, v in sorted(idx_to_pk.items())},
            "contributors": [{"pubkey": pk, **rng} for pk, rng in sorted(ranges.items())],
            "audit": passes,
        }
        path = os.path.join(out_dir, f"{rid}-{idx:05d}.json")
        with open(path, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
        written.append(path)
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", default="public/epochs")
    ap.add_argument("--round-id", default=None)
    a = ap.parse_args(argv)
    for p in publish(a.db, a.out, a.round_id):
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
