"""Measure the rho constant, by solving many independent instances and counting.

Expected work for an r-adding walk without the negation map is c·√n with c = 1.25.
A single solve says almost nothing -- rho's completion count is Rayleigh with a
standard deviation near half its mean -- so this solves many instances per size and
reports the mean, its 3-sigma interval, and the fitted exponent across sizes.

Every solve is checked against the generator's secret k. An unverified solve is a
bug report, not a data point.

    python -m tools.calibrate --bits 56 --solves 40 --procs 24
    python -m tools.calibrate --bits 28,32,36,40 --solves 300 --procs 24 --out data/calib.json

The measurement is the one thing that would catch a silently broken walk: a bad
branch function, or later a bad negation map, changes the constant and nothing
else. It does not crash and it does not change throughput.
"""
from __future__ import annotations

import argparse
import json
import math
import itertools
import multiprocessing as mp
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rhonet import ec, gencurve


def solve_once(args):
    """One instance: fresh curve, fresh secret, rho to a collision. Returns steps."""
    bits, index, w, r, seed, batch = args
    curve = gencurve.gen(bits)
    k = 1 + (int.from_bytes(ec.H("calibrate", seed, index, "k"), "big") % (curve.n - 1))
    Q = curve.mul(k, curve.G)
    spec = ec.RoundSpec(
        round_id=f"calib-{bits}-{index}", curve=curve, qx=Q[0], qy=Q[1], bits=bits,
        w=w, r=r, ticket_d=w + 1, credit_unit_log2=10, spot_check_rate=1,
        epoch_seconds=60, quota_dps_per_epoch_base=1 << 30, prize_pool_usdc=0.0,
        max_walk_len_log2=min(w + 6, w + 3), v=max(1, min(12, w - 6)))
    table = ec.walk_table(spec)

    # Use the batched kernel, not one replay() call per step: the whole point of
    # this measurement is to run enough instances that the mean is tight, and a
    # five-times-slower stepper buys nothing but wall clock.
    #
    # But B walks in flight cost about B/(2*theta) wasted steps when the collision
    # lands, because every unfinished walk is thrown away. That overhead is additive
    # and vanishes against sqrt(n) as n grows -- at 97 bits with B = 32 it is 0.002%
    # -- while at 28 bits with B = 32 it is a fifth of the whole measurement. Left
    # unaccounted it would make the constant look like 1.58 and the exponent still
    # look like 0.5, which is exactly the kind of wrong number this tool exists to
    # avoid. So cap B at 1% of the expected work for the size actually being run.
    root = math.isqrt(curve.n)
    batch = max(1, min(batch, int(0.0125 * root / (1 << max(0, w - 1)))))
    walker = ec.BatchWalker(spec, table, "00" * 32, batch, itertools.count().__next__)
    seen: dict[int, dict] = {}
    limit = int(40 * root + 1000)
    while walker.steps_done < limit:
        for dp in walker.step():
            # The chain is not needed here and would otherwise accumulate for every
            # walk ever started: tens of thousands of them at the larger sizes.
            walker.checkpoints.pop(dp["t"], None)
            previous = seen.get(dp["x"])
            if previous is None:
                seen[dp["x"]] = dp
                continue
            found = ec.solve_collision(spec, dp, previous)
            if found is None:
                continue  # a walk met itself, or the two coefficients cancel
            if found != k:
                return {"bits": bits, "index": index, "error": "wrong k",
                        "steps": walker.steps_done}
            return {"bits": bits, "index": index, "steps": walker.steps_done,
                    "sqrt_n": root, "batch": batch,
                    "ratio": walker.steps_done / root}
    return {"bits": bits, "index": index, "error": "gave up", "steps": walker.steps_done}


def arm(bits, solves, procs, w, r, seed, batch):
    tasks = [(bits, i, w or max(6, bits // 4), r, seed, batch) for i in range(solves)]
    started = time.time()
    with mp.get_context("fork").Pool(procs) as pool:
        results = pool.map(solve_once, tasks)
    bad = [x for x in results if "error" in x]
    ratios = [x["ratio"] for x in results if "ratio" in x]
    if not ratios:
        raise SystemExit(f"{bits}-bit: no solve completed ({bad[:1]})")
    mean = statistics.fmean(ratios)
    sd = statistics.stdev(ratios) if len(ratios) > 1 else 0.0
    stderr = sd / math.sqrt(len(ratios))
    return {"bits": bits, "solves": len(ratios), "failed": len(bad),
            "batch": max((x.get("batch", 0) for x in results if "ratio" in x), default=0),
            "mean_ratio": mean, "sd_ratio": sd,
            "mean_3sigma": [mean - 3 * stderr, mean + 3 * stderr],
            "p10": sorted(ratios)[max(0, len(ratios) // 10 - 1)],
            "p90": sorted(ratios)[min(len(ratios) - 1, 9 * len(ratios) // 10)],
            "seconds": round(time.time() - started, 1),
            "errors": bad[:3]}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", default="28,32,36,40")
    ap.add_argument("--solves", type=int, default=100)
    ap.add_argument("--procs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--w", type=int, default=None, help="DP width (default bits//4)")
    ap.add_argument("--r", type=int, default=32)
    ap.add_argument("--seed", default="v1")
    ap.add_argument("--batch", type=int, default=32,
                    help="walks in lock-step per instance; amortises the inversion")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    arms = []
    for bits in [int(b) for b in args.bits.split(",")]:
        result = arm(bits, args.solves, args.procs, args.w, args.r, args.seed, args.batch)
        arms.append(result)
        print(f"{bits:3d} bits  n={result['solves']:4d}  mean {result['mean_ratio']:.3f}"
              f"  sd {result['sd_ratio']:.3f}"
              f"  3sigma [{result['mean_3sigma'][0]:.3f}, {result['mean_3sigma'][1]:.3f}]"
              f"  p10-p90 {result['p10']:.2f}-{result['p90']:.2f}  B={result['batch']}"
              f"  {result['seconds']:.0f}s", flush=True)

    if len(arms) > 1:
        # Fit log(steps) against log(sqrt(n)): the exponent should be 1 against
        # sqrt(n), i.e. 0.5 against n. Report it the way the site does.
        xs = [a["bits"] / 2 * math.log(2) for a in arms]
        ys = [math.log(a["mean_ratio"]) + a["bits"] / 2 * math.log(2) for a in arms]
        mx, my = statistics.fmean(xs), statistics.fmean(ys)
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
        ss_res = sum((y - (my + slope * (x - mx))) ** 2 for x, y in zip(xs, ys))
        ss_tot = sum((y - my) ** 2 for y in ys)
        r2 = 1 - ss_res / ss_tot if ss_tot else 1.0
        print(f"fitted exponent {slope / 2:.4f} against n  (R^2 = {r2:.4f})")
        arms.append({"fit": {"exponent_vs_n": slope / 2, "r_squared": r2}})

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(arms, f, indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
