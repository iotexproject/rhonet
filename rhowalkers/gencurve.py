"""Generate a prime-order curve of a given bit size plus a random ECDLP
instance Q = k*G. The secret k is written to a separate file so the demo
can be checked; a real round never has this file.

Point counting uses baby-step giant-step on the Hasse interval, which is
plenty for the <= 64-bit toy curves the MVP runs on."""
from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import sys
import time

from .ec import INF, Curve


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


def sqrt_mod(a: int, p: int):
    """Tonelli-Shanks."""
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def random_point(p: int, a: int, b: int):
    while True:
        x = secrets.randbelow(p)
        rhs = (x * x * x + a * x + b) % p
        y = sqrt_mod(rhs, p)
        if y is not None:
            return (x, y)


def point_order_candidates(p: int, a: int, b: int, P):
    """All m in the Hasse interval with m*P = O (BSGS)."""
    c = Curve(p, a, b, 1, P[0], P[1])  # n unused for add
    # temporarily bypass mul's `k %= n` by using our own ladder
    def mul(k, R):
        out, A = INF, R
        while k:
            if k & 1:
                out = c.add(out, A)
            A = c.add(A, A)
            k >>= 1
        return out

    lo = p + 1 - 2 * math.isqrt(p) - 2
    width = 4 * math.isqrt(p) + 5
    m = math.isqrt(width) + 1
    baby = {}
    R = INF
    for i in range(m):
        baby.setdefault(R, i)
        R = c.add(R, P)
    mP = R  # m*P
    neg_mP = c.neg(mP)
    cands = []
    cur = mul(lo, P)  # lo*P ; want lo + i + t*m with (lo + t*m)*P = -i*P  -> i*P = -(cur)
    for t in range(m + 1):
        key = c.neg(cur)
        if key in baby:
            i = baby[key]
            cands.append(lo + t * m + i)
        cur = c.add(cur, mP)
    return sorted(set(cands))


def gen(bits: int):
    while True:
        p = random_prime(bits)
        a = secrets.randbelow(p)
        b = secrets.randbelow(p)
        if (4 * a * a * a + 27 * b * b) % p == 0:
            continue
        P = random_point(p, a, b)
        cands = point_order_candidates(p, a, b, P)
        if len(cands) != 1:
            continue
        n = cands[0]
        if not is_probable_prime(n):
            continue
        c = Curve(p, a, b, n, P[0], P[1])
        # sanity: another random point also has order n
        P2 = random_point(p, a, b)
        if c.mul(n, P2) is not INF or c.mul(n, P) is not INF:
            continue
        return c


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=44)
    ap.add_argument("--round-id", default=None)
    ap.add_argument("--w", type=int, default=None, help="DP bits (default: bits//4)")
    ap.add_argument("--r", type=int, default=32)
    ap.add_argument("--ticket-d", type=int, default=None, help="ticket difficulty bits (default: w+4)")
    ap.add_argument("--credit-unit-log2", type=int, default=20)
    ap.add_argument("--spot-check-rate", type=int, default=64)
    ap.add_argument("--epoch-seconds", type=int, default=20)
    ap.add_argument("--quota", type=int, default=1 << 16)
    ap.add_argument("--prize", type=float, default=10000.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    t0 = time.time()
    c = gen(args.bits)
    k = secrets.randbelow(c.n - 1) + 1
    Q = c.mul(k, c.G)
    w = args.w if args.w is not None else max(6, args.bits // 4)
    d = args.ticket_d if args.ticket_d is not None else w + 4
    rid = args.round_id or f"ecc-p{args.bits}-{secrets.token_hex(3)}"
    spec = {
        "round_id": rid,
        "curve": c.to_dict(),
        "qx": Q[0],
        "qy": Q[1],
        "bits": args.bits,
        "w": w,
        "r": args.r,
        "ticket_d": d,
        "credit_unit_log2": args.credit_unit_log2,
        "spot_check_rate": args.spot_check_rate,
        "epoch_seconds": args.epoch_seconds,
        "quota_dps_per_epoch_base": args.quota,
        "prize_pool_usdc": args.prize,
        "max_walk_len_log2": w + 5,
        "expected_steps": 1.25 * c.n ** 0.5,
        "created_at": int(time.time()),
    }
    with open(args.out, "w") as f:
        json.dump(spec, f, indent=2)
    secret_path = args.out.replace(".json", "") + ".secret.json"
    with open(secret_path, "w") as f:
        json.dump({"round_id": rid, "k": k}, f, indent=2)
    print(f"round {rid}: {args.bits}-bit curve, n={c.n}, w={w}, ticket_d={d}", file=sys.stderr)
    print(f"expected steps ~ {spec['expected_steps']:.3e}; wrote {args.out} (+ secret {secret_path}) in {time.time()-t0:.1f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
