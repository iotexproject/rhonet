"""Elliptic-curve arithmetic, r-adding walks, distinguished points, PRF-derived
starts, curve-native tickets and collision solving.

Everything here is deterministic from the round spec so any party (miner,
coordinator, auditor) can recompute any walk from (round_id, pubkey, t).
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
from dataclasses import dataclass

INF = None  # point at infinity
MAX_REPLAY_STEPS_LOG2_OVER_W = 3


def MAX_REPLAY_STEPS(spec):
    # Bounded-cost approximation; true 2^v replay from client-held checkpoints
    # is NOT implemented. We still replay from the PRF start.
    return min(1 << spec.max_walk_len_log2, 1 << (spec.w + MAX_REPLAY_STEPS_LOG2_OVER_W))


def TICKET_VERIFY_CAP(spec):
    return 4 << spec.ticket_d


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


def H(*parts: object) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, bytes):
            b = p
        else:
            b = str(p).encode()
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return h.digest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int
    n: int  # prime order of G
    gx: int
    gy: int

    @property
    def G(self):
        return (self.gx, self.gy)

    def on_curve(self, P) -> bool:
        if P is INF:
            return True
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def neg(self, P):
        if P is INF:
            return INF
        return (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        if P is INF:
            return Q
        if Q is INF:
            return P
        p = self.p
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return INF
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def mul(self, k: int, P):
        return self.mul_unreduced(k % self.n, P)

    def mul_unreduced(self, k: int, P):
        """Multiply without assuming the point has order n (for validation)."""
        if k < 0:
            return self.mul_unreduced(-k, self.neg(P))
        R = INF
        A = P
        while k:
            if k & 1:
                R = self.add(R, A)
            A = self.add(A, A)
            k >>= 1
        return R

    def to_dict(self):
        return {"p": self.p, "a": self.a, "b": self.b, "n": self.n, "gx": self.gx, "gy": self.gy}

    @staticmethod
    def from_dict(d):
        return Curve(int(d["p"]), int(d["a"]), int(d["b"]), int(d["n"]), int(d["gx"]), int(d["gy"]))


@dataclass
class RoundSpec:
    """Static description of one round. Published once, never mutated."""

    round_id: str
    curve: Curve
    qx: int
    qy: int
    bits: int
    w: int  # distinguished point: x mod 2^w == 0
    r: int  # adding-walk table size (power of two)
    ticket_d: int  # ticket difficulty: x mod 2^d == 0 (d > w)
    credit_unit_log2: int  # 1 credit == 2^credit_unit_log2 verified steps
    spot_check_rate: int  # replay 1 in N submitted DPs
    epoch_seconds: int
    quota_dps_per_epoch_base: int
    prize_pool_usdc: float
    max_walk_len_log2: int

    @property
    def Q(self):
        return (self.qx, self.qy)

    @property
    def expected_steps(self) -> float:
        # plain rho with r-adding walks, no negation map: ~1.25 * sqrt(n)
        return 1.25 * (self.curve.n ** 0.5)

    def validate(self, deep: bool = True):
        """Reject invalid round parameters; deep=False skips only scalar products."""
        if self.w < 1:
            raise ValueError("w must be >= 1")
        if self.r < 2 or self.r & (self.r - 1):
            raise ValueError("r must be >= 2 and a power of two")
        if self.w + self.r.bit_length() - 1 > self.bits:
            raise ValueError("w + log2(r) must be <= bits")
        if self.ticket_d <= self.w:
            raise ValueError("ticket_d must be > w (Sybil invariant)")
        if not self.w + 1 <= self.max_walk_len_log2 <= self.w + 6:
            raise ValueError("max_walk_len_log2 must satisfy w + 1 <= max_walk_len_log2 <= w + 6; "
                             "a larger value would let a submitter drive verifier cost")
        for field, minimum in (("spot_check_rate", 1), ("credit_unit_log2", 0),
                               ("epoch_seconds", 1), ("quota_dps_per_epoch_base", 1)):
            if getattr(self, field) < minimum:
                raise ValueError(f"{field} must be >= {minimum}")
        c = self.curve
        if not is_probable_prime(c.p):
            raise ValueError("curve p must be prime")
        if not is_probable_prime(c.n):
            raise ValueError("curve n must be prime")
        if (4 * c.a**3 + 27 * c.b**2) % c.p == 0:
            raise ValueError("curve must be nonsingular: 4a^3 + 27b^2 != 0 mod p")
        if c.G is INF:
            raise ValueError("G must not be INF")
        if not c.on_curve(c.G):
            raise ValueError("G must be on the curve")
        # Exact integer bound avoids floating-point rounding at Hasse endpoints.
        if abs(c.n - (c.p + 1)) > math.isqrt(4 * c.p):
            raise ValueError("curve n must be inside the Hasse interval")
        if not c.on_curve(self.Q):
            raise ValueError("Q must be on the curve")
        if deep:
            if c.mul_unreduced(c.n, c.G) is not INF:
                raise ValueError("G must have order exactly n: n*G != INF")
            if c.mul_unreduced(c.n, self.Q) is not INF:
                raise ValueError("Q must be in <P>: n*Q != INF")
        if c.n == c.p:
            raise ValueError("anomalous curve: n == p (Smart's attack)")
        for d in range(1, 21):
            if pow(c.p, d, c.n) == 1:
                raise ValueError(f"small embedding degree: n divides p^{d} - 1 (d={d} <= 20)")

    def to_dict(self):
        d = self.__dict__.copy()
        d["curve"] = self.curve.to_dict()
        d["expected_steps"] = self.expected_steps
        return d

    @staticmethod
    def from_dict(d):
        spec = RoundSpec(
            round_id=d["round_id"],
            curve=Curve.from_dict(d["curve"]),
            qx=int(d["qx"]),
            qy=int(d["qy"]),
            bits=int(d["bits"]),
            w=int(d["w"]),
            r=int(d["r"]),
            ticket_d=int(d["ticket_d"]),
            credit_unit_log2=int(d["credit_unit_log2"]),
            spot_check_rate=int(d["spot_check_rate"]),
            epoch_seconds=int(d["epoch_seconds"]),
            quota_dps_per_epoch_base=int(d["quota_dps_per_epoch_base"]),
            prize_pool_usdc=float(d["prize_pool_usdc"]),
            max_walk_len_log2=int(d["max_walk_len_log2"]),
        )

        spec.validate()
        return spec

    @staticmethod
    def load(path: str) -> "RoundSpec":
        with open(path) as f:
            return RoundSpec.from_dict(json.load(f))


# ---------------------------------------------------------------- walks


def walk_table(spec: RoundSpec):
    """R_j = c_j*G + d_j*Q for j in [0, r). Deterministic from round_id."""
    c = spec.curve
    table = []
    for j in range(spec.r):
        cj = int.from_bytes(H(spec.round_id, "table-c", j), "big") % c.n
        dj = int.from_bytes(H(spec.round_id, "table-d", j), "big") % c.n
        if cj == 0:
            cj = 1
        if dj == 0:
            dj = 1
        R = c.add(c.mul(cj, c.G), c.mul(dj, spec.Q))
        table.append((R[0], R[1], cj, dj))
    return table


def derive_start(spec: RoundSpec, pubkey_hex: str, t: int, tag: str = "walk"):
    """(a0, b0, P0) = PRF(round_id, pubkey, t). Nobody has to issue seeds."""
    n = spec.curve.n
    a0 = int.from_bytes(H(spec.round_id, tag, pubkey_hex, t, "a"), "big") % n
    b0 = int.from_bytes(H(spec.round_id, tag, pubkey_hex, t, "b"), "big") % n
    if b0 == 0:
        b0 = 1
    c = spec.curve
    P0 = c.add(c.mul(a0, c.G), c.mul(b0, spec.Q))
    return a0, b0, P0


def is_dp(x: int, w: int) -> bool:
    return x & ((1 << w) - 1) == 0


def branch_index(x: int, r: int, w: int) -> int:
    """Branch bits must be disjoint from the DP predicate bits (H-1)."""
    return (x >> w) & (r - 1)


def replay(spec: RoundSpec, table, a: int, b: int, P, steps: int):
    """Walk `steps` steps from (a, b, P) with the round's adding walk.
    Returns (a, b, P) or None if the walk degenerates."""
    c = spec.curve
    n = c.n
    for _ in range(steps):
        if P is INF:
            return None
        j = branch_index(P[0], spec.r, spec.w)
        Rx, Ry, cj, dj = table[j]
        P = c.add(P, (Rx, Ry))
        a = (a + cj) % n
        b = (b + dj) % n
    return a, b, P


def walk_to_dp(spec: RoundSpec, table, a, b, P, dp_bits: int, max_steps: int):
    """Single (slow, reference) walk until a point with dp_bits trailing zero
    bits in x. Returns (a, b, P, steps) or None."""
    c = spec.curve
    dpmask = (1 << dp_bits) - 1
    n = c.n
    steps = 0
    while steps < max_steps:
        if P is INF:
            return None
        if P[0] & dpmask == 0 and steps > 0:
            return a, b, P, steps
        j = branch_index(P[0], spec.r, spec.w)
        Rx, Ry, cj, dj = table[j]
        P = c.add(P, (Rx, Ry))
        a = (a + cj) % n
        b = (b + dj) % n
        steps += 1
    return None


# ---------------------------------------------------------------- tickets


def ticket_solve(spec: RoundSpec, table, pubkey_hex: str, start_nonce: int = 0, max_nonces: int = 1 << 20):
    """Curve-native proof of work: from a PRF start, walk until x has
    ticket_d trailing zero bits. Same kernel as mining, so no ASIC/botnet
    advantage relative to real miners. Returns dict or None."""
    limit = TICKET_VERIFY_CAP(spec)
    for nonce in range(start_nonce, start_nonce + max_nonces):
        a0, b0, P0 = derive_start(spec, pubkey_hex, nonce, tag="ticket")
        res = walk_to_dp(spec, table, a0, b0, P0, spec.ticket_d, limit)
        if res is not None:
            a, b, P, steps = res
            return {"nonce": nonce, "steps": steps, "x": P[0]}
    return None


def ticket_verify(spec: RoundSpec, table, pubkey_hex: str, ticket: dict) -> bool:
    nonce, steps, x = int(ticket["nonce"]), int(ticket["steps"]), int(ticket["x"])
    if not is_dp(x, spec.ticket_d):
        return False
    a0, b0, P0 = derive_start(spec, pubkey_hex, nonce, tag="ticket")
    res = walk_to_dp(spec, table, a0, b0, P0, spec.ticket_d, TICKET_VERIFY_CAP(spec))
    # Submitted steps is advisory: compare only after independently recomputing.
    return res is not None and res[2][0] == x and res[3] == steps


# ---------------------------------------------------------------- DPs


def dp_verify(spec: RoundSpec, table, pubkey_hex: str, dp: dict) -> bool:
    """Full replay of one walk segment: start from PRF(round, pubkey, t),
    take `steps` steps, must land exactly on (x, y) with coefficients (a, b)."""
    steps = int(dp["steps"])
    if steps <= 0 or steps > MAX_REPLAY_STEPS(spec):
        return False
    a0, b0, P0 = derive_start(spec, pubkey_hex, int(dp["t"]))
    res = replay(spec, table, a0, b0, P0, steps)
    if res is None or res[2] is INF:
        return False
    a, b, P = res
    return a == int(dp["a"]) and b == int(dp["b"]) and P[0] == int(dp["x"]) and P[1] == int(dp["y"])


def solve_collision_detail(spec: RoundSpec, d1: dict, d2: dict) -> dict:
    """Two walks landed on the same x. P = a*G + b*Q = (a + b*k)*G.
    Same point:  a1 + b1 k = a2 + b2 k   -> k = (a1 - a2) / (b2 - b1)
    Negatives:   a1 + b1 k = -(a2 + b2 k) -> k = -(a1 + a2) / (b1 + b2)
    Distinguishes zero denominators from a derived key that fails verification."""
    c = spec.curve
    n = c.n
    a1, b1, y1 = int(d1["a"]), int(d1["b"]), int(d1["y"])
    a2, b2, y2 = int(d2["a"]), int(d2["b"]), int(d2["y"])
    if y1 == y2:
        den = (b2 - b1) % n
        if den == 0:
            return {"kind": "degenerate_same_y"}
        k = (a1 - a2) * pow(den, -1, n) % n
    else:
        den = (b1 + b2) % n
        if den == 0:
            return {"kind": "degenerate_opposite_y"}
        k = (-(a1 + a2)) * pow(den, -1, n) % n
    if c.mul(k, c.G) == spec.Q:
        return {"kind": "solved", "k": k}
    return {"kind": "bad_k", "k": k}


def solve_collision(spec: RoundSpec, d1: dict, d2: dict):
    """Compatibility wrapper returning the verified key, or None."""
    result = solve_collision_detail(spec, d1, d2)
    return result["k"] if result["kind"] == "solved" else None


# ---------------------------------------------------------------- batched walks (miner kernel)


class BatchWalker:
    """Runs B independent walks in lock-step with one modular inversion per
    step (Montgomery's trick). This is the shape of a real GPU kernel; the
    Python version exists so the protocol can be exercised end to end."""

    def __init__(self, spec: RoundSpec, table, pubkey_hex: str, batch: int, rng_t):
        self.spec = spec
        self.c = spec.curve
        self.p = spec.curve.p
        self.n = spec.curve.n
        self.table = table
        self.pubkey = pubkey_hex
        self.dpmask = (1 << spec.w) - 1
        self.max_len = MAX_REPLAY_STEPS(spec)
        self.rng_t = rng_t
        self.walks = [self._fresh() for _ in range(batch)]
        self.steps_done = 0
        self.abandoned = 0

    def _fresh(self):
        t = self.rng_t()
        a, b, P = derive_start(self.spec, self.pubkey, t)
        return [P[0], P[1], a, b, t, 0]  # x, y, a, b, t, steps

    def step(self):
        """One step for every walk. Returns list of DP dicts found."""
        p = self.p
        table = self.table
        walks = self.walks
        B = len(walks)
        dens = [0] * B
        js = [0] * B
        for i in range(B):
            wlk = walks[i]
            j = branch_index(wlk[0], self.spec.r, self.spec.w)
            js[i] = j
            d = (table[j][0] - wlk[0]) % p
            dens[i] = d if d else 1  # degenerate walk gets replaced below
        # batch inversion
        pref = [0] * B
        acc = 1
        for i in range(B):
            acc = acc * dens[i] % p
            pref[i] = acc
        inv = pow(acc, -1, p)
        found = []
        n = self.n
        dpmask = self.dpmask
        for i in range(B - 1, -1, -1):
            if i:
                di = inv * pref[i - 1] % p
                inv = inv * dens[i] % p
            else:
                di = inv
            wlk = walks[i]
            Rx, Ry, cj, dj = table[js[i]]
            x1, y1 = wlk[0], wlk[1]
            if Rx == x1:
                self.abandoned += 1
                walks[i] = self._fresh()
                continue
            lam = (Ry - y1) * di % p
            x3 = (lam * lam - x1 - Rx) % p
            y3 = (lam * (x1 - x3) - y1) % p
            wlk[0] = x3
            wlk[1] = y3
            wlk[2] = (wlk[2] + cj) % n
            wlk[3] = (wlk[3] + dj) % n
            wlk[5] += 1
            if x3 & dpmask == 0:
                found.append({"x": x3, "y": y3, "a": wlk[2], "b": wlk[3], "t": wlk[4], "steps": wlk[5]})
                walks[i] = self._fresh()
            elif wlk[5] >= self.max_len:
                self.abandoned += 1
                walks[i] = self._fresh()
        self.steps_done += B
        return found
