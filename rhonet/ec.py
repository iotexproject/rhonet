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
    # Full replay cap, used only for collision correctness and miner walk length.
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
    """Deterministic JSON. Retained for internal digests only, never for signatures.

    Canonical JSON is a well-known source of cross-language signature failures:
    integer versus string encoding of large values, unicode escaping, key ordering
    over non-ASCII keys, and float formatting all differ between implementations.
    Anything a second implementation has to reproduce byte for byte uses `encode`
    below instead.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# --- the signed wire encoding -------------------------------------------------
#
# A signed message is a length-prefixed encoding of an explicit, ordered field
# list. There is no key ordering to agree on, no escaping, and no number
# formatting: every value is either a byte string or a non-negative integer, and
# both have exactly one representation. An independent client can reproduce these
# bytes from the specification alone, and the conformance vectors pin them down.
#
#   encode(domain, fields) =
#       "rhonet-v1\0" || uvarint(len(domain)) || domain
#                      || uvarint(len(fields))
#                      || for each field: tag || uvarint(len(value)) || value
#
#   tag 0x00  bytes, verbatim
#   tag 0x01  unsigned integer, minimal big-endian, empty for zero
#   tag 0x02  UTF-8 text
#   tag 0x03  a nested list, whose items are encoded by the same rules
#
# Field ORDER is part of the specification for each message type; a field is never
# identified by name on the wire, so a client cannot accidentally agree on the
# names while disagreeing on the bytes.

WIRE_MAGIC = b"rhonet-v1\0"


def uvarint(n: int) -> bytes:
    if n < 0:
        raise ValueError("uvarint is unsigned")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def uint_bytes(n: int) -> bytes:
    """Minimal big-endian. Zero encodes as empty, so there is one representation."""
    if n < 0:
        raise ValueError("field integers are unsigned")
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _field(value) -> bytes:
    if isinstance(value, bytes):
        return b"\x00" + uvarint(len(value)) + value
    if isinstance(value, bool):
        raise TypeError("encode booleans as integers, so the intent is explicit")
    if isinstance(value, int):
        b = uint_bytes(value)
        return b"\x01" + uvarint(len(b)) + b
    if isinstance(value, str):
        b = value.encode("utf-8")
        return b"\x02" + uvarint(len(b)) + b
    if isinstance(value, (list, tuple)):
        inner = b"".join(_field(v) for v in value)
        return b"\x03" + uvarint(len(inner)) + inner
    raise TypeError(f"no wire encoding for {type(value).__name__}")


def encode(domain: str, fields) -> bytes:
    """The exact bytes that get signed. See the field order for each message type
    in docs/PROTOCOL.md; the conformance vectors in spec/vectors.json pin them."""
    d = domain.encode("utf-8")
    body = b"".join(_field(v) for v in fields)
    return WIRE_MAGIC + uvarint(len(d)) + d + uvarint(len(fields)) + body


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
    v: int = 2
    audit_response_seconds: float = 10.0
    silence_epochs: int = 3
    settlement_sweep_seconds: float = 0.1
    funded: bool = False

    @property
    def segments_per_walk(self):
        return max(1, MAX_REPLAY_STEPS(self) // (1 << self.v))

    @property
    def detection(self):
        """What the audit actually guarantees, stated so it cannot be misread.

        Two different forgeries cost a cheat two different things.

        A point whose coefficients do not satisfy a*G + b*Q = (x, y) is the cheap
        forgery, and it is what a fabricating walker produces. Every segment
        challenge re-checks that relation, so any challenge at all catches it: the
        only escape is not being sampled, probability 1 - 1/N per point.

        A point that satisfies the relation but whose committed checkpoint chain
        does not actually connect is far more expensive to build, and it escapes a
        challenge unless the one segment we open is the broken one. Its per-point
        escape probability is 1 - 1/(N*S) with S segments per walk. This is the
        weaker of the two and is the number to quote.

        Both assume the audit seed is unpredictable when the batch is sealed. With
        a leaked seed and adaptively chosen submissions the bound is 1, which is
        why a funded round requires an external beacon.
        """
        n, seg = self.spot_check_rate, self.segments_per_walk
        return {
            "sampling_rate": f"1 in {n}",
            "segments_per_walk": seg,
            "escape_per_inconsistent_point": 1.0 - 1.0 / n,
            "escape_per_broken_chain_point": 1.0 - 1.0 / (n * seg),
            "note": ("Per point. An identity forging f points escapes with the f-th power, "
                     "so forging at scale is caught quickly; forging once is cheap to hide. "
                     "Assumes an unpredictable audit seed."),
        }

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
        if type(self.v) is not int or not 1 <= self.v <= self.w:
            raise ValueError("v must satisfy 1 <= v <= w")
        if (not math.isfinite(self.audit_response_seconds) or not math.isfinite(self.settlement_sweep_seconds)
                or self.audit_response_seconds <= 0 or self.silence_epochs < 1 or self.settlement_sweep_seconds < 0):
            raise ValueError("invalid audit maturity parameters")
        if type(self.funded) is not bool:
            raise ValueError("funded must be boolean")
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
        d["detection"] = self.detection
        return d

    @staticmethod
    def from_dict(d):
        spec = RoundSpec(
            v=int(d.get("v", min(12, max(1, int(d["w"]) - 6)))),
            audit_response_seconds=float(d.get("audit_response_seconds", 10)),
            silence_epochs=int(d.get("silence_epochs", 3)),
            settlement_sweep_seconds=float(d.get("settlement_sweep_seconds", .1)),
            funded=d.get("funded", False),
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
        counter = 0
        while True:
            # Preserve existing finite entries byte-for-byte. Only cancellation
            # extends the PRF domain with a deterministic retry counter.
            suffix = () if counter == 0 else (counter,)
            cj = int.from_bytes(H(spec.round_id, "table-c", j, *suffix), "big") % c.n or 1
            dj = int.from_bytes(H(spec.round_id, "table-d", j, *suffix), "big") % c.n or 1
            R = c.add(c.mul(cj, c.G), c.mul(dj, spec.Q))
            if R is not INF:
                break
            counter += 1
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
    """Full replay of one walk (collision fallback only): start from PRF(round, pubkey, t),
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


def audit_fraud_bound(k, forged, audited, max_segments=1):
    """Probability all challenges miss, with uniform unpredictable sampling.

    Let J be the count of forged points among m=ceil(k/N) sampled points.
    Pr[J=j] = C(f,j) C(k-f,m-j) / C(k,m). A forged walk with at least
    one bad segment among at most S segments passes with probability <=1-1/S.
    Thus epsilon <= sum_j Pr[J=j]*(1-1/S)**j, and P(caught)>=1-epsilon.
    With S=1 this reduces to C(k-f,m)/C(k,m) <= (1-phi)**m, phi=f/k.
    With known entropy and adaptive submissions the general bound is 1.
    """
    if not 0 <= forged <= k or not 0 <= audited <= k or max_segments < 1:
        raise ValueError("invalid fraud-bound population")
    def logchoose(n, r):
        if not 0 <= r <= n:
            return float('-inf')
        return math.lgamma(n+1)-math.lgamma(r+1)-math.lgamma(n-r+1)
    denom = logchoose(k, audited)
    if max_segments == 1:
        return min(1.0, math.exp(logchoose(k-forged, audited)-denom))
    logpass = math.log1p(-1/max_segments)
    return min(1.0, sum(math.exp(logchoose(forged,j)+logchoose(k-forged,audited-j)-denom+j*logpass)
                        for j in range(max(0,audited-k+forged), min(forged,audited)+1)))


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
        self.checkpoints = {}
        self.walks = [self._fresh() for _ in range(batch)]
        self.steps_done = 0
        self.abandoned = 0

    def _fresh(self):
        while True:
            t = self.rng_t()
            a, b, P = derive_start(self.spec, self.pubkey, t)
            # Coefficients can cancel even when both are nonzero. Skip this
            # identifier; replay retains the same public PRF start semantics.
            if P is not INF:
                self.checkpoints[t] = [[a, b, P[0], P[1]]]
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
                self.checkpoints.pop(wlk[4], None)
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
            if wlk[5] % (1 << self.spec.v) == 0 or x3 & dpmask == 0:
                self.checkpoints[wlk[4]].append([wlk[2], wlk[3], x3, y3])
            if x3 & dpmask == 0:
                found.append({"x": x3, "y": y3, "a": wlk[2], "b": wlk[3], "t": wlk[4], "steps": wlk[5],
                              "checkpoint_root": checkpoint_root(self.checkpoints[wlk[4]])})
                walks[i] = self._fresh()
            elif wlk[5] >= self.max_len:
                self.abandoned += 1
                self.checkpoints.pop(wlk[4], None)
                walks[i] = self._fresh()
        self.steps_done += B
        return found


    def open_segment(self, t, segment):
        return checkpoint_opening(self.checkpoints[t], segment)


def checkpoint_layers(points):
    layer = [H("checkpoint-leaf-v1", i, canonical(point)) for i, point in enumerate(points)]
    layers = [layer]
    while len(layer) > 1:
        layer = [H("checkpoint-node-v1", layer[i], layer[min(i + 1, len(layer)-1)])
                 for i in range(0, len(layer), 2)]
        layers.append(layer)
    return layers


def checkpoint_root(points):
    return checkpoint_layers(points)[-1][0].hex()


def checkpoint_opening(points, segment):
    layers = checkpoint_layers(points)
    def opening(index):
        proof, pos = [], index
        for layer in layers[:-1]:
            proof.append(layer[min(pos ^ 1, len(layer)-1)].hex())
            pos //= 2
        return {"point": points[index], "proof": proof}
    return {"start": opening(segment), "end": opening(segment+1)}


def checkpoint_verify(root, count, index, opening):
    if not 0 <= index < count:
        return False
    point, proof = opening["point"], opening["proof"]
    if len(point) != 4 or any(type(x) is not int for x in point):
        return False
    if len(proof) != (count-1).bit_length():
        return False
    node = H("checkpoint-leaf-v1", index, canonical(point))
    for sibling in proof:
        sibling = bytes.fromhex(sibling)
        if len(sibling) != 32:
            return False
        node = H("checkpoint-node-v1", sibling, node) if index & 1 else H("checkpoint-node-v1", node, sibling)
        index //= 2
    return node.hex() == root


def verify_segment(spec, table, pubkey, dp, segment, opening):
    """Pure process-worker entry point. Return validity and actual replay work."""
    work = 0
    try:
        length = 1 << spec.v
        segments = (dp["steps"] + length - 1) // length
        if not 0 <= segment < segments:
            return False, work
        c = spec.curve
        states = []
        for index, name in ((segment, "start"), (segment+1, "end")):
            item = opening[name]
            if not checkpoint_verify(dp["checkpoint_root"], segments+1, index, item):
                return False, work
            a, b, x, y = item["point"]
            if not (0 <= a < c.n and 0 <= b < c.n and 0 <= x < c.p and 0 <= y < c.p):
                return False, work
            if not c.on_curve((x, y)) or c.add(c.mul(a, c.G), c.mul(b, spec.Q)) != (x, y):
                return False, work
            states.append((a, b, (x, y)))
        if segment == 0 and states[0] != derive_start(spec, pubkey, dp["t"]):
            return False, work
        # Bind the submitted coefficients on every challenge. A valid segment
        # cannot launder fabricated collision coefficients at the endpoint.
        if c.add(c.mul(dp["a"], c.G), c.mul(dp["b"], spec.Q)) != (dp["x"], dp["y"]):
            return False, work
        if segment == segments-1 and states[1] != (dp["a"], dp["b"], (dp["x"], dp["y"])):
            return False, work
        work = min(length, dp["steps"] - segment*length)
        return replay(spec, table, *states[0], work) == states[1], work
    except (KeyError, ValueError, TypeError, IndexError, OverflowError):
        return False, work


# --- signed message types -----------------------------------------------------
#
# Each entry fixes a domain string and the exact order of the signed fields.
# Adding a field means a new domain, never a silent change of meaning.

def sign_bytes_admission(round_id: str, pubkey: bytes, payout: bytes, ticket_nonce: int,
                         ticket_steps: int, ticket_x: int, epoch: int, seq: int,
                         device: str) -> bytes:
    return encode("rhonet/admission-v1",
                  [round_id, pubkey, payout, ticket_nonce, ticket_steps, ticket_x,
                   epoch, seq, device])


def sign_bytes_submission(round_id: str, pubkey: bytes, epoch: int, seq: int,
                          steps_done: int, abandoned: int, dps) -> bytes:
    """`dps` is an ordered list; each point contributes its fields in this order,
    so two clients that agree on the points cannot disagree on the bytes."""
    items = [[_u(d.get("t")), _u(d.get("steps")), _u(d.get("x")), _u(d.get("y")),
              _u(d.get("a")), _u(d.get("b")),
              bytes.fromhex(str(d.get("checkpoint_root") or ""))]
             for d in dps]
    return encode("rhonet/submission-v1",
                  [round_id, pubkey, epoch, seq, steps_done, abandoned, items])


def sign_bytes_opening(round_id: str, pubkey: bytes, audit_epoch: int, t: int,
                       segment: int, opening_digest: bytes) -> bytes:
    return encode("rhonet/opening-v1",
                  [round_id, pubkey, audit_epoch, t, segment, opening_digest])


def sign_bytes_contributor(github: str, pubkey: bytes, payout: bytes) -> bytes:
    """Binds a GitHub account to a walker key. Signed by the walker key; the pull
    request proves the other half."""
    return encode("rhonet/contributor-v1", [github, pubkey, payout])


def _u(v) -> int:
    """Coerce a wire value to a non-negative integer for encoding purposes only.
    Range and sanity checks belong to the server, not to the signature."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    return n if n >= 0 else 0


def sign_bytes_for(body: dict) -> bytes:
    """Pick the signed encoding from the message's shape.

    Transport stays JSON, which is convenient and lossy; the signature covers the
    binary encoding above, which is neither. A client that agrees with us about the
    values cannot disagree about the signed bytes.
    """
    pubkey = bytes.fromhex(body["pubkey"])
    rid = body["round_id"]
    epoch = _u(body.get("epoch"))
    seq = _u(body.get("seq"))
    if "ticket" in body:
        # A malformed message must still be signable, so that the server rejects it
        # on its own validation rather than the client failing to encode it. Absent
        # fields encode as zero, which is a value the server will refuse anyway.
        t = body["ticket"] if isinstance(body.get("ticket"), dict) else {}
        return sign_bytes_admission(rid, pubkey,
                                    bytes.fromhex(str(body.get("payout_addr", "")).removeprefix("0x")),
                                    _u(t.get("nonce")), _u(t.get("steps")), _u(t.get("x")),
                                    epoch, seq, str(body.get("device") or ""))
    if "dps" in body:
        return sign_bytes_submission(rid, pubkey, epoch, seq,
                                     _u(body.get("steps_done")), _u(body.get("abandoned")),
                                     body["dps"] if isinstance(body.get("dps"), list) else [])
    if "opening" in body:
        return sign_bytes_opening(rid, pubkey, _u(body.get("audit_epoch")), _u(body.get("t")),
                                  _u((body.get("opening") or {}).get("segment")),
                                  H("opening", canonical(body["opening"])))
    if "payout_addr" in body:  # signed address rotation
        return encode("rhonet/rotate-v1",
                      [rid, pubkey, bytes.fromhex(body["payout_addr"].removeprefix("0x")),
                       epoch, seq])
    raise ValueError("unknown signed message type")
