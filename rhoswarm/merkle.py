"""SHA-256 Merkle tree over (payout_address, credited_steps) leaves.
Mirrors contracts/src/PrizeVault.sol byte for byte: leaf = sha256(addr20 || uint256 steps),
node = sha256(min(l,r) || max(l,r)) (sorted pairs, so proofs carry no side bits)."""
from __future__ import annotations

import hashlib


def leaf_hash(addr: str, steps: int) -> bytes:
    a = bytes.fromhex(addr[2:] if addr.startswith("0x") else addr)
    assert len(a) == 20, "payout address must be 20 bytes"
    return hashlib.sha256(a + steps.to_bytes(32, "big")).digest()


def node_hash(l: bytes, r: bytes) -> bytes:
    if r < l:
        l, r = r, l
    return hashlib.sha256(l + r).digest()


def build(leaves: list[bytes]):
    """Returns (root, layers). Odd nodes are promoted, not duplicated."""
    if not leaves:
        return b"\x00" * 32, [[]]
    layers = [list(leaves)]
    while len(layers[-1]) > 1:
        cur = layers[-1]
        nxt = [node_hash(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i] for i in range(0, len(cur), 2)]
        layers.append(nxt)
    return layers[-1][0], layers


def proof(layers, index: int) -> list[bytes]:
    out = []
    for layer in layers[:-1]:
        sib = index ^ 1
        if sib < len(layer):
            out.append(layer[sib])
        index //= 2
    return out


def verify(root: bytes, leaf: bytes, pf: list[bytes]) -> bool:
    h = leaf
    for s in pf:
        h = node_hash(h, s)
    return h == root
