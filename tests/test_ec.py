"""Offline checks of the math: walks replay, tickets verify, collisions solve."""
import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rhowalkers import ec, merkle  # noqa: E402

HERE = os.path.dirname(__file__)


def load(name):
    spec = ec.RoundSpec.load(os.path.join(HERE, "..", "rounds", name + ".json"))
    with open(os.path.join(HERE, "..", "rounds", name + ".secret.json")) as f:
        k = json.load(f)["k"]
    return spec, k


def test_curve_basics():
    spec, k = load("r32")
    c = spec.curve
    assert c.on_curve(c.G) and c.on_curve(spec.Q)
    assert c.mul(c.n, c.G) is ec.INF
    assert c.mul(k, c.G) == spec.Q


def test_batch_walker_matches_replay_and_ticket():
    spec, _ = load("r32")
    table = ec.walk_table(spec)
    pk = "ab" * 32
    bw = ec.BatchWalker(spec, table, pk, batch=32, rng_t=lambda: secrets.randbits(48))
    found = []
    while len(found) < 20:
        found += bw.step()
    for dp in found:
        assert ec.is_dp(dp["x"], spec.w)
        assert ec.dp_verify(spec, table, pk, dp)
    bad = dict(found[0]); bad["a"] = (bad["a"] + 1) % spec.curve.n
    assert not ec.dp_verify(spec, table, pk, bad)
    tk = ec.ticket_solve(spec, table, pk)
    assert tk and ec.ticket_verify(spec, table, pk, tk)
    tk2 = dict(tk); tk2["steps"] += 1
    assert not ec.ticket_verify(spec, table, pk, tk2)


def test_solve_by_collision():
    spec, k = load("r32")
    table = ec.walk_table(spec)
    pk = "cd" * 32
    bw = ec.BatchWalker(spec, table, pk, batch=64, rng_t=lambda: secrets.randbits(48))
    seen = {}
    t0 = time.time()
    while True:
        for dp in bw.step():
            key = dp["x"]
            if key in seen and (seen[key]["a"], seen[key]["b"]) != (dp["a"], dp["b"]):
                kk = ec.solve_collision(spec, seen[key], dp)
                if kk is not None:
                    assert kk == k
                    print(f"solved 32-bit in {bw.steps_done} steps ({bw.steps_done/spec.expected_steps:.2f}x expected), {time.time()-t0:.1f}s")
                    return
            seen.setdefault(key, dp)
        assert bw.steps_done < 40 * spec.expected_steps


def test_merkle():
    leaves = [merkle.leaf_hash("0x" + f"{i:040x}", i * 1000) for i in range(1, 6)]
    root, layers = merkle.build(leaves)
    for i, lf in enumerate(leaves):
        assert merkle.verify(root, lf, merkle.proof(layers, i))
    assert not merkle.verify(root, leaves[0], merkle.proof(layers, 1))


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("ok", name)
