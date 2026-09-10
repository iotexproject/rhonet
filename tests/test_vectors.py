"""The published conformance vectors are the contract with independent clients.

Every value in spec/vectors.json is recomputed here from the reference
implementation. A change to the wire format breaks this test, which is the point:
the format may only move in a commit that also moves the vectors on purpose.
"""
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rhonet import ec, merkle
from tools import gen_vectors


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ROOT / "spec/vectors.json") as f:
            cls.v = json.load(f)
        cls.spec = ec.RoundSpec.load(str(ROOT / gen_vectors.ROUND))
        cls.table = ec.walk_table(cls.spec)
        cls.pubkey = cls.v["identity"]["pubkey"]

    def test_file_matches_generator(self):
        """The committed file is exactly what the generator produces today."""
        self.assertEqual(gen_vectors.main(["--check"]), 0)

    def test_round_is_the_one_the_vectors_name(self):
        with open(ROOT / gen_vectors.ROUND) as f:
            self.assertEqual(json.load(f), self.v["round"])

    def test_primitives(self):
        self.assertEqual(self.v["wire"], ec.WIRE_MAGIC.decode("latin-1"))
        for case in self.v["uvarint"]:
            self.assertEqual(ec.uvarint(case["n"]).hex(), case["hex"], case)
        for case in self.v["uint_bytes"]:
            self.assertEqual(ec.uint_bytes(case["n"]).hex(), case["hex"], case)
        for case in self.v["hash"]:
            self.assertEqual(ec.H(*(self._value(f) for f in case["parts"])).hex(), case["hex"], case)
        for case in self.v["encode"]:
            fields = [self._value(f) for f in case["fields"]]
            self.assertEqual(ec.encode(case["domain"], fields).hex(), case["hex"], case)

    @classmethod
    def _value(cls, field):
        (kind, raw), = field.items()
        return {"uint": int, "text": str, "bytes": bytes.fromhex,
                "list": lambda items: [cls._value(i) for i in items]}[kind](raw)

    def test_walk_table(self):
        table = self.table
        self.assertEqual(len(table), self.v["walk_table"]["r"])
        self.assertEqual([list(e) for e in table[:4]], self.v["walk_table"]["entries_head"])
        self.assertEqual([list(e) for e in table[-2:]], self.v["walk_table"]["entries_tail"])
        digest = ec.H("vectors-table", ec.canonical([list(e) for e in table])).hex()
        self.assertEqual(digest, self.v["walk_table"]["digest"])

    def test_starts_are_prf_derived(self):
        for case in self.v["starts"]:
            a0, b0, P = ec.derive_start(self.spec, self.pubkey, case["t"])
            self.assertEqual([a0, b0, P[0], P[1]],
                             [case["a0"], case["b0"], case["x"], case["y"]], case)
            # Every start is a real representation of a known combination.
            c = self.spec.curve
            self.assertEqual(c.add(c.mul(a0, c.G), c.mul(b0, self.spec.Q)), P)
        case = self.v["ticket_start"]
        a0, b0, P = ec.derive_start(self.spec, self.pubkey, case["nonce"], tag="ticket")
        self.assertEqual([a0, b0, P[0], P[1]], [case["a0"], case["b0"], case["x"], case["y"]])

    def test_step_function_trace(self):
        trace = self.v["trace"]
        state = ec.derive_start(self.spec, self.pubkey, trace["t"])
        a, b, P = state
        self.assertEqual([a, b, P[0], P[1]], trace["states"][0])
        for i in range(trace["steps"]):
            self.assertEqual(ec.branch_index(P[0], self.spec.r, self.spec.w),
                             trace["branch_indices"][i], f"branch at step {i}")
            a, b, P = ec.replay(self.spec, self.table, a, b, P, 1)
            self.assertEqual([a, b, P[0], P[1]], trace["states"][i + 1], f"state after step {i+1}")

    def test_checkpoint_chain_and_root(self):
        chain = [list(c) for c in self.v["checkpoints"]["chain"]]
        self.assertEqual(len(chain), self.v["checkpoints"]["count"])
        self.assertEqual(ec.checkpoint_root(chain), self.v["checkpoints"]["root"])
        self.assertEqual(self.v["dp"]["checkpoint_root"], self.v["checkpoints"]["root"])
        # The chain really is the walk: consecutive checkpoints are one segment apart.
        length = self.v["checkpoints"]["segment_length"]
        steps = self.v["dp"]["steps"]
        for i in range(len(chain) - 1):
            a, b, x, y = chain[i]
            work = min(length, steps - i * length)
            got = ec.replay(self.spec, self.table, a, b, (x, y), work)
            self.assertEqual([got[0], got[1], got[2][0], got[2][1]], chain[i + 1], f"segment {i}")

    def test_openings_verify_and_replay_the_stated_work(self):
        dp = self.v["dp"]
        for case in self.v["openings"]:
            ok, work = ec.verify_segment(self.spec, self.table, self.pubkey, dp,
                                         case["segment"], case["opening"])
            self.assertTrue(ok, case["segment"])
            self.assertEqual(work, case["replayed_steps"])
            self.assertEqual(ec.checkpoint_opening(
                [list(c) for c in self.v["checkpoints"]["chain"]], case["segment"]),
                case["opening"])

    def test_a_tampered_opening_fails(self):
        dp = self.v["dp"]
        case = self.v["openings"][1]
        bad = json.loads(json.dumps(case["opening"]))
        bad["end"]["point"][0] ^= 1
        ok, _ = ec.verify_segment(self.spec, self.table, self.pubkey, dp, case["segment"], bad)
        self.assertFalse(ok)

    def test_ticket_verifies(self):
        self.assertTrue(ec.ticket_verify(self.spec, self.table, self.pubkey, self.v["ticket"]))

    def test_signed_bytes_and_signatures(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.v["identity"]["ed25519_seed"]))
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.pubkey))
        for case in self.v["signed"]:
            if case["name"] == "contributor":
                body = case["body"]
                message = ec.sign_bytes_contributor(
                    body["github"], bytes.fromhex(body["pubkey"]),
                    bytes.fromhex(body["payout"].removeprefix("0x")))
            else:
                message = ec.sign_bytes_for(case["body"])
            self.assertEqual(message.hex(), case["signed_hex"], case["name"])
            self.assertEqual(key.sign(message).hex(), case["sig"], case["name"])
            pub.verify(bytes.fromhex(case["sig"]), message)  # raises on failure

    def test_signed_domains_are_distinct(self):
        """No two message types may share a signed prefix, or one could be replayed
        as another. Each domain string appears in exactly one vector."""
        domains = [bytes.fromhex(c["signed_hex"]) for c in self.v["signed"]]
        prefixes = [d[:40] for d in domains]
        self.assertEqual(len(set(prefixes)), len({c["name"] for c in self.v["signed"]}) - 1,
                         "submission and submission_empty share a domain; others must not")

    def test_payment_merkle(self):
        pm = self.v["payment_merkle"]
        leaves = []
        for row in pm["leaves"]:
            h = merkle.leaf_hash(row["addr"], row["steps"])
            self.assertEqual(h.hex(), row["hash"])
            leaves.append(h)
        root, layers = merkle.build(leaves)
        self.assertEqual(root.hex(), pm["root"])
        self.assertEqual(merkle.build([])[0].hex(), pm["empty_root"])
        for i, expected in enumerate(pm["proofs"]):
            proof = [p.hex() for p in merkle.proof(layers, i)]
            self.assertEqual(proof, expected)
            self.assertTrue(merkle.verify(root, leaves[i], [bytes.fromhex(p) for p in expected]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
