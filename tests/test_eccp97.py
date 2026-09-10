"""The ECCp-97 round is Certicom's problem, and this proves it.

The decisive check is the last one: k*G == Q for the k published by the BT Labs /
INRIA team in March 1998. Nobody produces that k for this (G, Q) pair without
either solving the problem or holding the real answer, so a curve satisfying it
with the historical constant is the historical curve.

See rounds/eccp97.provenance.md for the sources.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rhonet import ec

# "the residue class of 1 6C86AA7C ACF69F1D D28B3E2F modulo 1 6EA1595E D21AE98F B6CCA20D"
HISTORICAL_K = 0x16C86AA7CACF69F1DD28B3E2F
HISTORICAL_N = 0x16EA1595ED21AE98FB6CCA20D
ROUND = ROOT / "rounds/eccp97.json"


class Eccp97Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = ec.RoundSpec.load(str(ROUND))
        cls.c = cls.spec.curve

    def test_it_is_the_certicom_curve(self):
        self.assertEqual(self.c.n, HISTORICAL_N,
                         "group order must equal the modulus in the 1998 announcement")
        self.assertEqual(self.c.p.bit_length(), 97)
        self.assertEqual(self.c.n.bit_length(), 97)
        self.assertEqual(self.spec.bits, 97)

    def test_the_round_validates(self):
        # Primality, nonsingularity, Hasse, n*G = n*Q = infinity, no small
        # embedding degree, not anomalous. Raises on any failure.
        self.spec.validate(deep=True)

    def test_the_published_answer_solves_it(self):
        self.assertEqual(self.c.mul(HISTORICAL_K, self.c.G), self.spec.Q)
        # And it is the only answer in [0, n): the group is cyclic of prime order.
        self.assertNotEqual(self.c.mul(HISTORICAL_K + 1, self.c.G), self.spec.Q)

    def test_the_answer_cannot_be_turned_into_credit(self):
        """Knowing k does not let anyone fabricate a point that replays.

        A submitted point is only worth anything if walking from
        PRF(round_id, pubkey, t) actually reaches it. k gives no control over
        where a PRF-derived walk goes, so a point built from k fails replay.
        """
        table = ec.walk_table(self.spec)
        pubkey = "aa" * 32
        # The most direct attempt: claim the target itself, with coefficients
        # that satisfy a*G + b*Q = P. They do, and it still fails.
        # A short claimed walk keeps this test cheap; length is irrelevant to the
        # argument, because replay disagrees at the very first step.
        forged = {"t": 7, "steps": 4,
                  "x": self.spec.qx, "y": self.spec.qy, "a": 0, "b": 1}
        self.assertTrue(self.c.add(self.c.mul(forged["a"], self.c.G),
                                   self.c.mul(forged["b"], self.spec.Q))
                        == (forged["x"], forged["y"]))
        self.assertFalse(ec.dp_verify(self.spec, table, pubkey, forged))

    def test_the_walk_is_the_plain_one(self):
        """The negation map is a round parameter, not a client optimisation.

        A client that canonicalises to min(y, p-y) walks a different function, so
        its submissions do not replay and the audit slashes it for a correct
        implementation of the wrong protocol. This round does not enable it, and
        the spec refuses to load a round that claims to until it is implemented.
        """
        self.assertFalse(self.spec.negation_map)
        self.assertIn("negation_map", self.spec.to_dict())
        with open(ROUND) as f:
            claimed = dict(json.load(f), negation_map=True)
        with self.assertRaises(ValueError) as exc:
            ec.RoundSpec.from_dict(claimed)
        self.assertIn("not implemented", str(exc.exception))

    def test_round_is_an_unfunded_exercise(self):
        self.assertFalse(self.spec.funded)
        self.assertEqual(self.spec.prize_pool_usdc, 0.0)

    def test_parameters_are_sized_for_the_round(self):
        spec = self.spec
        dps = spec.expected_steps / (1 << spec.w)
        self.assertLess(dps, 2_000_000, "too many points for one coordinator to hold")
        self.assertGreater(dps, 100_000, "too few points to pay contributors smoothly")
        fraction = (1 / spec.spot_check_rate) * (1 << spec.v) / (1 << spec.w)
        self.assertLess(fraction, 0.001, "verification must stay far below the search")
        self.assertGreater(spec.ticket_d, spec.w, "Sybil invariant")

    def test_provenance_is_committed(self):
        text = (ROOT / "rounds/eccp97.provenance.md").read_text()
        self.assertIn("eccp97a.c", text)
        self.assertIn(f"{HISTORICAL_K:x}", text.lower())
        with open(ROUND) as f:
            self.assertEqual(json.load(f)["round_id"], "exercise-97")


if __name__ == "__main__":
    unittest.main(verbosity=2)
