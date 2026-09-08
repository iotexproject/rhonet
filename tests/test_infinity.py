"""Validated adversarial rounds whose nonzero linear combinations are infinity."""
import dataclasses
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec
from rhonet.coordinator import Coordinator


class InfinityTests(unittest.TestCase):
    def setUp(self):
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))

    def cancelling_round(self, a, b):
        c = self.spec.curve
        self.assertNotEqual(a, 0)
        self.assertNotEqual(b, 0)
        k = (-a * pow(b, -1, c.n)) % c.n
        q = c.mul(k, c.G)
        self.assertIsNot(q, ec.INF)
        spec = dataclasses.replace(self.spec, qx=q[0], qy=q[1])
        spec.validate()
        self.assertIs(c.add(c.mul(a, c.G), c.mul(b, spec.Q)), ec.INF)
        return spec

    def test_coordinator_resamples_infinite_table_entry_deterministically(self):
        n, rid = self.spec.curve.n, self.spec.round_id
        a = int.from_bytes(ec.H(rid, 'table-c', 0), 'big') % n or 1
        b = int.from_bytes(ec.H(rid, 'table-d', 0), 'big') % n or 1
        spec = self.cancelling_round(a, b)
        with tempfile.TemporaryDirectory() as tmp:
            coord = Coordinator(spec, str(Path(tmp) / 'infinity.sqlite'))
            try:
                table = coord.table
                self.assertEqual(table, ec.walk_table(spec))
                self.assertEqual(len(table), spec.r)
                self.assertNotEqual(table[0][2:], (a, b))
                for x, y, cj, dj in table:
                    self.assertTrue(spec.curve.on_curve((x, y)))
                    self.assertEqual((x, y), spec.curve.add(spec.curve.mul(cj, spec.curve.G), spec.curve.mul(dj, spec.Q)))
            finally:
                coord.db.close()

    def test_batch_walker_skips_identifier_with_infinite_start(self):
        pk = 'ab' * 32
        a, b, _ = ec.derive_start(self.spec, pk, 0)
        spec = self.cancelling_round(a, b)
        self.assertIs(ec.derive_start(spec, pk, 0)[2], ec.INF)
        a1, b1, p1 = ec.derive_start(spec, pk, 1)
        self.assertIsNot(p1, ec.INF)
        identifiers = iter(range(10000))
        walker = ec.BatchWalker(spec, ec.walk_table(spec), pk, batch=1, rng_t=lambda: next(identifiers))
        self.assertEqual(walker.walks[0], [*p1, a1, b1, 1, 0])
        found = []
        for _ in range(ec.MAX_REPLAY_STEPS(spec) * 4):
            found.extend(walker.step())
            if found:
                break
        self.assertTrue(found)
        self.assertTrue(all(ec.dp_verify(spec, walker.table, pk, dp) for dp in found))


if __name__ == '__main__':
    unittest.main(verbosity=2)
