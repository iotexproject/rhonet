"""The strongest claim in the current design, measured rather than argued.

Under per-identity fractional sampling, an identity owes ceil(k/N) challenges for
the k points it submitted. The beacon decides *which* points, never *how many*.
So an adversary who somehow learns the beacon early -- including an operator who
holds the commit-reveal secret and colludes -- can choose which forgeries to place,
but cannot reduce the number of its points that get replayed.

That is what stands between the commit-reveal fallback and an external beacon, and
docs/ROUND-97.md flags it explicitly: "Both bounds assume the audit entropy is
unpredictable when the batch is sealed." This test grants an adversary exactly that
assumption's negation and shows what survives.
"""
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rhonet import coordinator as module, ec, merkle
from protocol_helpers import Coordinator


class BeaconAwareAdversaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(ROOT / 'rounds/r32.json'))
        secret = patch('rhonet.coordinator.secrets.token_bytes', return_value=bytes(range(32)))
        secret.start()
        self.addCleanup(secret.stop)
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'beacon.sqlite'))
        self.addCleanup(self.coord.db.close)
        self.clock = patch('rhonet.coordinator.now', return_value=self.coord.started_at + 1)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.rng = random.Random(99)
        self.seen = set()

    def admit(self, pk):
        self.coord.admit(pk, '0x' + '11' * 20, ec.ticket_solve(self.spec, self.coord.table, pk))

    def fake_of(self, dp):
        """Same point, fabricated coefficients: the cheap forgery, and the only one
        that actually saves work."""
        return dict(dp, a=(dp['a'] + self.rng.randrange(1, self.spec.curve.n)) % self.spec.curve.n,
                    b=self.rng.randrange(self.spec.curve.n))

    def point(self, pk, t, fake=False):
        result = ec.walk_to_dp(self.spec, self.coord.table, *ec.derive_start(self.spec, pk, t),
                               self.spec.w, 1 << self.spec.max_walk_len_log2)
        if result is None or result[2][0] in self.seen:
            return None
        a, b, (x, y), steps = result
        self.seen.add(x)
        if fake:
            a = (a + self.rng.randrange(1, self.spec.curve.n)) % self.spec.curve.n
            b = self.rng.randrange(self.spec.curve.n)
        return dict(x=x, y=y, a=a, b=b, t=t, steps=steps)

    def selected(self, pk, rows, seed_root, beacon):
        """Exactly what the coordinator will pick, computed by the adversary."""
        return {row[1] for row in Coordinator._select_targets(
            seed_root, beacon, rows, "spot", self.spec.spot_check_rate)}

    def test_knowing_the_beacon_does_not_reduce_how_much_is_replayed(self):
        pk = 'ab' * 32
        self.admit(pk)
        # The adversary holds the fallback secret from the moment the epoch opens.
        beacon = self.coord.beacon_for(0)
        seed_root = merkle.build([])[0]

        honest, t = [], 0
        while len(honest) < 60:
            dp = self.point(pk, t)
            if dp:
                honest.append(dp)
            t += 1
        rows = [(pk, dp['t'], dp['x'], dp['y'], dp['a'], dp['b'], dp['steps']) for dp in honest]
        chosen = self.selected(pk, rows, seed_root, beacon)

        # Every point it could place is one the beacon will not choose. This is the
        # most it can do with the secret, and it is a real advantage: it knows.
        safe = [dp for dp in honest if dp['t'] not in chosen]
        self.assertTrue(safe, "the adversary must have somewhere to hide")
        forged_t = safe[0]['t']
        batch = [self.fake_of(dp) if dp['t'] == forged_t else dp for dp in honest]
        self.assertEqual(self.coord.submit(pk, batch)['accepted'], len(batch))

        # The count replayed follows how much it submitted, not which identifiers
        # it chose, so foreknowledge buys placement and never volume.
        self.coord.started_at -= self.spec.epoch_seconds
        module.Coordinator.close_epoch(self.coord)
        owed = self.coord.db.execute(
            "SELECT COUNT(*) FROM challenges WHERE epoch=0 AND pubkey=?", (pk,)).fetchone()[0]
        expected = -(-len(batch) // self.spec.spot_check_rate)
        self.assertEqual(owed, expected,
                         "audited count must equal the honest fraction regardless of the beacon")

        # And the uncomfortable half, stated rather than elided: with the secret in
        # hand, that single hidden forgery does survive the epoch. This is exactly
        # the bound the round document publishes -- a lone forgery is cheap to hide
        # -- and it is why a funded round requires an external beacon rather than
        # the commit-reveal fallback an operator could hand to a colluder.
        self.coord.close_epoch()
        status = self.coord.db.execute(
            "SELECT status FROM miners WHERE pubkey=?", (pk,)).fetchone()[0]
        self.assertEqual(status, 'active')
        self.assertFalse(self.coord.db.execute(
            "SELECT 1 FROM challenges WHERE result='failed'").fetchone())

    def test_hiding_one_forgery_works_and_hiding_many_does_not(self):
        """Placement is the whole advantage, and it does not scale.

        With foreknowledge an adversary can put a single forgery on an unsampled
        point and pass. It cannot forge at any rate worth forging at, because the
        sample is a fixed fraction of everything it submits: forging more than the
        unsampled remainder means forging into a challenge.
        """
        pk = 'cd' * 32
        self.admit(pk)
        beacon = self.coord.beacon_for(0)
        seed_root = merkle.build([])[0]
        honest, t = [], 0
        while len(honest) < 60:
            dp = self.point(pk, t)
            if dp:
                honest.append(dp)
            t += 1
        rows = [(pk, dp['t'], dp['x'], dp['y'], dp['a'], dp['b'], dp['steps']) for dp in honest]
        chosen = self.selected(pk, rows, seed_root, beacon)
        # Forge everything, including the points it knows will be challenged --
        # which is what forging at scale necessarily means.
        batch = [self.fake_of(dp) for dp in honest]
        self.assertTrue(chosen & {dp['t'] for dp in batch})
        self.coord.submit(pk, batch)
        self.coord.started_at -= self.spec.epoch_seconds
        self.coord.close_epoch()
        status, credited = self.coord.db.execute(
            "SELECT status, credited_steps FROM miners WHERE pubkey=?", (pk,)).fetchone()
        self.assertEqual((status, credited), ('slashed', 0))


if __name__ == '__main__':
    unittest.main(verbosity=2)
