"""Slow start must not throttle the contributor the round exists to recruit.

The base quota is sized for the reference client. Doubling from there takes nine
epochs to reach a current GPU, and the first fast client to arrive is the most
valuable thing that can happen to this round: nine hours mostly idle, with no
explanation on the dashboard, is a good way to lose it.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rhonet import coordinator as module, ec, walker
from protocol_helpers import Coordinator


class QuotaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(ROOT / 'rounds/r32.json'))
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'quota.sqlite'))
        self.addCleanup(self.coord.db.close)
        self.pk = 'ab' * 32
        self.clock = patch.object(module, 'now', return_value=self.coord.started_at + 1)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.coord.admit(self.pk, '0x' + '11' * 20,
                         ec.ticket_solve(self.spec, self.coord.table, self.pk))

    def deliver(self, epoch, count):
        """Record `count` accepted points in `epoch`, as if the identity produced them."""
        self.coord.db.executemany(
            "INSERT OR IGNORE INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch) VALUES(?,?,'0','0','0','0',1,0,?)",
            [(self.pk, epoch * 10 ** 6 + i, epoch) for i in range(count)])
        self.coord.db.commit()

    def at(self, epoch):
        self.now.return_value = self.coord.started_at + epoch * self.spec.epoch_seconds + 1

    def test_a_fast_client_reaches_its_own_rate_in_a_few_epochs(self):
        """A GPU at the site's own plausible rate produces about 40,000 points an
        hour on this round. It must reach that inside three epochs, not nine."""
        base, capable = 2048, 40_000
        with patch.object(self.spec, 'quota_dps_per_epoch_base', base):
            epochs, delivered = 0, 0
            for epoch in range(0, 12):
                self.at(epoch)
                allowed = self.coord.quota(0, self.pk)
                delivered = min(capable, allowed)
                self.deliver(epoch, delivered)
                epochs = epoch
                if allowed >= capable:
                    break
            self.assertLessEqual(epochs + 1, 3,
                                 f"took {epochs} epochs to admit a client doing {capable}/epoch")

    def test_the_ceiling_can_only_be_earned(self):
        """Throughput pacing must follow accepted work, never a claim about it."""
        with patch.object(self.spec, 'quota_dps_per_epoch_base', 128):
            self.at(1)
            self.assertEqual(self.coord.quota(0, self.pk), 256)  # slow start alone
            self.deliver(1, 1000)
            self.at(2)
            self.assertEqual(self.coord.quota(0, self.pk),
                             module.QUOTA_THROUGHPUT_MULTIPLE * 1000)
            # Slashed rows are not delivered work and must not raise the ceiling.
            self.coord.db.execute("UPDATE dps SET slashed=1 WHERE epoch=1")
            self.coord.db.commit()
            self.assertEqual(self.coord.quota(0, self.pk), 512)

    def test_slow_start_still_applies_to_an_unknown_identity(self):
        with patch.object(self.spec, 'quota_dps_per_epoch_base', 128):
            self.at(0)
            self.assertEqual(self.coord.quota(0, self.pk), 128)
            self.at(1)
            self.assertEqual(self.coord.quota(0, self.pk), 256)

    def test_capacity_hints_explain_the_throttle(self):
        """A throttled client must be able to tell slow-start from rejection."""
        with patch.object(self.spec, 'quota_dps_per_epoch_base', 1):
            result = self.coord.submit(self.pk, [], freshness=(self.coord.current_epoch(), 1))
        for field in ("quota", "quota_used", "quota_source", "audit_backlog",
                      "audit_backlog_limit"):
            self.assertIn(field, result, field)
        self.assertIn(result["quota_source"], ("slow-start", "throughput"))


if __name__ == '__main__':
    unittest.main(verbosity=2)
