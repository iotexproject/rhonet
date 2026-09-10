"""An honest contributor must never be slashed for keeping up.

Both regressions here were found by a launch rehearsal, not by reasoning: two
walkers that did everything right were slashed for "silent in 3 audit epochs".
They were not silent. They were rate limited into silence, inside a response
window that did not depend on how many openings we had asked them for.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rhonet import coordinator as module, ec, walker
from protocol_helpers import Coordinator


class AuditWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(ROOT / 'rounds/r32.json'))
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'window.sqlite'))
        self.addCleanup(self.coord.db.close)
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
        self.pk = walker.pubkey_hex(self.key)
        self.addr = '0x' + 'cd' * 20
        self.clock = patch.object(module, 'now', return_value=self.coord.started_at + 1)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.coord.admit(self.pk, self.addr, ec.ticket_solve(self.spec, self.coord.table, self.pk))

    def submit_points(self, count):
        points, t = [], 0
        while len(points) < count:
            start = ec.derive_start(self.spec, self.pk, t)
            found = ec.walk_to_dp(self.spec, self.coord.table, *start, self.spec.w,
                                  1 << self.spec.max_walk_len_log2)
            if found is not None:
                a, b, (x, y), steps = found
                points.append(dict(x=x, y=y, a=a, b=b, t=t, steps=steps))
            t += 1
        self.coord.submit(self.pk, points)
        return points

    def test_the_window_scales_with_what_we_asked_for(self):
        """A flat window demands an unbounded answer rate from a large contributor."""
        with patch.object(self.spec, 'spot_check_rate', 1):
            self.submit_points(40)
            self.coord.started_at -= self.spec.epoch_seconds
            self.coord.close_epoch()
        owed = self.coord.db.execute(
            "SELECT COUNT(*), MAX(deadline) FROM challenges WHERE epoch=0 AND pubkey=?",
            (self.pk,)).fetchone()
        count, deadline = owed
        self.assertGreaterEqual(count, 40, "rate 1 must challenge every point")
        # Base window, plus time proportional to the number of openings demanded.
        expected = module.now() + self.spec.audit_response_seconds + count / module.AUDIT_ANSWER_RATE
        self.assertGreaterEqual(deadline, expected - 1)
        # And the plan says so publicly, so a slow client can see what it owes.
        event = next(e for e in self.coord.events_view() if e['kind'] == 'audit_window')
        self.assertEqual(event['detail']['challenges'], count)

    def test_keeping_up_is_not_silence(self):
        """Answer every challenge at a plausible pace: the identity stays active.

        Under the old flat window this fails: thirty openings at one every half
        second take fifteen seconds, and the window was ten regardless of count.
        """
        with patch.object(self.spec, 'spot_check_rate', 1):
            self.submit_points(30)
            self.coord.started_at -= self.spec.epoch_seconds
            # The real close_epoch, not the fixture's, which answers for us.
            module.Coordinator.close_epoch(self.coord)
            targets = self.coord.audit_targets(self.pk)
            self.assertTrue(targets)
            for i, target in enumerate(targets):
                # One answer every half second, which is slower than any real client.
                self.now.return_value += 0.5
                points = self.coord.fixtures[(self.spec.round_id, self.pk, target['t'])]
                self.coord.answer_audit(self.pk, target['epoch'], target['t'],
                                        ec.checkpoint_opening(points, target['segment']))
                # The epoch loop keeps ticking while we answer, and it is the tick
                # that converts an expired deadline into silence. That is exactly
                # what happened in rehearsal, so the test has to reproduce it.
                if i % 5 == 4:
                    module.Coordinator.close_epoch(self.coord)
            self.coord.close_epoch()
        status, credited = self.coord.db.execute(
            "SELECT status, credited_steps FROM miners WHERE pubkey=?", (self.pk,)).fetchone()
        self.assertEqual(status, 'active')
        self.assertGreater(credited, 0)
        self.assertFalse(self.coord.db.execute(
            "SELECT 1 FROM challenges WHERE result='silent'").fetchone())
        self.assertFalse(self.coord.db.execute("SELECT 1 FROM withheld").fetchone())

    def test_answering_an_audit_is_not_throttled_by_submission_limits(self):
        """The audit answer had shared the submission bucket at 5/s, so an identity
        owing hundreds of openings was rate limited into being slashed for silence."""
        client = TestClient(module.build_app(self.coord))
        # Drain the submission buckets completely.
        module.SUBMIT_KEY_BURST, module.SUBMIT_IP_BURST = 0, 0
        app = module.build_app(self.coord)
        client = TestClient(app)
        body = walker.signed(self.key, {'round_id': self.spec.round_id, 'pubkey': self.pk,
                                        'epoch': 0, 'seq': 99, 'dps': []})
        self.assertEqual(client.post('/api/submit', json=body).status_code, 429)
        opening = walker.signed(self.key, {
            'round_id': self.spec.round_id, 'pubkey': self.pk, 'audit_epoch': 0, 't': 0,
            'opening': {'segment': 0}, 'epoch': 0, 'seq': 100})
        response = client.post('/api/audit/open', json=opening)
        self.assertNotEqual(response.status_code, 429,
                            "an obligation with a deadline must not share the submit bucket")
        self.assertEqual(response.status_code, 404)  # no such challenge, which is fine

    def tearDown(self):
        module.SUBMIT_KEY_BURST = module._env_num("RHONET_SUBMIT_KEY_BURST", 20, int)
        module.SUBMIT_IP_BURST = module._env_num("RHONET_SUBMIT_IP_BURST", 20, int)


if __name__ == '__main__':
    unittest.main(verbosity=2)
