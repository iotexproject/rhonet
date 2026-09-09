"""Permanent work-budget regression: use actual mining and actual replay."""
import concurrent.futures
import dataclasses
import itertools
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec
from rhonet.coordinator import Coordinator


class VerificationCostTests(unittest.TestCase):
    def test_real_round_verification_budget(self):
        base = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/cost40.json'))
        for rate in (1, 64, 4096):
            with self.subTest(rate=rate), tempfile.TemporaryDirectory() as tmp:
                fields = dict(w=8, ticket_d=9, max_walk_len_log2=11, spot_check_rate=rate)
                if hasattr(base, 'v'):
                    fields['v'] = 1
                spec = dataclasses.replace(base, **fields)
                coord = Coordinator(spec, str(Path(tmp) / 'cost.sqlite'))
                self.addCleanup(coord.db.close)
                pk = 'ab' * 32
                # Admission is real; ticket verification is measured separately
                # from search replay because it buys admission, not search credit.
                coord.admit(pk, '0x' + 'ab' * 20, ec.ticket_solve(spec, coord.table, pk))
                miner = ec.BatchWalker(spec, coord.table, pk, 32, itertools.count().__next__)
                replay_steps = 0
                original = ec.replay
                def measured(spec, table, a, b, point, steps):
                    nonlocal replay_steps
                    replay_steps += steps
                    return original(spec, table, a, b, point, steps)
                last = epoch = submitted = 0
                def answer():
                    if hasattr(coord, 'audit_targets'):
                        while targets := coord.audit_targets(pk):
                            def respond(target):
                                return coord.answer_audit(pk, target['epoch'], target['t'],
                                    miner.open_segment(target['t'], target['segment']))
                            with concurrent.futures.ThreadPoolExecutor(4) as pool:
                                list(pool.map(respond, targets))
                # Exercise multiple real epochs, not a round-long deferred
                # verification campaign. Keep the final window's volume bounded.

                with patch.object(ec, 'replay', side_effect=measured), patch(
                        'rhonet.coordinator.now', return_value=coord.started_at + 1) as clock:
                    while coord.status == 'open':
                        points = miner.step()
                        if points:
                            collision_started = time.monotonic()
                            coord.submit(pk, points, steps_done=miner.steps_done - last)
                            last = miner.steps_done
                            submitted += len(points)
                        if submitted >= 256 and coord.status == 'open':
                            epoch += 1
                            clock.return_value = coord.started_at + epoch*spec.epoch_seconds+1
                            coord.close_epoch()
                            answer()
                            coord.close_epoch()
                            submitted = 0
                            if hasattr(miner, "checkpoints"):
                                live = {walk[4] for walk in miner.walks}
                                miner.checkpoints = {t:points for t,points in miner.checkpoints.items() if t in live}
                        self.assertLess(miner.steps_done, 20 * spec.expected_steps)
                    started = collision_started
                    while coord.status == 'settling':
                        # The new interactive protocol must remain serviceable
                        # after intake stops; answer only published challenges.
                        answer()
                        coord._finish(*coord._get_state('pending_solution'))
                        self.assertLess(time.monotonic() - started, 5)
                measured_total = coord.status_view().get('verification_replay_steps', replay_steps)
                ratio = measured_total / miner.steps_done
                print(f'rate=1/{rate}: replay={measured_total}, search={miner.steps_done}, '
                      f'ratio={ratio:.6%}, settlement={time.monotonic()-started:.3f}s', flush=True)
                self.assertLess(time.monotonic()-started, 5)
                self.assertEqual(coord.status, 'solved')
                self.assertTrue(coord.status_view()['solution']['verified'])
                self.assertLessEqual(ratio, .02)


if __name__ == '__main__':
    unittest.main(verbosity=2)
