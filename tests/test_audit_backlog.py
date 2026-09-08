"""Verification follows identity volume; bounded unreplayed credit must drain."""
import dataclasses
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from rhonet import coordinator as module, ec, walker


class BacklogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.spec = dataclasses.replace(base, w=4, ticket_d=5, max_walk_len_log2=10)
        self.path = str(Path(self.tmp.name) / 'backlog.sqlite')
        self.coord = module.Coordinator(self.spec, self.path)
        self.addCleanup(self.coord.db.close)
        self.clock = patch.object(module, 'now', return_value=self.coord.started_at + 1).start()
        self.addCleanup(patch.stopall)
        self.seen = set()

    def point(self, pk, start=0):
        for t in range(start, start + 4096):
            res = ec.walk_to_dp(self.spec, self.coord.table,
                                *ec.derive_start(self.spec, pk, t),
                                self.spec.w, ec.MAX_REPLAY_STEPS(self.spec))
            if res and res[2][0] not in self.seen:
                a, b, (x, y), steps = res
                self.seen.add(x)
                return dict(t=t, a=a, b=b, x=x, y=y, steps=steps)
        self.fail('no distinct DP')

    def admit(self, pk):
        self.coord.admit(pk, '0x' + pk[:40], ec.ticket_solve(self.spec, self.coord.table, pk))

    def advance(self, epoch):
        self.clock.return_value = self.coord.started_at + epoch * self.spec.epoch_seconds + 1
        self.coord.close_epoch()

    def test_200_ticketed_forgers_all_slashed_in_one_closure(self):
        for i in range(1, 201):
            pk = f'{i:064x}'
            self.admit(pk)
            dp = self.point(pk)
            dp['a'] = (dp['a'] + 1) % self.spec.curve.n
            self.assertFalse(ec.dp_verify(self.spec, self.coord.table, pk, dp))
            self.assertEqual(self.coord.submit(pk, [dp])['accepted'], 1)
        self.assertEqual(len(self.coord.status_view()['audit_backlog_by_identity']), 200)
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            self.advance(1)
        self.assertEqual(verify.call_count, 200)
        self.assertEqual(self.coord.db.execute("SELECT COUNT(*) FROM miners WHERE status='slashed' AND credited_steps=0").fetchone()[0], 200)
        self.assertEqual(self.coord.status_view()['audit_backlog_steps'], 0)
        self.assertEqual(json.loads(self.coord.db.execute('SELECT leaves FROM epochs WHERE idx=0').fetchone()[0]), [])

    def test_sample_exceeds_old_global_caps_and_scales_per_identity(self):
        rows = []
        for i in range(200):
            pk = f'{i:064x}'
            rows.extend((pk, t) for t in range(192))
        selected = self.coord._select_targets(bytes(32), bytes(range(32)), rows, 'spot', 64)
        self.assertEqual(len(selected), 600)
        for i in range(200):
            self.assertEqual(sum(pk == f'{i:064x}' for pk, _ in selected), 3)
        delayed = self.coord._select_targets(bytes(32), bytes(range(32)), rows, 'spot2', 512)
        self.assertEqual(len(delayed), 200)
        self.assertTrue(all(t == 0 for _, t in delayed))
        self.assertEqual(selected, self.coord._select_targets(bytes(32), bytes(range(32)), list(reversed(rows)), 'spot', 64))

    def test_backlog_limits_batches_persists_and_drains_without_new_work(self):
        pk = 'ab' * 32
        self.admit(pk)
        batch = []
        for _ in range(5):
            batch.append(self.point(pk, batch[-1]['t'] + 1 if batch else 0))
        with patch.object(module, 'MAX_AUDIT_BACKLOG_DPS', 4):
            result = self.coord.submit(pk, batch)
            self.assertEqual(result['accepted'], 4)
            self.assertEqual(result['rejected'], [(4, 'audit backlog')])
            self.assertEqual(self.coord.submit(pk, [batch[4]])['rejected'], [(0, 'audit backlog')])
            client = TestClient(module.build_app(self.coord))
            self.addCleanup(client.close)
            status = client.get('/api/status').json()
            self.assertEqual(status['audit_backlog_by_identity'][pk], 4 * (1 << self.spec.w))
            self.assertEqual(status['audit_backlog_limit_steps'], 4 * (1 << self.spec.w))
            restarted = module.Coordinator(self.spec, self.path)
            try:
                self.assertEqual(restarted.status_view()['audit_backlog_steps'], status['audit_backlog_steps'])
                self.assertEqual(restarted.submit(pk, [batch[4]])['accepted'], 0)
            finally:
                restarted.db.close()
            for epoch in range(1, 5):
                self.advance(epoch)
                self.assertEqual(self.coord.status_view()['audit_backlog_steps'], max(0, 3 - epoch) * (1 << self.spec.w))
            self.assertEqual(self.coord.submit(pk, [batch[4]])['accepted'], 1)
            self.assertEqual(self.coord.miners_view()[0]['status'], 'active')

    def test_hard_driving_honest_miner_retries_without_gaps_or_slashes(self):
        pk = 'ac' * 32
        self.admit(pk)
        batch = []
        for _ in range(160):
            batch.append(self.point(pk, batch[-1]['t'] + 1 if batch else 0))
        pending = list(reversed(batch))
        deferred = 0
        with patch.object(module, 'MAX_AUDIT_BACKLOG_DPS', 16):
            for epoch in range(1, 40):
                pending.sort(key=lambda dp: dp['t'])
                result = self.coord.submit(pk, pending)
                deferred += len(result['retry_indices'])
                self.assertFalse(result.get('slashed'))
                self.assertLessEqual(self.coord.status_view()['audit_backlog_steps'], 16 << self.spec.w)
                pending = walker.retain_deferred(pending, pending, result)
                self.assertEqual(self.coord.miners_view()[0]['status'], 'active')
                self.assertEqual(self.coord.db.execute('SELECT t_gaps FROM miners').fetchone()[0], 0)
                if not pending:
                    break
                self.advance(epoch)
            self.assertFalse(pending)
            self.assertGreater(deferred, 500)
            self.assertEqual(self.coord.db.execute('SELECT COUNT(*) FROM dps').fetchone()[0], 160)
            self.assertEqual(self.coord.miners_view()[0]['credited_steps'], 160 << self.spec.w)

    def test_quota_retry_and_hysteresis_do_not_consume_identifiers(self):
        pk = 'ad' * 32
        self.admit(pk)
        batch = [self.point(pk, t) for t in range(5)]
        with patch.object(self.coord, 'quota', return_value=0):
            result = self.coord.submit(pk, batch)
        self.assertEqual(result['retry_indices'], list(range(5)))
        self.assertEqual(self.coord.db.execute('SELECT next_t,t_gaps FROM miners').fetchone(), (0, 0))
        with patch.object(module, 'MAX_AUDIT_BACKLOG_DPS', 4):
            self.coord.submit(pk, batch)
            self.coord.db.execute('UPDATE dps SET checked=1 WHERE t=?', (batch[0]['t'],))
            self.coord.db.commit()
            paused = self.coord.submit(pk, [batch[4]])
            self.assertEqual(paused['accepted'], 0)
            self.assertEqual(paused['batch_limit'], 1)
            self.coord.db.execute('UPDATE dps SET checked=1 WHERE t=?', (batch[1]['t'],))
            self.coord.db.commit()
            self.assertEqual(self.coord.submit(pk, [batch[4]])['accepted'], 1)
        self.assertEqual(self.coord.miners_view()[0]['status'], 'active')

    def test_restart_with_wrong_round_refuses_to_replay_or_slash(self):
        with self.assertRaisesRegex(ValueError, 'different round'):
            module.Coordinator(dataclasses.replace(self.spec, round_id='wrong-round'), self.path)

    def test_delayed_oldest_row_cannot_be_starved_by_fresh_submissions(self):
        # Even an adversary choosing new hash ranks cannot displace the oldest slot.
        rows = [('ab' * 32, t) for t in range(1024)]
        for oldest in range(8):
            targets = self.coord._select_targets(bytes(32), bytes([oldest]) * 32,
                                                  rows[oldest:], 'spot2', 512)
            self.assertEqual(targets[0][1], oldest)


if __name__ == '__main__':
    unittest.main(verbosity=2)
