"""H-3 work telemetry stays separate from payment; direct and pytest runners."""
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec, miner
from rhonet.coordinator import Coordinator, MAX_TELEMETRY_PER_SUBMISSION, SCHEMA


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.coord = Coordinator(self.spec, ':memory:')
        self.addCleanup(self.coord.db.close)
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.pk = miner.pubkey_hex(self.key)
        self.ticket = ec.ticket_solve(self.spec, self.coord.table, self.pk)
        self.coord.admit(self.pk, '0x' + '11' * 20, self.ticket)
        for t in range(100):
            result = ec.walk_to_dp(self.spec, self.coord.table, *ec.derive_start(self.spec, self.pk, t),
                                   self.spec.w, ec.MAX_REPLAY_STEPS(self.spec))
            if result:
                a, b, (x, y), steps = result
                self.dp = dict(a=a, b=b, x=x, y=y, steps=steps, t=t)
                break
        else:
            self.fail('No DP found')

    def test_signed_submission_stores_telemetry_without_extra_credit(self):
        from rhonet.coordinator import build_app
        body = miner.signed(self.key, dict(round_id=self.spec.round_id, pubkey=self.pk,
                                          dps=[self.dp], steps_done=12345, abandoned=7, epoch=self.coord.current_epoch(), seq=0))
        with TestClient(build_app(self.coord)) as client:
            tampered = dict(body, steps_done=12346)
            self.assertEqual(client.post('/api/submit', json=tampered).status_code, 401)
            response = client.post('/api/submit', json=body)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['accepted'], 1)
            status = client.get('/api/status').json()
            m, = client.get('/api/miners').json()
        credit = 1 << self.spec.w
        self.assertEqual(self.coord.db.execute(
            'SELECT executed_steps, abandoned_walks, ticket_steps, credited_steps FROM miners').fetchone(),
            (12345, 7, self.ticket['steps'], credit))
        self.assertGreater(status['total_ticket_steps'], 0)
        self.assertEqual(status['total_ticket_steps'], self.ticket['steps'])
        self.assertEqual(status['total_executed_steps'], 12345 + self.ticket['steps'])
        self.assertEqual(status['total_abandoned_walks'], 7)
        self.assertEqual(status['total_credited_steps'], credit)
        self.assertEqual(status['executed_to_credited'], status['total_executed_steps'] / credit)
        self.assertEqual(m['executed_steps'], 12345)
        self.assertEqual(m['ticket_steps'], self.ticket['steps'])
        self.assertEqual(m['abandoned_walks'], 7)
        self.assertEqual(m['total_executed_steps'], status['total_executed_steps'])
        self.assertEqual(m['executed_to_credited'], status['executed_to_credited'])
        self.coord.submit(self.pk, [], steps_done=55, abandoned=2)
        self.assertEqual(self.coord.status_view()['total_executed_steps'], 12400 + self.ticket['steps'])
        self.assertEqual(self.coord.status_view()['total_abandoned_walks'], 9)
        self.assertEqual(self.coord.status_view()['total_credited_steps'], credit)

    def test_huge_negative_and_legacy_telemetry_cannot_inflate_credit(self):
        self.coord.submit(self.pk, [self.dp], steps_done=1 << 100, abandoned=1 << 100)
        self.coord.submit(self.pk, [], steps_done=-500, abandoned=-10)
        self.coord.submit(self.pk, [])
        m, = self.coord.miners_view()
        self.assertEqual(m['credited_steps'], 1 << self.spec.w)
        self.assertEqual(m['executed_steps'], MAX_TELEMETRY_PER_SUBMISSION)
        self.assertEqual(m['abandoned_walks'], MAX_TELEMETRY_PER_SUBMISSION)

    def test_admission_is_idempotent_and_slashing_preserves_work(self):
        self.coord.admit(self.pk, '0x' + '11' * 20, self.ticket)
        self.coord.submit(self.pk, [self.dp], steps_done=500, abandoned=3)
        self.coord._slash(self.pk, 'test slash')
        status = self.coord.status_view()
        self.assertEqual(status['total_ticket_steps'], self.ticket['steps'])
        self.assertEqual(status['total_executed_steps'], 500 + self.ticket['steps'])
        self.assertEqual(status['total_abandoned_walks'], 3)
        self.assertEqual(status['total_credited_steps'], 0)
        self.assertIsNone(status['executed_to_credited'])
        self.assertIsNone(self.coord.miners_view()[0]['executed_to_credited'])
        self.assertEqual(self.coord.db.execute('SELECT COUNT(*) FROM dps').fetchone()[0], 1)

    def test_solution_records_distinct_work_and_payment_ratios(self):
        self.coord.submit(self.pk, [self.dp], steps_done=500, abandoned=3)
        # Isolate final accounting; actual collision verification has its own suite.
        solution = self.coord._finish(1, self.pk, self.pk, self.dp['x'])
        status = self.coord.status_view()
        for name in ('total_executed_steps', 'total_ticket_steps', 'total_abandoned_walks', 'executed_to_credited'):
            self.assertEqual(solution[name], status[name])
        self.assertEqual(solution['ratio'], (1 << self.spec.w) / self.spec.expected_steps)
        self.assertEqual(solution['ratio_credited'], solution['ratio'])
        self.assertEqual(solution['ratio_executed'], (500 + self.ticket['steps']) / self.spec.expected_steps)

    def test_migration_preserves_legacy_credit_and_is_idempotent(self):
        legacy = '\n'.join(line for line in SCHEMA.splitlines()
                           if not line.strip().startswith(('executed_steps INTEGER', 'abandoned_walks INTEGER', 'ticket_steps INTEGER')))
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'legacy.sqlite')
            db = sqlite3.connect(path)
            db.executescript(legacy)
            db.execute('INSERT INTO miners(pubkey,payout_addr,ticket,admitted_at,admitted_epoch,credited_steps) '
                       'VALUES(?,?,?,?,?,?)', (self.pk, '0x' + '11' * 20, '{}', 0, 0, 123))
            db.commit()
            db.close()
            for _ in range(2):
                coord = Coordinator(self.spec, path)
                try:
                    self.assertEqual(coord.db.execute(
                        'SELECT credited_steps,executed_steps,abandoned_walks,ticket_steps FROM miners').fetchone(),
                        (123, 0, 0, 0))
                finally:
                    coord.db.close()

    def test_worker_ships_and_resets_both_counters(self):
        bw, q, stop = Mock(steps_done=0, abandoned=0), Mock(), Mock()
        stop.is_set.side_effect = [False, False, True]
        def step():
            bw.steps_done += 64
            bw.abandoned += 2
            return []
        bw.step.side_effect = step
        with patch.object(ec, 'BatchWalker', return_value=bw), patch.object(miner.time, 'time', side_effect=[0, 1, 1, 2, 2]):
            miner.worker(self.spec.to_dict(), self.pk, 64, q, stop, False, 0, 1)
        self.assertEqual([call.args[0] for call in q.put.call_args_list], [([], 64, 2), ([], 64, 2)])
        self.assertEqual((bw.steps_done, bw.abandoned), (0, 0))

    def test_parent_submits_signed_deltas_even_without_dps(self):
        client, ctx = Mock(), Mock()
        client.get.side_effect = lambda url: Mock(json=lambda: self.spec.to_dict() if url == "/api/round" else {"epoch": 0})
        ok = Mock(status_code=200)
        ok.json.return_value = {'accepted': 0, 'epoch': 0}
        done = Mock(status_code=200)
        done.json.return_value = {'status': 'solved'}
        client.post.side_effect = [ok, ok, done]
        ctx.Queue.return_value.get.side_effect = [([], 100, 3), ([], 25, 1)]
        with patch.object(miner, 'load_or_create_key', return_value=self.key), \
                patch.object(miner.httpx, 'Client', return_value=client), \
                patch.object(miner.mp, 'get_context', return_value=ctx), \
                patch.object(miner.time, 'time', side_effect=range(100)), \
                patch.object(sys, 'stderr', new_callable=io.StringIO):
            self.assertEqual(miner.main(['--procs', '1', '--flush', '0']), 0)
        submitted = [call.kwargs['json'] for call in client.post.call_args_list if call.args[0] == '/api/submit']
        self.assertEqual([(b['steps_done'], b['abandoned']) for b in submitted], [(100, 3), (25, 1)])
        for body in submitted:
            sig = body.pop('sig')
            Coordinator.verify_sig(self.pk, body, sig)
            self.assertEqual(body['dps'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
