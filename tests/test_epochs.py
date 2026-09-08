"""H-5 epoch ledger regressions; run directly or with pytest."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec, merkle
from rhonet.coordinator import Coordinator, build_app


class EpochTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'epochs.sqlite'))
        self.addCleanup(self.coord.db.close)
        clock = patch('rhonet.coordinator.now', return_value=self.coord.started_at + 1)
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.seen = set()
        self.next_t = {}
        self.a, self.b = '0x' + 'ab' * 20, '0x' + 'cd' * 20

    def advance(self, epoch):
        self.clock.return_value = self.coord.started_at + epoch * self.spec.epoch_seconds + 1

    def admit(self, pk, addr):
        ticket = ec.ticket_solve(self.spec, self.coord.table, pk)
        self.assertIsNotNone(ticket)
        self.coord.admit(pk, addr, ticket)
        self.next_t[pk] = 0

    def work(self, pk):
        for _ in range(1000):
            t = self.next_t[pk]
            self.next_t[pk] += 1
            start = ec.derive_start(self.spec, pk, t)
            result = ec.walk_to_dp(self.spec, self.coord.table, *start, self.spec.w,
                                   1 << self.spec.max_walk_len_log2)
            if result is None or result[2][0] in self.seen:
                continue
            a, b, (x, y), steps = result
            self.seen.add(x)  # Keep collision settlement separate from epoch tests.
            self.assertEqual(self.coord.submit(pk, [dict(t=t, a=a, b=b, x=x, y=y, steps=steps)])['accepted'], 1)
            return
        self.fail('could not find a fresh distinguished point')

    def verify(self, proof, epoch):
        root = self.coord.db.execute('SELECT root FROM epochs WHERE idx=?', (epoch,)).fetchone()[0]
        self.assertEqual(proof['epoch'], epoch)
        self.assertEqual(proof['root'], '0x' + root)
        self.assertTrue(merkle.verify(bytes.fromhex(root),
                                    merkle.leaf_hash(proof['payout_addr'], proof['credited_steps']),
                                    [bytes.fromhex(p[2:]) for p in proof['proof']]))
        self.assertTrue(proof['verifies'])

    def test_downtime_backfills_empty_epochs_and_is_idempotent(self):
        self.advance(4)
        self.coord.close_epoch()
        self.advance(7)
        self.coord.close_epoch()
        rows = self.coord.db.execute('SELECT idx, root, total_steps, n_miners, leaves FROM epochs WHERE audit_complete=1 ORDER BY idx').fetchall()
        self.assertEqual([r[0] for r in rows], list(range(self.coord.current_epoch())))
        for _, root, total, count, leaves in rows:
            self.assertEqual(root, merkle.build([])[0].hex())
            self.assertEqual((total, count, json.loads(leaves)), (0, 0, []))
        self.coord.close_epoch()
        self.assertEqual(self.coord.db.execute('SELECT COUNT(*) FROM epochs WHERE audit_complete=1').fetchone()[0], len(rows))

    def test_departed_miner_and_cumulative_balances(self):
        a_pk, b_pk = 'ab' * 32, 'cd' * 32
        self.admit(a_pk, self.a)
        self.admit(b_pk, self.b)
        balances = []
        for epoch in range(5):
            if epoch < 2:
                self.work(a_pk)
            self.work(b_pk)
            self.advance(epoch + 1)
            self.coord.close_epoch()
            balances.append(self.coord.proof(self.b)['credited_steps'])
        self.assertEqual(balances, sorted(balances))
        self.assertEqual(balances, [(i + 1) * (1 << self.spec.w) for i in range(5)])
        latest = self.coord.proof(self.a.upper())
        historic = self.coord.proof(self.a, epoch=1)
        self.verify(latest, 4)
        self.verify(historic, 1)
        self.assertEqual(latest['credited_steps'], 2 * (1 << self.spec.w))
        self.assertEqual(latest['credited_steps'], historic['credited_steps'])
        self.assertEqual(self.coord.epochs_for(self.a.upper()), list(range(5)))

    def test_unclosed_epoch_and_unknown_address(self):
        with self.assertRaises(HTTPException) as exc:
            self.coord.proof(self.a)
        self.assertEqual(exc.exception.status_code, 404)
        self.advance(2)
        self.coord.close_epoch()
        for epoch in (-1, 2, 100):
            with self.assertRaises(HTTPException) as exc:
                self.coord.proof(self.a, epoch=epoch)
            self.assertEqual(exc.exception.status_code, 404)
            self.assertIn(f'epoch {epoch} is not closed', exc.exception.detail)
        self.assertEqual(self.coord.epochs_for(self.a), [])
        with self.assertRaises(HTTPException) as exc:
            self.coord.proof(self.a, epoch=0)
        self.assertEqual(exc.exception.status_code, 404)
        self.assertIn('does not appear in any closed epoch', exc.exception.detail)

    def test_slash_preserves_historical_proof_and_discovery_over_http(self):
        pk = 'ab' * 32
        self.admit(pk, self.a)
        self.work(pk)
        self.advance(1)
        self.coord.close_epoch()
        self.coord._slash(pk, 'test slash')
        self.advance(3)
        self.coord.close_epoch()
        self.assertEqual(self.coord.epochs_for(self.a), [0])
        # No lifespan context: control epoch closure explicitly in this test.
        client = TestClient(build_app(self.coord))
        self.addCleanup(client.close)
        response = client.get('/api/proof', params={'payout_addr': self.a})
        self.assertEqual(response.status_code, 404)
        self.assertIn('most recent epoch containing this address is 0', response.json()['detail'])
        response = client.get('/api/proof', params={'payout_addr': self.a, 'epoch': 0})
        self.assertEqual(response.status_code, 200)
        self.verify(response.json(), 0)
        response = client.get('/api/proof', params={'payout_addr': self.a, 'epoch': 3})
        self.assertEqual(response.status_code, 404)
        response = client.get('/api/proof/epochs', params={'payout_addr': self.a.upper()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [0])

    def test_backfill_audits_previous_root_before_publishing(self):
        pk = 'ab' * 32
        self.admit(pk, self.a)
        self.work(pk)
        self.advance(3)
        # Slash during the second audit; only post-audit balances may be published.
        def audit(idx, root):
            stored = self.coord.db.execute('SELECT audit_seed_root FROM epochs WHERE idx=?', (idx,)).fetchone()[0]
            self.assertEqual(root.hex(), stored)
            self.assertEqual(self.coord.db.execute('SELECT root FROM epochs WHERE idx=?', (idx,)).fetchone()[0], '')
            if idx == 1:
                self.coord._slash(pk, 'test slash')
        with patch.object(self.coord, 'audit_epoch', side_effect=audit) as primary, \
                patch.object(self.coord, 'audit_delayed', wraps=self.coord.audit_delayed) as delayed:
            self.coord.close_epoch()
        roots = self.coord.db.execute('SELECT idx, root FROM epochs WHERE audit_complete=1 ORDER BY idx').fetchall()
        expected = [(idx, merkle.build([])[0] if idx == 0 else bytes.fromhex(roots[idx - 1][1])) for idx, _ in roots]
        self.assertEqual([c.args for c in primary.call_args_list], expected)
        self.assertEqual([c.args for c in delayed.call_args_list], expected)
        self.assertNotEqual(roots[0][1], roots[1][1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
