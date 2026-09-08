"""Bounded epoch listing and independently reproducible audit details."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from rhonet import ec
from rhonet.coordinator import Coordinator, build_app


class EpochApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, RHONET_BEACON_URL='')
        env.start()
        self.addCleanup(env.stop)
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'round.sqlite'))
        self.addCleanup(self.coord.db.close)
        self.client = TestClient(build_app(self.coord))
        self.addCleanup(self.client.close)
        self.pk = 'ab' * 32
        self.coord.db.execute("INSERT INTO miners(pubkey,payout_addr,ticket,admitted_at,admitted_epoch) VALUES(?,?,'{}',0,0)",
                              (self.pk, '0x' + '11' * 20))
        self.coord.db.commit()

    def populate(self, epochs=4, count=1000):
        for epoch in range(epochs):
            self.coord.db.executemany(
                'INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch) VALUES(?,?,1,1,1,1,1,0,?)',
                [(self.pk, epoch * count + t, epoch) for t in range(count)])
        self.coord.db.commit()
        with patch('rhonet.coordinator.now', return_value=self.coord.started_at + epochs * self.spec.epoch_seconds + 1), patch.object(ec, 'dp_verify', return_value=True):
            self.coord.close_epoch()

    def test_listing_size(self):
        self.populate()
        response = self.client.get('/api/epochs')
        self.assertEqual(response.status_code, 200)
        print(f'GET /api/epochs fixture: {len(response.content)} bytes', flush=True)
        self.assertLess(len(response.content), 65536)
        self.assertNotIn(self.pk, response.text)
        self.assertNotIn('pairs', response.text)
        self.assertNotIn('audit_inputs', response.text)

    def test_paging_and_reproduction(self):
        actual = []
        def verify(spec, table, pk, dp):
            actual.append((pk, dp['t']))
            return True
        # populate normally patches replay; record it separately here.
        self.coord.db.executemany(
            'INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch) VALUES(?,?,1,1,1,1,1,0,0)',
            [(self.pk, t) for t in range(600)])
        self.coord.db.commit()
        with patch('rhonet.coordinator.now', return_value=self.coord.started_at + self.spec.epoch_seconds + 1), patch.object(ec, 'dp_verify', side_effect=verify):
            self.coord.close_epoch()
        listing = self.client.get('/api/epochs').json()
        closed = next(e for e in listing if e['idx'] == 0)
        detail = self.client.get('/api/epochs/0/audit?limit=3').json()
        self.assertEqual(detail['beacon_reveal'], closed['beacon_reveal'])
        published, expected = [], []
        for tag, entry in detail['audit_inputs'].items():
            pairs, candidates = [], []
            for kind, output in [('audited', pairs), ('candidates', candidates)]:
                offset = 0
                while True:
                    page = self.client.get(f'/api/epochs/0/audit?kind={kind}&limit=3&offset={offset}').json()['audit_inputs'][tag]
                    self.assertLessEqual(len(page['pairs']), 3)
                    output.extend(tuple(p) for p in page['pairs'])
                    if page['next_offset'] is None:
                        self.assertEqual(len(output), page['stored_count'])
                        break
                    offset = page['next_offset']
            self.assertEqual(entry['rate'], self.spec.spot_check_rate * (8 if tag == 'spot2' else 1))
            ranked = sorted((int.from_bytes(ec.H(bytes.fromhex(detail['audit_seed_root'][2:]), bytes.fromhex(detail['beacon_reveal']), tag, pk, t), 'big'), pk, t) for pk, t in candidates)
            count = (len(ranked) + entry['rate'] - 1) // entry['rate']
            if tag == 'spot2' and ranked:
                oldest = min(ranked, key=lambda r: r[2])
                ranked = [oldest] + [r for r in ranked if r != oldest]
            selected = [(pk, t) for _, pk, t in ranked[:count]]
            self.assertEqual(entry['total'], len(selected))
            self.assertEqual(pairs, selected[:entry['cap']])
            published.extend(pairs)
            expected.extend(selected[:entry['cap']])
        self.assertTrue(actual)
        self.assertEqual(actual, published)
        self.assertEqual(actual, expected)
        raw = self.coord.db.execute('SELECT audit_inputs FROM epochs WHERE idx=0').fetchone()[0]
        self.assertNotIn(self.pk, raw)
        self.assertEqual(raw, json.dumps(json.loads(raw), separators=(',', ':')))
        self.assertIsInstance(json.loads(raw)['spot']['pairs'][0][0], int)

    def test_uncapped_selection_and_snapshot_survives_deleted_dps(self):
        rows = [(self.pk, t, '1', '1', '1', '1', 1) for t in range(20)]
        self.coord.db.executemany(
            'INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch) VALUES(?,?,1,1,1,1,1,0,0)',
            [(self.pk, t) for t in range(20)])
        self.coord.db.commit()
        with patch.object(ec, 'dp_verify', return_value=True) as verify:
            self.coord._audit_rows(0, bytes(32), rows, 'spot', 1, 'epoch_audit')
        self.assertEqual(verify.call_count, 20)
        self.coord.db.execute('UPDATE epochs SET root=?,beacon_reveal=?,audit_complete=1 WHERE idx=0',
                              ('00' * 32, self.coord.beacon_for(0).hex()))
        self.coord.db.execute('DELETE FROM dps')
        self.coord.db.commit()
        raw = json.loads(self.coord.db.execute('SELECT audit_inputs FROM epochs WHERE idx=0').fetchone()[0])['spot']
        self.assertEqual(raw['total'], 20)
        self.assertEqual(len(raw['pairs']), 20)
        detail = self.client.get('/api/epochs/0/audit?limit=2').json()['audit_inputs']['spot']
        self.assertEqual(detail['total'], 20)
        self.assertEqual(detail['stored_count'], 20)
        self.assertFalse(detail['truncated'])
        self.assertEqual(len(detail['pairs']), 2)
        last = self.client.get('/api/epochs/0/audit?limit=2&offset=18').json()['audit_inputs']['spot']
        self.assertEqual(len(last['pairs']), 2)
        self.assertIsNone(last['next_offset'])
        candidates = self.client.get('/api/epochs/0/audit?kind=candidates').json()['audit_inputs']['spot']
        self.assertEqual(candidates['pairs'], [[self.pk, t] for t in range(20)])
        counts = self.client.get('/api/epochs').json()[0]['audit_counts']['spot']
        self.assertEqual(counts, {'audited': 20, 'total': 20, 'failed': 0})

    def test_listing_paging_and_validation(self):
        for idx in range(1, 65):
            self.coord._open_epoch(idx)
        first = self.client.get('/api/epochs').json()
        self.assertEqual(len(first), 50)
        second = self.client.get('/api/epochs', params={'before': first[-1]['idx'], 'limit': 50}).json()
        self.assertEqual([e['idx'] for e in first + second], list(range(64, -1, -1)))
        for url in ['/api/epochs?limit=0', '/api/epochs?limit=101', '/api/epochs?before=x',
                    '/api/epochs/0/audit?offset=-1', '/api/epochs/0/audit?limit=513',
                    '/api/epochs/0/audit?kind=bad']:
            self.assertEqual(self.client.get(url).status_code, 422, url)
        self.assertEqual(self.client.get('/api/epochs/0/audit').status_code, 409)
        self.assertEqual(self.client.get('/api/epochs/999/audit').status_code, 404)
        page = self.client.get('/').text
        self.assertIn('e.total_steps/unit', page)
        self.assertIn('e.miners', page)
        self.assertNotIn('/audit', page)

    def test_legacy_compaction_and_stable_indices(self):
        from rhonet.coordinator import migrate_schema
        pairs = [[self.pk, t] for t in range(20)]
        self.coord.db.execute('UPDATE epochs SET root=?,beacon_reveal=?,audit_complete=1,audit_inputs=? WHERE idx=0',
                              ('00' * 32, self.coord.beacon_for(0).hex(),
                               json.dumps({'spot': {'rate': 1, 'cap': 3, 'pairs': pairs}})))
        self.coord.db.commit()
        for _ in range(2):
            migrate_schema(self.coord.db)
            self.coord._migrate_audit_inputs()
            self.coord.db.execute('VACUUM')
            entry = self.client.get('/api/epochs/0/audit').json()['audit_inputs']['spot']
            self.assertEqual(entry['total'], 20)
            self.assertEqual(entry['stored_count'], 3)
            candidates = self.client.get('/api/epochs/0/audit?kind=candidates').json()['audit_inputs']['spot']
            self.assertEqual(candidates['pairs'], pairs)
            self.assertEqual(self.coord.db.execute('SELECT miner_idx FROM miners').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
