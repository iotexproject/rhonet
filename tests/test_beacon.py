"""Beacon and delayed-audit attack regressions; runnable directly."""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from io import BytesIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from rhonet import ec, merkle
from rhonet.coordinator import Coordinator, build_app
from protocol_helpers import Coordinator


class BeaconTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, RHONET_BEACON_URL='')
        env.start()
        self.addCleanup(env.stop)
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        # A fixed private secret makes security regressions deterministic.
        secret = patch('rhonet.coordinator.secrets.token_bytes', return_value=bytes(range(32)))
        secret.start()
        self.addCleanup(secret.stop)
        self.coord = self.make_coord('fixed')
        clock = patch('rhonet.coordinator.now', return_value=self.coord.started_at + 1)
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.pk, self.addr = 'ab' * 32, '0x' + '11' * 20

    def make_coord(self, name):
        coord = Coordinator(self.spec, str(Path(self.tmp.name) / (name + '.sqlite')))
        self.addCleanup(coord.db.close)
        return coord

    def admit(self, coord):
        coord.admit(self.pk, self.addr, ec.ticket_solve(self.spec, coord.table, self.pk))

    def point(self, t, pk=None):
        result = ec.walk_to_dp(self.spec, self.coord.table,
                              *ec.derive_start(self.spec, pk or self.pk, t),
                              self.spec.w, 1 << self.spec.max_walk_len_log2)
        if result is None:
            return None
        a, b, (x, y), steps = result
        return dict(t=t, a=a, b=b, x=x, y=y, steps=steps)

    def advance(self, epoch):
        self.clock.return_value = self.coord.started_at + epoch * self.spec.epoch_seconds + 1
        self.coord.close_epoch()

    def test_sampled_miss_is_bounded_risk_and_mature_payment_is_final(self):
        self.admit(self.coord)
        root = merkle.build([])[0]
        beacon = self.coord.beacon_for(0)
        candidates = []
        seen = set()
        for t in range(100):
            dp = self.point(t)
            if dp and dp['x'] not in seen:
                candidates.append(dp)
                seen.add(dp['x'])
            if len(candidates) == 2:
                break
        ranked = sorted(candidates, key=lambda dp: ec.H(root, beacon, 'spot', self.pk, dp['t']))
        good, dp = ranked
        dp['a'] = (dp['a'] + 1) % self.spec.curve.n
        self.assertEqual(self.coord.submit(self.pk, sorted([good, dp], key=lambda d: d['t']))['accepted'], 2)
        self.advance(1)
        self.assertEqual(self.coord.miners_view()[0]['status'], 'active')
        self.assertEqual(self.coord.db.execute('SELECT checked FROM dps WHERE t=?', (dp['t'],)).fetchone(), (0,))
        self.advance(2)
        self.assertEqual(self.coord.miners_view()[0]['status'], 'active')
        self.assertEqual(self.coord.proof(self.addr, 0)['credited_steps'], 2 << self.spec.w)
        # Known entropy permits mixing honest selected points with unselected
        # forgeries. Sampling fixes count, not unpredictability; do not claim
        # that this strategy must be slashed.
        self.assertEqual(self.coord.status_view()['operator_collusion_fraud_bound'], 1.0)

    def test_dominant_miner_root_prediction_attack(self):
        count = 256
        root = merkle.build([merkle.leaf_hash(self.addr, count * (1 << self.spec.w))])[0]
        batch, seen = [], set()
        donor_t = 0
        for t in range(count):
            if int.from_bytes(ec.H(root, 'spot', self.pk, t), 'big') % self.spec.spot_check_rate == 0:
                dp = self.point(t)
                self.assertIsNotNone(dp)
                self.assertNotIn(dp['x'], seen)
            else:
                # Reuse a pool of distinguished coordinates from unrelated walks;
                # the attacker never performs its assigned walk for these t values.
                while True:
                    dp = self.point(donor_t, 'cd' * 32)
                    donor_t += 1
                    if dp and dp['x'] not in seen:
                        break
                dp.update(t=t, a=(dp['a'] + 1) % self.spec.curve.n)
                self.assertFalse(ec.dp_verify(self.spec, self.coord.table, self.pk, dp))
            seen.add(dp['x'])
            batch.append(dp)
        old = self.make_coord('old')
        old.started_at = self.coord.started_at
        for coord in (old, self.coord):
            self.admit(coord)
            self.assertEqual(coord.submit(self.pk, batch)['accepted'], count)
            self.assertEqual(coord.db.execute('SELECT next_t FROM miners').fetchone()[0], count)
        original_hash = ec.H
        def root_only(*parts):
            # H length-prefixes parts: dropping the beacon exactly reproduces
            # the old selector (adding b'' would NOT reproduce it).
            if len(parts) == 5 and parts[2] in ('spot', 'spot2'):
                return original_hash(root, *parts[2:])
            return original_hash(*parts)
        self.clock.return_value = self.coord.started_at + self.spec.epoch_seconds + 1
        with patch.object(ec, 'H', side_effect=root_only), patch.object(old, '_select_targets', side_effect=old._legacy_targets):
            old.close_epoch()
        self.assertEqual(old.miners_view()[0]['status'], 'active')
        self.assertGreater(old.miners_view()[0]['spot_checks'], 0)
        self.assertEqual(old.db.execute('SELECT root FROM epochs WHERE idx=0').fetchone()[0], root.hex())
        self.coord.close_epoch()
        self.assertEqual(self.coord.miners_view()[0]['status'], 'slashed')
        self.assertEqual(self.coord.db.execute('SELECT root FROM epochs WHERE idx=0').fetchone()[0], merkle.build([])[0].hex())

    def test_commit_reveal_and_public_reproduction(self):
        client = TestClient(build_app(self.coord))
        self.addCleanup(client.close)
        opened = client.get('/api/epochs').json()[0]
        self.assertEqual(opened['beacon_source'], 'commit-reveal')
        self.assertTrue(opened['beacon_commitment'])
        self.assertIsNone(opened['beacon_reveal'])
        self.assertEqual(client.get('/api/status').json()['epochs'][0], opened)
        restarted_open = self.make_coord('fixed')
        self.assertEqual(restarted_open.epochs_view()[0], opened)
        self.assertEqual(restarted_open.beacon_for(0), self.coord.beacon_for(0))
        self.admit(self.coord)
        seen = set()
        for t in range(256):
            dp = self.point(t)
            if dp and dp['x'] not in seen:
                seen.add(dp['x'])
                self.assertEqual(self.coord.submit(self.pk, [dp])['accepted'], 1)
        actual = []
        original_verify = ec.verify_segment
        def verify(spec, table, pk, dp, segment, opening):
            self.assertIsNotNone(next(e for e in client.get('/api/epochs').json() if e['idx'] == 0)['beacon_reveal'])
            actual.append((pk, dp['t']))
            return original_verify(spec, table, pk, dp, segment, opening)
        with patch.object(ec, 'verify_segment', side_effect=verify):
            self.advance(1)
        closed = next(e for e in client.get('/api/epochs').json() if e['idx'] == 0)
        self.assertEqual(ec.H(bytes.fromhex(closed['beacon_reveal'])).hex(), opened['beacon_commitment'])
        expected, published = [], []
        candidates = client.get('/api/epochs/0/audit?kind=candidates&limit=512').json()
        detail = client.get('/api/epochs/0/audit?limit=512').json()
        for tag, inputs in candidates['audit_inputs'].items():
            ranked = sorted((int.from_bytes(ec.H(bytes.fromhex(closed['audit_seed_root'][2:]), bytes.fromhex(closed['beacon_reveal']), tag, pk, t), 'big'), pk, t) for pk, t in inputs['pairs'])
            count = (len(ranked) + inputs['rate'] - 1) // inputs['rate']
            if tag == 'spot2' and ranked:
                oldest = min(ranked, key=lambda r: r[2])
                ranked = [oldest] + [r for r in ranked if r != oldest]
            expected.extend((pk, t) for _, pk, t in ranked[:count])
            published.extend(tuple(pair) for pair in detail['audit_inputs'][tag]['pairs'])
        self.assertCountEqual(actual, published)
        self.assertTrue(actual)
        self.assertCountEqual(actual, expected)
        self.assertTrue(closed['audit_complete'])
        restarted = self.make_coord('fixed')
        self.assertEqual(restarted.beacon_for(0).hex(), closed['beacon_reveal'])

    def test_legacy_epoch_migration_is_idempotent(self):
        path = str(Path(self.tmp.name) / 'legacy.sqlite')
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE epochs (idx INTEGER PRIMARY KEY, ts REAL NOT NULL, root TEXT NOT NULL, total_steps INTEGER NOT NULL, n_miners INTEGER NOT NULL, leaves TEXT NOT NULL)")
            db.execute("INSERT INTO epochs VALUES(-1,0,?,0,0,'[]')", ('00' * 32,))
        for _ in range(2):
            coord = self.make_coord('legacy')
            historical = next(e for e in coord.epochs_view() if e['idx'] == -1)
            self.assertTrue(historical['audit_complete'])
            self.assertIsNone(historical['beacon_source'])
            self.assertIsNone(historical['beacon_commitment'])
            self.assertIsNone(historical['beacon_reveal'])
            self.assertTrue(next(e for e in coord.epochs_view() if e['idx'] == 0)['beacon_commitment'])

    def test_http_lazy_cached_and_retry_after_failure(self):
        with patch.dict(os.environ, RHONET_BEACON_URL='https://beacon.example/{epoch}/{root}'):
            coord = self.make_coord('http')
        coord.started_at = self.coord.started_at
        with patch('rhonet.coordinator.urlopen') as fetch:
            coord.status_view()
            fetch.assert_not_called()
            self.clock.return_value = coord.started_at + self.spec.epoch_seconds + 1
            fetch.side_effect = TimeoutError('beacon unavailable')
            with self.assertRaises(TimeoutError):
                coord.close_epoch()
            record = next(e for e in coord.epochs_view() if e['idx'] == 0)
            self.assertFalse(record['audit_complete'])
            self.assertIsNone(record['beacon_reveal'])
            fetch.side_effect = lambda *a, **kw: BytesIO(json.dumps({'hash': '0x' + '42' * 32}).encode())
            coord.close_epoch()
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(fetch.call_args.kwargs, {'timeout': 5})
            self.assertIn('/0/' + record['sealed_root'][2:], fetch.call_args.args[0])
            self.assertEqual(coord.beacon_for(0), bytes.fromhex('42' * 32))
            restarted = self.make_coord('http')
            self.assertEqual(restarted.beacon_for(0), bytes.fromhex('42' * 32))
            self.assertEqual(fetch.call_count, 2)


    def test_drand_shape_and_a_constant_beacon_is_refused(self):
        """drand puts the value under "randomness", and a value that never changes
        is not a beacon: the audit would be predictable, so the epoch stays open."""
        with patch.dict(os.environ, RHONET_BEACON_URL='https://api.drand.sh/public/latest'):
            coord = self.make_coord('drand')
        coord.started_at = self.coord.started_at
        # drand's /info also carries a "hash" -- the chain identifier, a constant.
        # Reading it in preference to "randomness" would be a silent downgrade.
        body = {'round': 1, 'randomness': 'ab' * 32, 'hash': 'cd' * 32}
        with patch('rhonet.coordinator.urlopen') as fetch:
            fetch.side_effect = lambda *a, **kw: BytesIO(json.dumps(body).encode())
            self.clock.return_value = coord.started_at + self.spec.epoch_seconds + 1
            coord.close_epoch()
            self.assertEqual(coord.beacon_for(0), bytes.fromhex('ab' * 32))
            # The same value again in the next epoch must not be accepted.
            self.clock.return_value = coord.started_at + 2 * self.spec.epoch_seconds + 1
            with self.assertRaises(ValueError) as exc:
                coord.close_epoch()
            self.assertIn('repeated', str(exc.exception))
            self.assertFalse(next(e for e in coord.epochs_view() if e['idx'] == 1)['audit_complete'])
            # A fresh value closes it.
            body['randomness'] = 'ef' * 32
            coord.close_epoch()
            self.assertEqual(coord.beacon_for(1), bytes.fromhex('ef' * 32))


if __name__ == '__main__':
    unittest.main(verbosity=2)
