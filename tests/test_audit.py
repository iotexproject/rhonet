"""Offline C-1 regressions; run directly or with pytest."""
import random
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec, merkle
from rhonet.coordinator import Coordinator, SCHEMA, T_WINDOW


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        secret = patch('rhonet.coordinator.secrets.token_bytes', return_value=bytes(range(32)))
        secret.start()
        self.addCleanup(secret.stop)
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'audit.sqlite'))
        self.addCleanup(self.coord.db.close)
        # Freeze epoch zero until each test explicitly crosses its boundary.
        self.clock = patch('rhonet.coordinator.now', return_value=self.coord.started_at + 1)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.seen = set()
        self.rng = random.Random(12345)

    def admit(self, pk, address):
        ticket = ec.ticket_solve(self.spec, self.coord.table, pk)
        self.assertIsNotNone(ticket)
        self.coord.admit(pk, address, ticket)

    def dp(self, pk, t, fake=False):
        start = ec.derive_start(self.spec, pk, t)
        res = ec.walk_to_dp(self.spec, self.coord.table, *start, self.spec.w,
                            1 << self.spec.max_walk_len_log2)
        if res is None or res[2][0] in self.seen:
            return None
        a, b, (x, y), steps = res
        self.seen.add(x)  # Isolate epoch audits from collision detection.
        if fake:
            a = (a + self.rng.randrange(1, self.spec.curve.n)) % self.spec.curve.n
            b = self.rng.randrange(self.spec.curve.n)
        return dict(x=x, y=y, a=a, b=b, t=t, steps=steps)

    def old_selector(self, pk, t):
        return int.from_bytes(ec.H(self.spec.round_id, 'spot', pk, t), 'big') % self.spec.spot_check_rate

    def miner(self, pk):
        return self.coord.db.execute(
            'SELECT status, credited_steps, next_t, t_gaps FROM miners WHERE pubkey=?', (pk,)).fetchone()

    def close(self, epochs=1):
        self.coord.started_at -= epochs * self.spec.epoch_seconds
        self.coord.close_epoch()

    def test_T1_evasive_adversary_is_slashed(self):
        honest, evil = 'ab' * 32, 'cd' * 32
        self.admit(honest, '0x' + '11' * 20)
        self.admit(evil, '0x' + '22' * 20)
        good, bad = [], []
        for t in range(T_WINDOW):
            if len(good) < 16:
                dp = self.dp(honest, t)
                if dp:
                    good.append(dp)
            if len(bad) < 256 and self.old_selector(evil, t) != 0:
                dp = self.dp(evil, t, fake=True)
                if dp:
                    bad.append(dp)
            if len(good) == 16 and len(bad) == 256:
                break
        self.assertEqual(len(bad), 256)
        for pk, batch in ((honest, good), (evil, bad)):
            result = self.coord.submit(pk, batch)
            self.assertEqual(result['accepted'], len(batch))
            self.assertEqual(result['checked'], 0)
            self.assertEqual(self.miner(pk)[0], 'active')
        self.close(2)  # Also exercises catching up a missed epoch zero.
        self.assertEqual(self.miner(evil)[:2], ('slashed', 0))
        self.assertEqual(self.miner(honest)[0], 'active')
        root = bytes.fromhex(self.coord.db.execute('SELECT audit_seed_root FROM epochs WHERE idx=0').fetchone()[0])
        targets = [dp for dp in bad if int.from_bytes(ec.H(root, self.coord.beacon_for(0), 'spot', evil, dp['t']), 'big') % self.spec.spot_check_rate == 0]
        self.assertTrue(targets)
        failures = [e for e in self.coord.events_view(1000) if e['kind'] == 'audit_failed']
        self.assertTrue(any(e['detail']['pubkey'] == evil[:16] and e['detail']['epoch'] == 0 for e in failures))

    def test_old_nonzero_selector_is_caught_after_close(self):
        pk, address = 'ef' * 32, '0x' + '33' * 20
        self.admit(pk, address)
        # A one-DP fixture whose root and private test beacon select the old-selector
        # evasion. No selector or replay is mocked in either attack regression.
        root, _ = merkle.build([])
        bad = None
        for t in range(T_WINDOW):
            if self.old_selector(pk, t) and int.from_bytes(ec.H(root, self.coord.beacon_for(0), 'spot', pk, t), 'big') % self.spec.spot_check_rate == 0:
                bad = self.dp(pk, t, fake=True)
                if bad:
                    break
        self.assertIsNotNone(bad)
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            result = self.coord.submit(pk, [bad])
            verify.assert_not_called()
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(self.miner(pk)[0], 'active')
        self.close()
        self.assertEqual(self.miner(pk)[:2], ('slashed', 0))

    def test_reordering_and_gap_accounting(self):
        pk = '12' * 32
        self.admit(pk, '0x' + '44' * 20)
        points = [self.dp(pk, t) for t in (0, 1, 2, T_WINDOW + 2)]
        self.assertTrue(all(points))
        self.coord.submit(pk, [points[2], points[0]])
        self.assertEqual(self.miner(pk)[2:], (1, 0))
        dup = self.coord.submit(pk, [points[2]])
        self.assertEqual(dup['rejected'], [(0, 'duplicate')])
        self.coord.submit(pk, [points[3]])
        # Missing identifiers remain retryable even far behind newer work.
        self.assertEqual(self.miner(pk)[2:], (1, 0))
        old = self.coord.submit(pk, [points[1]])
        self.assertEqual(old['accepted'], 1)
        self.assertEqual(self.miner(pk)[2:], (3, 0))

    def test_gaps_are_not_evidence_of_fraud(self):
        pk = '34' * 32
        self.admit(pk, '0x' + '55' * 20)
        batch = []
        for t in range(1000):
            dp = self.dp(pk, t)
            if dp:
                batch.append(dp)
            if len(batch) == 63:
                break
        self.coord.submit(pk, batch)
        for t in range(T_WINDOW * 2, T_WINDOW * 3):
            dp = self.dp(pk, t)
            if dp:
                break
        extra = None
        for later in range(t + 1, t + 100):
            extra = self.dp(pk, later)
            if extra:
                break
        self.assertIsNotNone(extra)
        result = self.coord.submit(pk, [dp, extra])
        self.assertEqual(result['accepted'], 2)
        self.assertFalse(result.get('slashed'))
        self.assertEqual(self.miner(pk)[:2], ('active', 65 << self.spec.w))

    def test_fractional_primary_and_oldest_delayed_pass(self):
        pk = '56' * 32
        self.admit(pk, '0x' + '66' * 20)
        self.coord.db.executemany(
            'INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch,checked) VALUES(?,?,?,?,?,?,?,?,?,?)',
            [(pk, t, '0', '0', '0', '0', 1, 0, 0, 0) for t in range(600)])
        self.coord.db.commit()
        original_hash = ec.H
        def selector(*parts):
            if len(parts) != 5 or parts[2] not in ("spot", "spot2"):
                return original_hash(*parts)
            return (600 - parts[-1]).to_bytes(32, 'big')
        primary = (600 + self.spec.spot_check_rate - 1) // self.spec.spot_check_rate
        remaining = 600 - primary
        delayed = (remaining + 8 * self.spec.spot_check_rate - 1) // (8 * self.spec.spot_check_rate)
        with patch.object(ec, 'H', side_effect=selector), patch.object(ec, 'dp_verify', return_value=True) as verify:
            self.coord.audit_epoch(0, b'root')
            self.assertEqual(verify.call_count, primary)
            self.assertEqual([c.args[3]['t'] for c in verify.call_args_list], list(range(599, 599 - primary, -1)))
            verify.reset_mock()
            self.coord.audit_delayed(0, b'root')
            verify.assert_not_called()
            self.coord.audit_delayed(1, b'new-root')
            self.assertEqual(verify.call_count, delayed)
            self.assertEqual(verify.call_args_list[0].args[3]['t'], 0)
            self.assertEqual(self.coord.db.execute('SELECT COUNT(*) FROM dps WHERE checked=1').fetchone()[0], primary + delayed)
        with patch.object(ec, 'dp_verify', return_value=False):
            self.coord.audit_delayed(2, b'later-root')
        self.assertEqual(self.miner(pk)[:2], ('slashed', 0))

    def test_multiple_failures_emit_one_slash_with_evidence(self):
        pk = '78' * 32
        self.admit(pk, '0x' + '77' * 20)
        bad = []
        for t in range(100):
            dp = self.dp(pk, t, fake=True)
            if dp:
                bad.append(dp)
            if len(bad) == 11:
                break
        self.assertEqual(self.coord.submit(pk, bad)['accepted'], 11)
        with patch.object(self.spec, 'spot_check_rate', 1), patch.object(ec, 'H', return_value=bytes(32)):
            self.coord.audit_epoch(0, b'root')
        events = self.coord.events_view(1000)
        for kind in ('slashed', 'audit_failed'):
            matching = [e['detail'] for e in events if e['kind'] == kind]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0]['failures'], 11)
            self.assertEqual(matching[0]['first_failing_t'], bad[0]['t'])
            self.assertEqual(matching[0]['epoch'], 0)
            self.assertEqual(matching[0]['evidence']['claimed'],
                             {k: str(bad[0][k]) for k in ('a', 'b', 'x', 'y')})
        self.assertEqual(self.coord.miners_view()[0]['spot_fails'], 1)

    def test_legacy_schema_migration_is_idempotent(self):
        path = str(Path(self.tmp.name) / 'legacy.sqlite')
        legacy = '\n'.join(line for line in SCHEMA.splitlines()
                           if not line.strip().startswith(('next_t INTEGER', 'epoch INTEGER', 'slashed INTEGER', 'last_seq INTEGER', 'CREATE INDEX IF NOT EXISTS dps_epoch_checked')))
        db = sqlite3.connect(path)
        db.executescript(legacy)
        db.execute("INSERT INTO dps VALUES('0','0','0','0','legacy',7,1,0,0)")
        db.commit()
        db.close()
        for _ in range(2):
            coord = Coordinator(self.spec, path)
            try:
                self.assertEqual(coord.db.execute('SELECT epoch FROM dps').fetchone()[0], -1)
                columns = {r[1] for r in coord.db.execute('PRAGMA table_info(miners)')}
                self.assertTrue({'next_t', 't_gaps', 'last_seq'} <= columns)
                self.assertEqual(coord.db.execute('SELECT slashed FROM dps').fetchone()[0], 0)
                self.assertTrue(coord.db.execute("SELECT 1 FROM sqlite_master WHERE name='dps_epoch_checked'").fetchone())
            finally:
                coord.db.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
