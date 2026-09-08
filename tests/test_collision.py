"""Offline C-2 regressions; run directly or with pytest."""
import concurrent.futures
import dataclasses
import json
import threading
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec
from rhonet.coordinator import Coordinator


class CollisionTests(unittest.TestCase):
    honest = 'ab' * 32
    partner = 'cd' * 32
    evil = 'ef' * 32

    @classmethod
    def setUpClass(cls):
        cls.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        table = ec.walk_table(cls.spec)
        seen = {cls.honest: {}, cls.partner: {}}
        # Find a real cross-identity collision with deterministic, sequential starts.
        for t in range(4096):
            for pk, other in ((cls.honest, cls.partner), (cls.partner, cls.honest)):
                res = ec.walk_to_dp(cls.spec, table, *ec.derive_start(cls.spec, pk, t),
                                    cls.spec.w, 1 << cls.spec.max_walk_len_log2)
                if res is None:
                    continue
                a, b, (x, y), steps = res
                dp = dict(a=a, b=b, x=x, y=y, steps=steps, t=t)
                prior = seen[other].get(x)
                if prior and ec.solve_collision_detail(cls.spec, dp, prior)['kind'] == 'solved':
                    cls.pair = {pk: dp, other: prior}
                    return
                seen[pk][x] = dp
        raise AssertionError('No deterministic collision found')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.coord = Coordinator(self.spec, str(Path(self.tmp.name) / 'collision.sqlite'))
        self.addCleanup(self.coord.db.close)
        self.clock = patch('rhonet.coordinator.now', return_value=self.coord.started_at + 1)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        for i, pk in enumerate((self.honest, self.partner, self.evil), 1):
            # Seed admitted identities to isolate collision handling from ticket PoW.
            self.coord.db.execute(
                'INSERT INTO miners(pubkey,payout_addr,ticket,admitted_at,admitted_epoch) VALUES(?,?,?,?,?)',
                (pk, '0x' + f'{i:040x}', '{}', self.coord.started_at, 0))
        self.coord.db.commit()
        self.h = dict(self.pair[self.honest])
        self.p = dict(self.pair[self.partner])

    def store(self, pk, dp, checked=0):
        self.coord.db.execute(
            'INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch,checked) VALUES(?,?,?,?,?,?,?,?,?,?)',
            (pk, dp['t'], *(str(dp[k]) for k in ('x', 'y', 'a', 'b')), dp['steps'],
             self.coord.started_at, 0, checked))
        self.coord.db.execute(
            'UPDATE miners SET credited_steps=credited_steps+?, dps=dps+1 WHERE pubkey=?',
            (1 << self.spec.w, pk))
        self.coord.db.commit()

    def miner(self, pk):
        return self.coord.db.execute(
            'SELECT status,credited_steps FROM miners WHERE pubkey=?', (pk,)).fetchone()

    def exists(self, pk, t):
        return self.coord.db.execute('SELECT 1 FROM dps WHERE pubkey=? AND t=?', (pk, t)).fetchone() is not None

    def events(self, kind):
        return [e['detail'] for e in self.coord.events_view(1000) if e['kind'] == kind]

    def poison(self):
        return dict(self.h, b=(self.h['b'] + 1) % self.spec.curve.n)

    def forged_audit_point(self):
        self.coord.spec = dataclasses.replace(self.spec, spot_check_rate=1)
        for t in range(100):
            result = ec.walk_to_dp(self.spec, self.coord.table,
                                  *ec.derive_start(self.spec, self.evil, t),
                                  self.spec.w, ec.MAX_REPLAY_STEPS(self.spec))
            if result and result[2][0] != self.h['x']:
                a, b, (x, y), steps = result
                return dict(t=t, a=(a + 1) % self.spec.curve.n, b=b, x=x, y=y, steps=steps)
        self.fail('no forged fixture')

    def test_audited_forfeit_has_no_epoch_leaf_or_proof(self):
        bad = self.forged_audit_point()
        self.assertEqual(self.coord.submit(self.evil, [bad])['accepted'], 1)
        self.coord.started_at -= self.spec.epoch_seconds
        self.coord.close_epoch()
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        leaves = json.loads(self.coord.db.execute('SELECT leaves FROM epochs WHERE idx=0').fetchone()[0])
        self.assertNotIn('0x' + f'{3:040x}', [a for a, _ in leaves])
        with self.assertRaises(HTTPException) as exc:
            self.coord.proof('0x' + f'{3:040x}', 0)
        self.assertEqual(exc.exception.status_code, 404)

    def test_collision_drains_open_epoch_backlog(self):
        bad = self.forged_audit_point()
        self.coord.spec = dataclasses.replace(self.spec, spot_check_rate=64)
        self.coord.submit(self.evil, [bad])
        self.store(self.partner, self.p)
        self.assertEqual(self.coord.current_epoch(), 0)
        result = self.coord.submit(self.honest, [self.h])
        self.assertTrue(result['solved']['verified'])
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        self.assertNotIn(self.evil, [p['pubkey'] for p in result['solved']['payouts']])
        self.assertEqual(self.coord.status_view()['audit_backlog_steps'], 0)
        self.assertTrue(self.coord.epochs_view()[-1]['audit_complete'])

    def test_collision_waits_for_pending_audit_before_payouts(self):
        bad = self.forged_audit_point()
        self.coord.submit(self.evil, [bad])
        self.store(self.partner, self.p, checked=1)
        self.coord.started_at -= self.spec.epoch_seconds
        entered, release, collided = threading.Event(), threading.Event(), threading.Event()
        original = ec.dp_verify
        def verify(spec, table, pk, dp):
            if pk == self.evil:
                entered.set()
                if not release.wait(10):
                    raise RuntimeError('audit release timeout')
            if pk == self.honest:
                collided.set()
            return original(spec, table, pk, dp)
        with patch.object(ec, 'dp_verify', side_effect=verify), concurrent.futures.ThreadPoolExecutor(2) as pool:
            audit = pool.submit(self.coord.close_epoch)
            try:
                self.assertTrue(entered.wait(5))
                collision = pool.submit(self.coord.submit, self.honest, [self.h])
                self.assertTrue(collided.wait(5))
                # Old code completes the payout table while replay is paused.
                try:
                    collision.result(timeout=0.2)
                except concurrent.futures.TimeoutError:
                    pass
            finally:
                release.set()
            audit.result(timeout=10)
            solution = collision.result(timeout=10)['solved']
        self.assertTrue(solution['verified'])
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        self.assertNotIn(self.evil, [p['pubkey'] for p in solution['payouts']])
        self.assertTrue(self.coord.epochs_view()[-1]['audit_complete'])

    def test_T2_poisoned_stored_point_is_attributed_and_deleted(self):
        poisoned = self.poison()
        self.store(self.evil, poisoned)
        result = self.coord.submit(self.honest, [self.h])
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        failures = self.events('collision_replay_failed')
        self.assertEqual(len(failures), 1)
        evidence = failures[0]
        self.assertEqual(evidence['pubkey'], self.evil[:16])
        self.assertEqual(evidence['t'], poisoned['t'])
        self.assertEqual(evidence['steps'], poisoned['steps'])
        self.assertEqual(evidence['claimed'], {k: str(poisoned[k]) for k in ('a', 'b', 'x', 'y')})
        a, b, (x, y) = ec.replay(self.spec, self.coord.table,
                                *ec.derive_start(self.spec, self.evil, poisoned['t']), poisoned['steps'])
        self.assertEqual(evidence['replayed'], dict(a=str(a), b=str(b), x=str(x), y=str(y)))
        self.assertEqual(self.miner(self.honest), ('active', 1 << self.spec.w))
        self.assertEqual(result['accepted'], 1)
        self.assertTrue(self.exists(self.honest, self.h['t']))
        self.assertEqual(self.coord.status, 'open')
        # Pre-fix behavior silently leaves this poisoned record in the table.
        self.assertFalse(self.exists(self.evil, poisoned['t']))
        self.assertFalse(self.coord.status_view()['halted'])

    def test_bad_k_halts_verified_pair_and_rejects_further_intake(self):
        self.store(self.partner, self.p, checked=1)
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify, patch.object(
                ec, 'solve_collision_detail', return_value={'kind': 'bad_k', 'k': 1}) as solve:
            result = self.coord.submit(self.honest, [self.h, dict(self.h, t=self.h['t'] + 1)])
        self.assertEqual(verify.call_count, 2)
        self.assertEqual([c.args[2] for c in verify.call_args_list], [self.honest, self.partner])
        solve.assert_called_once()
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(result['status'], 'halted_for_review')
        self.assertEqual(self.coord.status, 'halted_for_review')
        self.assertTrue(self.coord.status_view()['halted'])
        incident, = self.events('halted_for_review')
        self.assertEqual(incident['k'], '1')
        self.assertEqual({s['pubkey'] for s in incident['segments']}, {self.honest[:16], self.partner[:16]})
        for segment in incident['segments']:
            self.assertEqual(segment['claimed'], segment['replayed'])
        self.assertEqual(self.coord.submit(self.honest, [self.h])['accepted'], 0)
        with self.assertRaises(HTTPException) as exc:
            self.coord.admit(self.evil, '0x' + '11' * 20, {})
        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(self.miner(self.honest)[0], 'active')
        self.assertEqual(self.miner(self.partner)[0], 'active')

    def test_degenerate_collisions_are_counted_without_slashing(self):
        # Stub only replay validity to isolate zero-denominator handling;
        # the actual solver is exercised here and separately below.
        for pk, offset in ((self.partner, 1), (self.evil, 2)):
            self.store(pk, dict(self.h, a=(self.h['a'] + offset) % self.spec.curve.n))
        with patch.object(ec, 'dp_verify', return_value=True) as verify:
            result = self.coord.submit(self.honest, [self.h])
        self.assertEqual(verify.call_count, 4)
        self.assertEqual(result['accepted'], 1)
        events = self.events('degenerate_collision')
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e['kind'] == 'degenerate_same_y' for e in events))
        self.assertEqual(self.coord._get_state('degenerate_collisions'), 2)
        self.assertEqual(self.coord.status_view()['degenerate_collisions'], 2)
        self.assertEqual(self.coord.status, 'open')
        self.assertTrue(all(self.miner(pk)[0] == 'active' for pk in (self.honest, self.partner, self.evil)))

    def test_checked_poison_is_removed_and_remaining_collision_solves(self):
        self.store(self.evil, self.poison(), checked=1)
        self.store(self.partner, self.p, checked=1)
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            result = self.coord.submit(self.honest, [self.h])
        self.assertEqual(verify.call_count, 4)
        self.assertTrue(result['solved']['verified'])
        self.assertFalse(self.exists(self.evil, self.h['t']))
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        self.assertEqual(self.miner(self.honest)[0], 'active')

    def test_invalid_incoming_is_removed_and_loses_all_credit(self):
        self.store(self.partner, self.p)
        self.coord.db.execute('UPDATE miners SET credited_steps=999 WHERE pubkey=?', (self.honest,))
        self.coord.db.commit()
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            result = self.coord.submit(self.honest, [self.poison()])
        self.assertEqual(verify.call_count, 2)
        self.assertTrue(result['slashed'])
        self.assertEqual(result['accepted'], 0)
        self.assertEqual(self.miner(self.honest), ('slashed', 0))
        self.assertFalse(self.exists(self.honest, self.h['t']))
        self.assertTrue(self.exists(self.partner, self.p['t']))
        self.assertEqual(self.miner(self.partner)[0], 'active')
        self.assertEqual(self.events('collision_replay_failed')[0]['pubkey'], self.honest[:16])

    def test_both_invalid_are_replayed_slashed_and_removed(self):
        self.store(self.evil, dict(self.h, a=(self.h['a'] + 1) % self.spec.curve.n))
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            result = self.coord.submit(self.honest, [self.poison()])
        self.assertEqual(verify.call_count, 2)
        self.assertTrue(result['slashed'])
        for pk in (self.honest, self.evil):
            self.assertEqual(self.miner(pk), ('slashed', 0))
            self.assertFalse(self.exists(pk, self.h['t']))
        event, = self.events('collision_both_invalid')
        self.assertEqual({s['pubkey'] for s in event['segments']}, {self.honest[:16], self.evil[:16]})
        self.assertTrue(all(s['t'] == self.h['t'] for s in event['segments']))

    def test_copier_arrives_first_and_victim_keeps_credit(self):
        self.assertFalse(ec.dp_verify(self.spec, self.coord.table, self.evil, self.h))
        self.assertTrue(ec.dp_verify(self.spec, self.coord.table, self.honest, self.h))
        self.assertEqual(self.coord.submit(self.evil, [self.h])['accepted'], 1)
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            result = self.coord.submit(self.honest, [self.h])
        self.assertEqual(verify.call_count, 2)
        self.assertEqual([c.args[2] for c in verify.call_args_list], [self.honest, self.evil])
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        self.assertEqual(self.miner(self.honest), ('active', 1 << self.spec.w))
        self.assertFalse(self.exists(self.evil, self.h['t']))
        self.assertTrue(self.exists(self.honest, self.h['t']))

    def test_copier_arrives_second_and_victim_keeps_credit(self):
        self.store(self.honest, self.h)
        with patch.object(ec, 'dp_verify', wraps=ec.dp_verify) as verify:
            result = self.coord.submit(self.evil, [self.h])
        self.assertEqual(verify.call_count, 2)
        self.assertTrue(result['slashed'])
        self.assertEqual(self.miner(self.evil), ('slashed', 0))
        self.assertEqual(self.miner(self.honest), ('active', 1 << self.spec.w))

    def test_capacity_deferred_collision_survives_retry_and_restart(self):
        self.store(self.partner, self.p)
        with patch.object(self.coord, 'quota', return_value=0):
            result = self.coord.submit(self.honest, [self.h])
        self.assertEqual(result['retry_indices'], [0])
        self.assertFalse(self.exists(self.honest, self.h['t']))
        restarted = Coordinator(self.spec, str(Path(self.tmp.name) / 'collision.sqlite'))
        try:
            result = restarted.submit(self.honest, [self.h])
            self.assertTrue(result['solved']['verified'])
            self.assertEqual({p['pubkey'] for p in result['solved']['payouts']},
                             {self.honest, self.partner})
            self.assertEqual(restarted.status_view()['slashed'], 0)
        finally:
            restarted.db.close()

    def test_collision_detail_arithmetic_and_compatibility(self):
        n, p = self.spec.curve.n, self.spec.curve.p
        solved = ec.solve_collision_detail(self.spec, self.h, self.p)
        self.assertEqual(solved['kind'], 'solved')
        self.assertEqual(ec.solve_collision(self.spec, self.h, self.p), solved['k'])
        opposite = dict(self.p, a=(-self.p['a']) % n, b=(-self.p['b']) % n, y=(-self.p['y']) % p)
        self.assertEqual(ec.solve_collision_detail(self.spec, self.h, opposite), solved)
        for dp, kind in ((dict(self.h), 'degenerate_same_y'),
                         (dict(self.h, a=(-self.h['a']) % n, b=(-self.h['b']) % n,
                               y=(-self.h['y']) % p), 'degenerate_opposite_y')):
            self.assertEqual(ec.solve_collision_detail(self.spec, self.h, dp), {'kind': kind})
            self.assertIsNone(ec.solve_collision(self.spec, self.h, dp))
        bad = dict(self.h, a=(self.h['a'] + 1) % n)
        self.assertEqual(ec.solve_collision_detail(self.spec, bad, self.p)['kind'], 'bad_k')
        self.assertIsNone(ec.solve_collision(self.spec, bad, self.p))


if __name__ == '__main__':
    unittest.main(verbosity=2)
