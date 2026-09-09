"""Interactive protocol regressions use the production coordinator directly."""
import concurrent.futures
import dataclasses
import itertools
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi import HTTPException
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rhonet import ec, merkle, walker
from rhonet.coordinator import Coordinator, build_app


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = dataclasses.replace(ec.RoundSpec.load('rounds/r32.json'), audit_response_seconds=2)
        self.env = patch.dict(os.environ, RHONET_BEACON_URL='').start()
        self.addCleanup(patch.stopall)
        self.path = str(Path(self.tmp.name) / 'round.sqlite')
        self.coord = Coordinator(self.spec, self.path)
        self.addCleanup(self.coord.db.close)
        self.clock = patch('rhonet.coordinator.now', return_value=self.coord.started_at+1).start()
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([42])*32)
        self.pk = walker.pubkey_hex(self.key)
        self.coord.admit(self.pk, '0x'+'ab'*20, ec.ticket_solve(self.spec, self.coord.table, self.pk))
        self.miner = ec.BatchWalker(self.spec, self.coord.table, self.pk, 16, itertools.count().__next__)
        self.seen = set()

    def points(self, count):
        out = []
        while len(out) < count:
            for dp in self.miner.step():
                if dp['x'] not in self.seen:
                    self.seen.add(dp['x'])
                    out.append(dp)
                    if len(out) == count:
                        return out

    def close(self, epoch=1):
        self.clock.return_value = self.coord.started_at + epoch*self.spec.epoch_seconds+1
        self.coord.close_epoch()

    def answer(self):
        for target in self.coord.audit_targets(self.pk):
            self.coord.answer_audit(self.pk, target['epoch'], target['t'],
                                    self.miner.open_segment(target['t'], target['segment']))

    def test_every_segment_and_tampering(self):
        dp = max(self.points(10), key=lambda d:d['steps'])
        segments = (dp['steps']+(1<<self.spec.v)-1)>>self.spec.v
        self.assertGreater(segments, 3)
        for segment in range(segments):
            opening = self.miner.open_segment(dp['t'], segment)
            ok, steps = ec.verify_segment(self.spec, self.coord.table, self.pk, dp, segment, opening)
            self.assertTrue(ok)
            self.assertLessEqual(steps, 1<<self.spec.v)
            opening['end']['proof'][0] = 'ff'*32
            self.assertEqual(ec.verify_segment(self.spec, self.coord.table, self.pk, dp, segment, opening), (False, 0))
        self.assertFalse(ec.verify_segment(self.spec, self.coord.table, self.pk, dict(dp, checkpoint_root='00'*32), 0,
                                          self.miner.open_segment(dp['t'], 0))[0])

    def test_valid_merkle_proof_does_not_replace_replay_or_curve_checks(self):
        dp = max(self.points(8), key=lambda d:d['steps'])
        points = [list(p) for p in self.miner.checkpoints[dp['t']]]
        points[1] = points[2]  # Valid curve point/coefficients, wrong transition.
        changed = dict(dp, checkpoint_root=ec.checkpoint_root(points))
        ok, work = ec.verify_segment(self.spec, self.coord.table, self.pk, changed, 0,
                                     ec.checkpoint_opening(points, 0))
        self.assertFalse(ok)
        self.assertEqual(work, 1<<self.spec.v)
        points[1] = list(points[1])
        while self.spec.curve.on_curve(tuple(points[1][2:])):
            points[1][2] = (points[1][2]+1) % self.spec.curve.p
        changed['checkpoint_root'] = ec.checkpoint_root(points)
        self.assertEqual(ec.verify_segment(self.spec, self.coord.table, self.pk, changed, 0,
                                          ec.checkpoint_opening(points,0)), (False, 0))

    def test_commitment_required_and_signed_opening(self):
        dp, = self.points(1)
        bare = dict(dp); bare.pop('checkpoint_root')
        self.assertEqual(self.coord.submit(self.pk, [bare])['accepted'], 0)
        client = TestClient(build_app(self.coord))
        self.addCleanup(client.close)
        body = walker.signed(self.key, dict(round_id=self.spec.round_id, pubkey=self.pk, epoch=0, seq=1, dps=[dp]))
        changed = dict(body, dps=[dict(dp, checkpoint_root='ff'*32)])
        self.assertEqual(client.post('/api/submit', json=changed).status_code, 401)
        self.assertEqual(client.post('/api/submit', json=body).json()['accepted'], 1)
        self.close()
        self.assertFalse(self.coord.epochs_view()[-1]['audit_complete'])
        target, = client.get('/api/audit/targets', params={'pubkey':self.pk}).json()
        opening = walker.signed(self.key, dict(round_id=self.spec.round_id, pubkey=self.pk, audit_epoch=0,
                                             t=target['t'], opening=self.miner.open_segment(target['t'],target['segment'])))
        self.assertEqual(client.post('/api/audit/open', json=dict(opening, sig='00')).status_code, 401)
        self.assertEqual(client.post('/api/audit/open', json=opening).json()['result'], 'passed')
        before = self.coord.status_view()['verification_replay_steps']
        self.assertEqual(client.post('/api/audit/open', json=opening).json()['result'], 'passed')
        self.assertEqual(self.coord.status_view()['verification_replay_steps'], before)
        self.coord.close_epoch()
        self.assertEqual(self.coord.status_view()['total_payable_steps'], 1<<self.spec.w)

    def test_restart_keeps_target_and_silence_forfeits_only_pending_epoch(self):
        self.coord.submit(self.pk, self.points(3))
        self.close()
        targets = self.coord.audit_targets(self.pk)
        restarted = Coordinator(self.spec, self.path)
        try:
            self.assertEqual(restarted.audit_targets(self.pk), targets)
        finally:
            restarted.db.close()
        self.answer(); self.coord.close_epoch()
        paid = self.coord.status_view()['total_payable_steps']
        proof = self.coord.proof('0x'+'ab'*20, 0)
        for epoch in range(1, 4):
            self.coord.submit(self.pk, self.points(1))
            self.close(epoch+1)
            self.clock.return_value += self.spec.audit_response_seconds+1
            self.coord.close_epoch()
            self.assertEqual(self.coord.status_view()['total_payable_steps'], paid)
            self.assertEqual(self.coord.miners_view()[0]['status'], 'slashed' if epoch==3 else 'active')
        self.assertEqual(self.coord.proof('0x'+'ab'*20, 0), proof)

    def test_TD_beacon_aware_all_forgery_selector_cannot_lower_count(self):
        # Grant the attacker exactly the operator's opening secret and seed.
        secret = bytes.fromhex(self.coord._get_state('beacon_secret:0'))
        root = merkle.build([])[0]
        candidates = self.points(80)
        # Choose only high hash ranks, the strategy that defeats modulo sampling.
        selected = sorted(candidates, key=lambda dp:ec.H(root, secret, 'spot', self.pk, dp['t']))[-32:]
        for dp in selected:
            dp['a'] = (dp['a']+1) % self.spec.curve.n
        self.assertEqual(self.coord.submit(self.pk, selected)['accepted'], 32)
        self.close()
        self.assertEqual(len(self.coord.audit_targets(self.pk)), 1)
        self.answer(); self.coord.close_epoch()
        self.assertEqual(self.coord.miners_view()[0]['status'], 'slashed')
        self.assertEqual(self.coord.status_view()['total_payable_steps'], 0)

    def test_parallel_replay_reports_actual_worker_processes(self):
        self.coord.spec = dataclasses.replace(self.spec, spot_check_rate=1)
        self.coord.submit(self.pk, self.points(16))
        self.close()
        targets = self.coord.audit_targets(self.pk)
        # Spawn startup must not dominate these intentionally tiny toy jobs.
        import time
        from rhonet.coordinator import audit_pool
        warmup = [audit_pool().submit(time.sleep, .5) for _ in range(4)]
        for future in warmup:
            future.result()
        def answer(target):
            return self.coord.answer_audit(self.pk, target['epoch'], target['t'],
                self.miner.open_segment(target['t'], target['segment']))
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            self.assertTrue(all(r['result']=='passed' for r in pool.map(answer, targets)))
        status = self.coord.status_view()
        self.assertGreaterEqual(len(status['verifier_worker_pids']), 2)
        self.assertNotIn(os.getpid(), status['verifier_worker_pids'])
        self.assertGreater(status['verifier_steps_per_second'], 0)

    def test_fractional_fraud_bound_matches_exhaustive_enumeration(self):
        import math
        for k in range(1, 12):
            for forged in range(k+1):
                for audited in range(k+1):
                    exact = math.comb(k-forged, audited)/math.comb(k,audited) if audited<=k-forged else 0
                    self.assertAlmostEqual(ec.audit_fraud_bound(k, forged, audited), exact)
                    # Segment sampling is weaker than checking an entire walk.
                    self.assertGreaterEqual(ec.audit_fraud_bound(k, forged, audited, 8)+1e-12, exact)

    def test_funded_round_requires_external_beacon(self):
        funded = dataclasses.replace(self.spec, funded=True)
        path = str(Path(self.tmp.name)/'funded.sqlite')
        with self.assertRaisesRegex(ValueError, 'requires RHONET_BEACON_URL'):
            Coordinator(funded, path)
        self.assertFalse(Path(path).exists())
        with patch.dict(os.environ, RHONET_BEACON_URL='https://beacon.example/{epoch}/{root}'):
            coord = Coordinator(funded, path)
            try:
                self.assertEqual(coord.status_view()['beacon_mode'], 'external')
            finally:
                coord.db.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
