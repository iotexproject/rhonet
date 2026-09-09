"""Final hardening regressions; run directly or under pytest."""
import concurrent.futures
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import coordinator as module, ec, walker
from protocol_helpers import Coordinator


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.path = str(Path(self.tmp.name) / 'hardening.sqlite')
        self.coord = Coordinator(self.spec, self.path)
        self.addCleanup(self.coord.db.close)
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([42]) * 32)
        self.pk = walker.pubkey_hex(self.key)
        self.addr = '0x' + 'ab' * 20
        self.ticket = ec.ticket_solve(self.spec, self.coord.table, self.pk)
        self.clock = patch.object(module, 'now', return_value=self.coord.started_at + 1)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def body(self, seq=0, **fields):
        return walker.signed(self.key, dict(round_id=self.spec.round_id, pubkey=self.pk,
                                          epoch=self.coord.current_epoch(), seq=seq, **fields))

    def admit(self):
        self.coord.admit(self.pk, self.addr, self.ticket)

    def test_key_exclusive_creation_and_existing_key(self):
        path = Path(self.tmp.name) / 'miner.key'
        original = os.open
        def create(name, flags, mode):
            self.assertEqual(flags, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
            self.assertEqual(mode, 0o600)
            fd = original(name, flags, mode)
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
            return fd
        with patch.object(walker.os, 'open', side_effect=create) as opening:
            first = walker.load_or_create_key(str(path))
            second = walker.load_or_create_key(str(path))
        self.assertEqual(opening.call_count, 2)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(walker.pubkey_hex(first), walker.pubkey_hex(second))

    def test_signed_replay_staleness_and_restart(self):
        self.admit()
        client = TestClient(module.build_app(self.coord))
        body = self.body(seq=10, dps=[])
        self.assertEqual(client.post('/api/submit', json=body).status_code, 200)
        replay = client.post('/api/submit', json=body)
        self.assertEqual((replay.status_code, replay.json()['detail']), (400, 'replayed submission'))
        stale = dict(body, epoch=self.coord.current_epoch() - 2, seq=11)
        stale = walker.signed(self.key, stale)
        response = client.post('/api/submit', json=stale)
        self.assertEqual((response.status_code, response.json()['detail']), (400, 'stale submission'))
        other = Coordinator(self.spec, self.path)
        try:
            self.assertEqual(other.db.execute('SELECT last_seq FROM miners').fetchone()[0], 10)
            with self.assertRaises(HTTPException) as exc:
                other.rotate(self.body(seq=10, payout_addr=self.addr))
            self.assertEqual(exc.exception.detail, 'replayed submission')
        finally:
            other.db.close()

    def test_sequence_acceptance_is_atomic(self):
        self.admit()
        def submit():
            try:
                self.coord.submit(self.pk, [], freshness=(self.coord.current_epoch(), 1))
                return 200
            except HTTPException as exc:
                return exc.status_code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: submit(), range(2))), [200, 400])

    def test_missing_freshness_and_epoch_boundaries(self):
        self.admit()
        client = TestClient(module.build_app(self.coord))
        for field in ('epoch', 'seq'):
            body = self.body(dps=[])
            del body[field]
            response = client.post('/api/submit', json=walker.signed(self.key, body))
            self.assertEqual(response.status_code, 400)
        for seq, offset in enumerate((-1, 1)):
            body = self.body(seq=seq, dps=[])
            body['epoch'] += offset
            self.assertEqual(client.post('/api/submit', json=walker.signed(self.key, body)).status_code, 200)

    def test_ticket_freshness(self):
        client = TestClient(module.build_app(self.coord))
        body = self.body(payout_addr=self.addr, ticket=self.ticket)
        self.assertEqual(client.post('/api/ticket', json=body).status_code, 200)
        response = client.post('/api/ticket', json=body)
        self.assertEqual((response.status_code, response.json()['detail']), (400, 'replayed submission'))

    def test_addresses_rotation_and_committed_leaves(self):
        for address in ('0x' + 'a' * 39, '0x' + 'z' * 40, 'ab' * 20,
                        '0x' + 'ab' * 19 + '  ', None):
            self.assertFalse(module.valid_payout_addr(address))
        self.assertTrue(module.valid_payout_addr(self.addr))
        self.admit()
        self.coord.db.execute('UPDATE miners SET credited_steps=256')
        self.coord.db.execute("INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch,checked) VALUES(?,0,'0','0','0','0',1,0,0,1)", (self.pk,))
        self.coord.db.commit()
        self.coord.started_at -= self.spec.epoch_seconds
        self.coord.close_epoch()
        new = '0x' + 'cd' * 20
        result = self.coord.rotate(self.body(payout_addr=new))
        self.assertEqual(result['payout_addr'], new)
        self.assertEqual(self.coord.miners_view()[0]['payout_addr'], new)
        self.assertEqual(self.coord.proof(self.addr, 0)['credited_steps'], 256)
        event = next(e for e in self.coord.events_view() if e['kind'] == 'payout_rotated')
        self.assertEqual((event['detail']['old'], event['detail']['new']), (self.addr, new))
        self.coord._slash(self.pk, 'test')
        with self.assertRaises(HTTPException) as exc:
            self.coord.rotate(self.body(seq=1, payout_addr=self.addr))
        self.assertEqual(exc.exception.status_code, 403)

    def test_rotation_unknown_signature_and_limits(self):
        body = self.body(payout_addr=self.addr)
        with self.assertRaises(HTTPException) as exc:
            self.coord.rotate(body)
        self.assertEqual(exc.exception.status_code, 403)
        self.admit()
        with self.assertRaises(HTTPException) as exc:
            self.coord.rotate(dict(body, payout_addr='0x' + 'cd' * 20))
        self.assertEqual(exc.exception.status_code, 401)
        for kind in ('IP', 'KEY'):
            with patch.object(module, 'SUBMIT_' + kind + '_BURST', 0):
                client = TestClient(module.build_app(self.coord))
                self.assertEqual(client.post('/api/rotate', json=body).status_code, 429)

    def test_slash_retains_nonfailing_rows(self):
        self.admit()
        self.coord.db.executemany(
            'INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch) VALUES(?,?,?,?,?,?,?,?,?)',
            [(self.pk, t, '0', '0', '0', '0', 1, 0, 0) for t in range(3)])
        self.coord.db.commit()
        with patch.object(self.spec, 'spot_check_rate', 1), patch.object(ec, 'H', return_value=bytes(32)), \
                patch.object(ec, 'verify_segment', side_effect=lambda spec, table, pk, dp, seg, opening: (dp['t'] != 1, 1)):
            self.coord.audit_epoch(0, b'root')
            self.coord.respond()
        self.assertEqual(self.coord.db.execute('SELECT t,slashed FROM dps ORDER BY t').fetchall(),
                         [(0, 1), (1, 1), (2, 1)])
        self.assertEqual(self.coord.status_view()['dps_from_slashed'], 3)

    def test_epoch_loop_degradation_and_recovery(self):
        stop = Mock()
        stop.wait.side_effect = [False] * 3 + [True]
        with patch.object(self.coord, 'close_epoch', side_effect=RuntimeError('fault')), \
                patch.object(module.time, 'monotonic', return_value=100):
            module._epoch_loop(self.coord, stop)
        self.assertEqual(self.coord.epoch_loop_failures, 3)
        self.assertTrue(self.coord.status_view()['degraded'])
        stop.wait.side_effect = [False] * 5 + [True]
        with patch.object(self.coord, 'close_epoch', side_effect=RuntimeError('fault')), \
                patch.object(module.time, 'monotonic', return_value=101):
            module._epoch_loop(self.coord, stop)
        kinds = [e['kind'] for e in self.coord.events_view()]
        self.assertEqual(kinds.count('epoch_loop_degraded'), 1)
        self.assertEqual(kinds.count('epoch_error'), 1)
        stop.wait.side_effect = [False, True]
        with patch.object(self.coord, 'close_epoch'):
            module._epoch_loop(self.coord, stop)
        self.assertEqual(self.coord.epoch_loop_failures, 0)
        self.assertFalse(self.coord.status_view()['degraded'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
