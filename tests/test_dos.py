"""C-4 regressions: run directly or with pytest; HTTP uses a real local server."""
import concurrent.futures
import socket
import statistics
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, ExitStack
from pathlib import Path
from unittest.mock import patch

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec, coordinator as module


class DosTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.coord = module.Coordinator(self.spec, str(Path(self.tmp.name) / 'dos.sqlite'))
        self.addCleanup(self.coord.db.close)

    def identity(self, seed):
        key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        return key, key.public_key().public_bytes_raw().hex()

    def signed(self, key, **body):
        body.setdefault("epoch", self.coord.current_epoch())
        body.setdefault("seq", 0 if "ticket" in body else getattr(self, "_seq", 0) + 1)
        if "ticket" not in body:
            self._seq = body["seq"]
        body.update(round_id=self.spec.round_id, pubkey=key.public_key().public_bytes_raw().hex())
        return dict(body, sig=key.sign(ec.canonical(body)).hex())

    def ticket_body(self, key, ticket):
        return self.signed(key, payout_addr='0x' + '11' * 20, ticket=ticket)

    def test_ticket_cost_ignores_steps(self):
        _, pk = self.identity(1)
        ticket = ec.ticket_solve(self.spec, self.coord.table, pk)
        durations = [[], []]
        original = ec.walk_to_dp
        with patch.object(ec, 'walk_to_dp', wraps=original) as walk:
            for _ in range(15):
                for i, steps in enumerate((ticket['steps'], 1 << 40)):
                    start = time.perf_counter()
                    self.assertEqual(ec.ticket_verify(self.spec, self.coord.table, pk,
                                                      dict(ticket, steps=steps)), i == 0)
                    durations[i].append(time.perf_counter() - start)
            self.assertTrue(all(c.args[-1] == ec.TICKET_VERIFY_CAP(self.spec)
                                for c in walk.call_args_list))
        ratio = statistics.median(durations[1]) / statistics.median(durations[0])
        self.assertLess(ratio, 3)
        self.assertGreater(ratio, 1 / 3)
        print(f'ticket timing: huge/honest steps ratio={ratio:.2f}', flush=True)

    def test_admit_releases_lock_and_rechecks_key(self):
        entered, release = threading.Event(), threading.Event()
        _, pk = self.identity(2)
        def verify(*args):
            entered.set()
            self.assertTrue(release.wait(5))
            return True
        def read():
            with self.coord.lock:
                return self.coord.status_view()
        with concurrent.futures.ThreadPoolExecutor(3) as pool:
            with patch.object(ec, 'ticket_verify', side_effect=verify):
                admission = pool.submit(self.coord.admit, pk, '0x' + '11' * 20, {'steps': 1})
                try:
                    self.assertTrue(entered.wait(2))
                    self.assertEqual(pool.submit(read).result(timeout=1)['status'], 'open')
                    second = pool.submit(self.coord.admit, pk, '0x' + '11' * 20, {'steps': 1})
                finally:
                    release.set()
                results = [admission.result(timeout=2), second.result(timeout=2)]
                self.assertEqual(sorted(r['already'] for r in results), [False, True])

    def test_dp_cap_and_validation_outside_lock(self):
        dp = dict(x=0, y=0, a=0, b=0, t=0, steps=ec.MAX_REPLAY_STEPS(self.spec) + 1)
        with patch.object(ec, 'replay') as replay:
            self.assertFalse(ec.dp_verify(self.spec, self.coord.table, 'ab' * 32, dp))
            replay.assert_not_called()
        pk = 'ab' * 32
        self.coord.admit(pk, '0x' + '11' * 20, ec.ticket_solve(self.spec, self.coord.table, pk))
        self.assertEqual(self.coord.submit(pk, [dp])['rejected'], [(0, 'walk too long')])
        original = self.spec.curve.on_curve
        def on_curve(point):
            self.assertFalse(self.coord.lock._is_owned())
            return original(point)
        with patch.object(ec.Curve, 'on_curve', side_effect=on_curve):
            self.coord.submit(pk, [dict(dp, steps=1)])

    def test_audit_releases_lock(self):
        # Audit pairs reference the admitted miner's stable index.
        self.coord.db.execute("INSERT INTO miners(pubkey,payout_addr,ticket,admitted_at,admitted_epoch) "
                              "VALUES('ab',?,'{}',0,0)", ('0x' + '11' * 20,))
        self.coord.db.execute('INSERT INTO dps(pubkey,t,x,y,a,b,steps,ts,epoch) VALUES(?,?,?,?,?,?,?,?,?)',
                              ('ab', 0, '0', '0', '0', '0', 1, 0, 0))
        self.coord.db.commit()
        self.coord.started_at -= self.spec.epoch_seconds
        def verify(*args):
            self.assertFalse(self.coord.lock._is_owned())
            return True
        with patch.object(ec, 'H', return_value=bytes(32)), patch.object(ec, 'dp_verify', side_effect=verify):
            self.coord.close_epoch()

    def test_rate_limiter_and_http_gates(self):
        limiter = module.RateLimiter(module.TICKET_KEY_RATE, module.TICKET_KEY_BURST)
        with patch.object(module.time, 'monotonic', return_value=100):
            for _ in range(module.TICKET_KEY_BURST):
                self.assertTrue(limiter.allow('a'))
            self.assertFalse(limiter.allow('a'))
            self.assertTrue(limiter.allow('b'))
        with patch.object(module.time, 'monotonic', return_value=100 + 1 / module.TICKET_KEY_RATE):
            self.assertTrue(limiter.allow('a'))
        for endpoint in ('ticket', 'submit'):
            for kind in ('IP', 'KEY'):
                prefix = endpoint.upper()
                with patch.object(module, prefix + '_' + kind + '_BURST', 0):
                    with TestClient(module.build_app(self.coord)) as client:
                        response = client.post('/api/' + endpoint, json={'pubkey': 'ab'})
                        self.assertEqual(response.status_code, 429)
        gate = module.TicketGate(1, 1, 0.01)
        gate.slots.acquire()
        key, _ = self.identity(4)
        with patch.object(module, 'TICKET_GATE', gate):
            with TestClient(module.build_app(self.coord)) as client:
                response = client.post('/api/ticket', json=self.ticket_body(key, {}))
                self.assertEqual(response.status_code, 503)
                gate.slots.release()
                self.assertEqual(client.get('/api/proof', params={'payout_addr': '0x' + '11' * 20}).status_code, 404)
                with patch.object(ec, 'ticket_verify', return_value=False):
                    self.assertEqual(client.post('/api/ticket', json=self.ticket_body(key, {})).status_code, 400)
                self.assertTrue(gate.slots.acquire(blocking=False))
                gate.slots.release()

    def test_demo_ip_limits_preserve_ticket_key_limit(self):
        with patch.object(module, 'TICKET_IP_RATE', 8), \
                patch.object(module, 'TICKET_IP_BURST', 32), \
                patch.object(module.time, 'monotonic', return_value=100):
            client = TestClient(module.build_app(self.coord))
            # Missing ticket fields fail after both buckets, without costly verification.
            for _ in range(module.TICKET_KEY_BURST):
                self.assertEqual(client.post('/api/ticket', json={'pubkey': 'ab'}).status_code, 400)
            self.assertEqual(client.post('/api/ticket', json={'pubkey': 'AB'}).status_code, 429)
            self.assertEqual(client.post('/api/ticket', json={'pubkey': 'cd'}).status_code, 400)
        with patch.object(module.time, 'monotonic', return_value=100 + 1 / module.TICKET_KEY_RATE):
            self.assertEqual(client.post('/api/ticket', json={'pubkey': 'ab'}).status_code, 400)

    @contextmanager
    def server(self):
        with ExitStack() as stack:
            for prefix in ('TICKET_IP', 'TICKET_KEY', 'SUBMIT_IP', 'SUBMIT_KEY'):
                for suffix in ('RATE', 'BURST'):
                    stack.enter_context(patch.object(module, prefix + '_' + suffix, 100000))
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(module.build_app(self.coord), log_level='error'))
            thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.started and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(server.started)
                yield f'http://127.0.0.1:{port}'
            finally:
                server.should_exit = True
                thread.join(5)
                sock.close()
                self.assertFalse(thread.is_alive())

    def test_T4_http_submissions_continue_during_maximal_ticket(self):
        key, pk = self.identity(5)
        evil, evil_pk = self.identity(6)
        table, spec = self.coord.table, self.spec
        # Find a nonce that exhausts the FULL internal cap, without degeneration.
        for nonce in range(1000):
            start = ec.derive_start(spec, evil_pk, nonce, tag='ticket')
            if ec.walk_to_dp(spec, table, *start, spec.ticket_d, ec.TICKET_VERIFY_CAP(spec)) is None:
                if ec.replay(spec, table, *start, ec.TICKET_VERIFY_CAP(spec)) is not None:
                    break
        else:
            self.fail('No cap-exhausting nonce')
        attack = self.ticket_body(evil, dict(nonce=nonce, steps=1 << (spec.ticket_d + 3), x=0))
        self.assertTrue(ec.is_dp(0, spec.ticket_d))
        batches, seen = [], set()
        for t in range(1000):
            res = ec.walk_to_dp(spec, table, *ec.derive_start(spec, pk, t), spec.w, ec.MAX_REPLAY_STEPS(spec))
            if res is not None and res[2][0] not in seen:
                a, b, (x, y), steps = res
                seen.add(x)  # Avoid ending this tiny round through an honest collision.
                batches.append(self.signed(key, dps=[dict(a=a, b=b, x=x, y=y, t=t, steps=steps)]))
            if len(batches) == 200:
                break
        self.assertEqual(len(batches), 200)
        accepted, errors = [], []
        ready = threading.Event()
        # r32's full cap can finish before the next HTTP request is scheduled.
        # Add 2 ms per 128 real curve additions ONLY in the attack thread so
        # overlap is reproducible. Do not replace verification or release locks.
        local = threading.local()
        original_add, original_verify = ec.Curve.add, ec.ticket_verify
        def paced_add(curve, left, right):
            if getattr(local, 'attack', False):
                local.calls += 1
                if local.calls % 128 == 0:
                    time.sleep(0.002)
            return original_add(curve, left, right)
        def paced_verify(spec, table, pubkey, ticket):
            local.attack, local.calls = pubkey == evil_pk, 0
            try:
                return original_verify(spec, table, pubkey, ticket)
            finally:
                local.attack = False
        with patch.object(ec.Curve, 'add', paced_add), patch.object(ec, 'ticket_verify', paced_verify), self.server() as url:
            with httpx.Client(base_url=url, timeout=5) as client:
                self.assertEqual(client.post('/api/ticket', json=self.ticket_body(
                    key, ec.ticket_solve(spec, table, pk))).status_code, 200)
                def submitter():
                    try:
                        with httpx.Client(base_url=url, timeout=5) as sender:
                            deadline = time.monotonic() + 1.5  # N seconds
                            for batch in batches:
                                if time.monotonic() >= deadline:
                                    break
                                response = sender.post('/api/submit', json=batch)
                                if response.status_code != 200 or response.json().get('accepted') != 1:
                                    raise AssertionError(response.text)
                                accepted.append(time.monotonic())
                                ready.set()
                                time.sleep(0.005)
                    except Exception as exc:
                        errors.append(exc)
                worker = threading.Thread(target=submitter)
                worker.start()
                try:
                    self.assertTrue(ready.wait(3))
                    begin = time.monotonic()
                    response = client.post('/api/ticket', json=attack)
                    end = time.monotonic()
                    self.assertEqual(response.status_code, 400, response.text)
                finally:
                    worker.join(6)
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors, errors)
        during = [t for t in accepted if begin <= t <= end]
        self.assertGreater(len(during), 0)
        # Include the surrounding acceptances: a stall covering the entire attack
        # must not disappear through filtering timestamps to the attack window.
        gaps = [b - a for a, b in zip(accepted, accepted[1:]) if a <= end and b >= begin]
        self.assertTrue(gaps)
        self.assertLess(max(gaps), 2)
        print(f'T4: attack={end-begin:.3f}s, accepted during attack={len(during)}, '
              f'longest overlapping acceptance gap={max(gaps):.3f}s', flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
