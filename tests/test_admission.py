"""Fleet admission, flood shedding and miner retries; direct or pytest execution."""
import concurrent.futures
import itertools
import queue
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import coordinator as module, ec, walker


class AdmissionTests(unittest.TestCase):
    @contextmanager
    def server(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
            coord = module.Coordinator(spec, str(Path(tmp) / 'admission.sqlite'))
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            server = uvicorn.Server(uvicorn.Config(module.build_app(coord), log_level='error'))
            thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.started and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(server.started)
                with httpx.Client(base_url=f'http://127.0.0.1:{sock.getsockname()[1]}', timeout=5) as client:
                    yield coord, client
            finally:
                server.should_exit = True
                thread.join(5)
                sock.close()
                self.assertFalse(thread.is_alive())
                coord.db.close()

    def test_A_simultaneous_honest_fleet(self):
        with self.server() as (coord, client):
            identities = []
            seen = set()
            for i in range(8):
                key = Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
                pk = walker.pubkey_hex(key)
                ticket = ec.ticket_solve(coord.spec, coord.table, pk)
                for t in range(1000):
                    result = ec.walk_to_dp(coord.spec, coord.table, *ec.derive_start(coord.spec, pk, t),
                                           coord.spec.w, ec.MAX_REPLAY_STEPS(coord.spec))
                    if result and result[2][0] not in seen:
                        a, b, (x, y), steps = result
                        seen.add(x)
                        break
                else:
                    self.fail('No genuine DP')
                identities.append((key, pk, ticket, dict(t=t, a=a, b=b, x=x, y=y, steps=steps)))
            barrier = threading.Barrier(8)
            def admit(identity):
                key, pk, ticket, dp = identity
                seq = itertools.count()
                def body(**fields):
                    return walker.signed(key, dict(round_id=coord.spec.round_id, pubkey=pk,
                                        epoch=client.get('/api/status').json()['epoch'], seq=next(seq), **fields))
                barrier.wait(timeout=5)
                response = walker.post_with_retry(client, '/api/ticket',
                    lambda: body(ticket=ticket, payout_addr='0x' + pk[:40]))
                self.assertEqual(response.status_code, 200, response.text)
                response = walker.post_with_retry(client, '/api/submit', lambda: body(dps=[dp]))
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()['accepted'], 1)
            original_verify = ec.ticket_verify
            def paced_verify(*args):
                # Keep real verification, but ensure the fleet overlaps on fast r32.
                time.sleep(.05)
                return original_verify(*args)
            with patch.object(ec, 'ticket_verify', side_effect=paced_verify), \
                    concurrent.futures.ThreadPoolExecutor(8) as pool:
                list(pool.map(admit, identities))
            rows = coord.miners_view()
            self.assertEqual(len(rows), 8)
            self.assertTrue(all(row['credited_steps'] > 0 for row in rows))
            print('A: 8/8 simultaneous honest miners admitted and credited', flush=True)

    def test_B_flood_is_shed(self):
        with self.server() as (coord, client):
            key = Ed25519PrivateKey.generate()
            pk = walker.pubkey_hex(key)
            # Invalid nonce is rejected cheaply by the real verifier.
            bodies = [walker.signed(key, dict(round_id=coord.spec.round_id, pubkey=pk,
                payout_addr='0x' + '11' * 20, epoch=coord.current_epoch(), seq=i,
                ticket=dict(nonce=-1, steps=1, x=0))) for i in range(600)]
            latencies = []
            with patch.object(ec, 'ticket_verify', wraps=ec.ticket_verify) as verify:
                with concurrent.futures.ThreadPoolExecutor(16) as pool:
                    futures = [pool.submit(client.post, '/api/ticket', json=body) for body in bodies]
                    while not all(f.done() for f in futures):
                        start = time.monotonic()
                        self.assertEqual(client.get('/api/status').status_code, 200)
                        latencies.append(time.monotonic() - start)
                        time.sleep(.01)
                    codes = [f.result().status_code for f in futures]
                shed = sum(code in (429, 503) for code in codes)
                self.assertGreater(shed, 500)
                self.assertLess(verify.call_count, 20)
                self.assertTrue(latencies)
                self.assertLess(max(latencies), 2)
                print(f'B: shed {shed}/600; verifications={verify.call_count}; '
                      f'max status latency={max(latencies):.3f}s', flush=True)

    def test_C_retry_helper(self):
        client = Mock()
        client.post.side_effect = [httpx.Response(c) for c in (429, 429, 200)]
        bodies = Mock(side_effect=[{'seq': i, 'epoch': i} for i in range(3)])
        with patch.object(walker.time, 'sleep') as sleep, patch.object(walker.random, 'uniform', return_value=1):
            self.assertEqual(walker.post_with_retry(client, '/api/ticket', bodies).status_code, 200)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [.5, 1])
        self.assertEqual(bodies.call_count, 3)
        self.assertEqual([c.kwargs['json']['seq'] for c in client.post.call_args_list], [0, 1, 2])
        client.reset_mock()
        client.post.side_effect = [httpx.Response(400)]
        self.assertEqual(walker.post_with_retry(client, '/api/ticket', lambda: {}).status_code, 400)
        self.assertEqual(client.post.call_count, 1)

    def test_C_submit_retains_batch_and_telemetry(self):
        self.check_submit_retention(False)

    def test_submit_survives_exhausted_budget(self):
        self.check_submit_retention(True)

    def check_submit_retention(self, exhaust):
        spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        client = Mock()
        client.get.side_effect = lambda path: httpx.Response(200, json=spec.to_dict() if path == '/api/round' else {'epoch': 0})
        submitted = []
        def post(path, json):
            if path == '/api/ticket':
                return httpx.Response(200, json={'epoch': 0})
            submitted.append(json)
            if len(submitted) == 1:
                return httpx.Response(429)
            return httpx.Response(200, json={'accepted': 1, 'status': 'solved'})
        client.post.side_effect = post
        ctx = Mock()
        ctx.Queue.return_value.get.side_effect = [([{'t': 7}], 123, 2), queue.Empty()]
        original_retry = walker.post_with_retry
        def retry(*args, **kwargs):
            return original_retry(*args, **kwargs, budget=0 if exhaust else 300)
        with tempfile.TemporaryDirectory() as tmp, patch.object(walker.httpx, 'Client', return_value=client), \
                patch.object(walker.ec, 'ticket_solve', return_value={'steps': 1, 'nonce': 0}), \
                patch.object(walker.mp, 'get_context', return_value=ctx), \
                patch.object(walker.time, 'sleep'), patch.object(walker, 'post_with_retry', side_effect=retry), \
                patch('sys.stderr') as stderr:
            self.assertEqual(walker.main(['--key', str(Path(tmp) / 'key'), '--procs', '1', '--flush', '0']), 0)
        self.assertEqual(len(submitted), 2)
        for body in submitted:
            self.assertEqual((body['dps'], body['steps_done'], body['abandoned']), ([{'t': 7}], 123, 2))
        self.assertGreater(submitted[1]['seq'], submitted[0]['seq'])
        output = ''.join(c.args[0] for c in stderr.write.call_args_list)
        self.assertEqual(output.count('sent 1 DPs'), 1)

    def test_partial_capacity_response_retries_original_points_in_order(self):
        spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        client, ctx = Mock(), Mock()
        client.get.side_effect = lambda path: httpx.Response(200, json=spec.to_dict() if path == '/api/round' else {'epoch': 0})
        submitted = []
        def post(path, json):
            if path == '/api/ticket':
                return httpx.Response(200, json={'epoch': 0})
            submitted.append(json)
            if len(submitted) == 1:
                return httpx.Response(200, json={'accepted': 1, 'rejected': [[1, 'audit backlog'], [2, 'quota']],
                                                'retry_indices': [1, 2], 'batch_limit': 2})
            return httpx.Response(200, json={'accepted': 2, 'status': 'solved'})
        client.post.side_effect = post
        ctx.Queue.return_value.get.side_effect = [([{'t': 9}, {'t': 3}, {'t': 7}], 123, 2),
                                                  ([{'t': 10}], 50, 1)]
        with tempfile.TemporaryDirectory() as tmp, patch.object(walker.httpx, 'Client', return_value=client), \
                patch.object(walker.ec, 'ticket_solve', return_value={'steps': 1, 'nonce': 0}), \
                patch.object(walker.mp, 'get_context', return_value=ctx), patch('sys.stderr'):
            self.assertEqual(walker.main(['--key', str(Path(tmp) / 'key'), '--procs', '1', '--flush', '0']), 0)
        self.assertEqual(submitted[0]['dps'], [{'t': 3}, {'t': 7}, {'t': 9}])
        self.assertEqual(submitted[1]['dps'], [{'t': 7}, {'t': 9}])
        self.assertEqual((submitted[1]['steps_done'], submitted[1]['abandoned']), (50, 1))

    def test_epoch_advance_rebuilds_submission_instead_of_losing_work(self):
        client = Mock()
        client.post.side_effect = [httpx.Response(400, json={'detail': 'stale submission'}),
                                   httpx.Response(200, json={'accepted': 1})]
        bodies = Mock(side_effect=[{'epoch': 0, 'dps': [{'t': 7}]},
                                   {'epoch': 2, 'dps': [{'t': 7}]}])
        with patch.object(walker.time, 'sleep'):
            self.assertEqual(walker.post_with_retry(client, '/api/submit', bodies).status_code, 200)
        self.assertEqual(bodies.call_count, 2)
        self.assertEqual([c.kwargs['json']['dps'] for c in client.post.call_args_list],
                         [[{'t': 7}], [{'t': 7}]])

    def test_retry_transport_and_budget(self):
        client = Mock()
        client.post.side_effect = [httpx.ConnectError('offline'), httpx.Response(200)]
        with patch.object(walker.time, 'sleep'):
            self.assertEqual(walker.post_with_retry(client, '/api/submit', lambda: {}).status_code, 200)
        client.post.side_effect = [httpx.Response(503)]
        with patch.object(walker.time, 'monotonic', side_effect=[0, 1]), patch.object(walker.time, 'sleep') as sleep:
            self.assertEqual(walker.post_with_retry(client, '/api/submit', lambda: {}, budget=1).status_code, 503)
            sleep.assert_not_called()
        client.post.side_effect = [httpx.ConnectError('offline')]
        self.assertIsNone(walker.post_with_retry(client, '/api/submit', lambda: {}, budget=0))

    def test_gate_queue_timeout_and_release(self):
        gate = module.TicketGate(1, 1, .1)
        with gate.enter(), concurrent.futures.ThreadPoolExecutor(1) as pool:
            def waiter():
                with self.assertRaises(module.HTTPException) as raised:
                    with gate.enter():
                        self.fail('slot occupied')
                self.assertEqual(raised.exception.status_code, 503)
            future = pool.submit(waiter)
            deadline = time.monotonic() + 1
            while gate.waiting != 1 and time.monotonic() < deadline:
                time.sleep(.001)
            start = time.monotonic()
            with self.assertRaises(module.HTTPException):
                with gate.enter():
                    self.fail('queue full')
            self.assertLess(time.monotonic() - start, .05)
            future.result()
        self.assertEqual(gate.waiting, 0)
        with self.assertRaises(ValueError):
            with gate.enter():
                raise ValueError('verification failed')
        with gate.enter():
            pass


if __name__ == '__main__':
    unittest.main(verbosity=2)
