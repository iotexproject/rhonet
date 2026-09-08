"""H-4/M-1 regressions, runnable directly or under pytest."""
import copy
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec, gencurve
from rhonet.coordinator import Coordinator

ROUND = Path(__file__).resolve().parents[1] / 'rounds/r32.json'


class SpecValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(ROUND.read_text())

    def small_curve(self, p, a, b, n, G, Q=None):
        data = copy.deepcopy(self.data)
        data['curve'] = dict(p=p, a=a, b=b, n=n, gx=G[0], gy=G[1])
        data['qx'], data['qy'] = Q or G
        return data

    def test_valid_round_and_headroom_boundaries(self):
        spec = ec.RoundSpec.load(ROUND)
        spec.validate()
        for extra in (1, 6):
            replace(spec, max_walk_len_log2=spec.w + extra).validate()

    def test_parameter_violations(self):
        w = self.data['w']
        for field, value, message in (
            ('ticket_d', w, 'ticket_d must be > w'),
            ('r', 30, 'r must be >= 2 and a power of two'),
            ('r', 1, 'r must be >= 2'),
            ('w', 0, 'w must be >= 1'),
            ('max_walk_len_log2', w + 20, 'submitter drive verifier cost'),
            ('max_walk_len_log2', w, 'max_walk_len_log2 must satisfy'),
            ('spot_check_rate', 0, 'spot_check_rate must be >= 1'),
            ('credit_unit_log2', -1, 'credit_unit_log2 must be >= 0'),
            ('epoch_seconds', 0, 'epoch_seconds must be >= 1'),
            ('quota_dps_per_epoch_base', 0, 'quota_dps_per_epoch_base must be >= 1'),
        ):
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(self.data)
                data[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    ec.RoundSpec.from_dict(data)

    def test_off_curve_Q(self):
        self.data['qx'] = self.data['qy'] = 0
        self.assertNotEqual(self.data['curve']['b'] % self.data['curve']['p'], 0)
        with self.assertRaisesRegex(ValueError, 'Q must be on the curve'):
            ec.RoundSpec.from_dict(self.data)

    def test_Q_outside_subgroup(self):
        # E(F_7) has 12 points; G has order 3, Q has order 6.
        data = self.small_curve(7, 0, 1, 3, (0, 1), (1, 3))
        with self.assertRaisesRegex(ValueError, 'Q must be in <P>'):
            ec.RoundSpec.from_dict(data)

    def test_anomalous_curve(self):
        # Actual anomalous curve: #E(F_5) = 5, G has order 5.
        data = self.small_curve(5, 3, 2, 5, (1, 1))
        with self.assertRaisesRegex(ValueError, 'anomalous curve: n == p'):
            ec.RoundSpec.from_dict(data)

    def test_small_embedding_degree(self):
        data = self.small_curve(7, 0, 1, 3, (0, 1))
        with self.assertRaisesRegex(ValueError, 'small embedding degree.*d=1'):
            ec.RoundSpec.from_dict(data)
        # Also exercise a degree greater than one.
        data = self.small_curve(5, 0, 1, 3, (0, 1))
        with self.assertRaisesRegex(ValueError, 'small embedding degree.*d=2'):
            ec.RoundSpec.from_dict(data)

    def test_curve_invariants(self):
        for field, value, message in (
            ('p', 15, 'curve p must be prime'),
            ('n', 15, 'curve n must be prime'),
            ('n', 2, 'Hasse interval'),
        ):
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(self.data)
                data['curve'][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    ec.RoundSpec.from_dict(data)
        with self.assertRaisesRegex(ValueError, 'nonsingular'):
            ec.RoundSpec.from_dict(self.small_curve(7, 0, 0, 3, (0, 0)))
        with self.assertRaisesRegex(ValueError, 'G must be on the curve'):
            ec.RoundSpec.from_dict(self.small_curve(7, 0, 1, 3, (0, 0)))
        with self.assertRaisesRegex(ValueError, 'G must have order exactly n'):
            ec.RoundSpec.from_dict(self.small_curve(7, 0, 1, 3, (1, 3)))
        spec = ec.RoundSpec.load(ROUND)
        with patch.object(ec.Curve, 'G', new_callable=lambda: property(lambda self: ec.INF)):
            with self.assertRaisesRegex(ValueError, 'G must not be INF'):
                spec.validate()

    def test_shallow_validation_skips_only_scalar_products(self):
        spec = ec.RoundSpec.load(ROUND)
        with patch.object(ec.Curve, 'mul_unreduced', side_effect=AssertionError('scalar product')):
            spec.validate(deep=False)
            with self.assertRaisesRegex(ValueError, 'ticket_d'):
                replace(spec, ticket_d=spec.w).validate(deep=False)
            with self.assertRaisesRegex(AssertionError, 'scalar product'):
                spec.validate()

    def test_coordinator_refuses_invalid_round_before_side_effects(self):
        spec = ec.RoundSpec.load(ROUND)
        spec.ticket_d = spec.w
        with patch('rhonet.coordinator.sqlite3.connect') as connect:
            with self.assertRaisesRegex(ValueError, 'ticket_d must be > w'):
                Coordinator(spec, ':memory:')
            connect.assert_not_called()

    def test_generator_rejects_invalid_parameters_before_generation(self):
        for flags, message in ((['--w', '8', '--ticket-d', '8'], '--ticket-d'),
                               (['--r', '30'], '--r')):
            with self.subTest(flags=flags), patch.object(gencurve, 'gen') as gen:
                with self.assertRaisesRegex(SystemExit, message):
                    gencurve.main(['--out', 'unused.json', *flags])
                gen.assert_not_called()

    def test_generator_skips_weak_candidates(self):
        anomalous = ec.Curve(5, 3, 2, 5, 1, 1)
        embedding = ec.Curve(7, 0, 1, 3, 0, 1)
        good = ec.RoundSpec.load(ROUND).curve
        curves = [anomalous, embedding, good]
        with patch.object(gencurve, 'random_prime', side_effect=[c.p for c in curves]), \
             patch.object(gencurve, 'secrets', Mock(randbelow=Mock(side_effect=[v for c in curves for v in (c.a, c.b)]))), \
             patch.object(gencurve, 'random_point', side_effect=[c.G for c in curves] + [good.G]), \
             patch.object(gencurve, 'point_order_candidates', side_effect=[[c.n] for c in curves]):
            self.assertEqual(gencurve.gen(32), good)


if __name__ == '__main__':
    unittest.main(verbosity=2)
