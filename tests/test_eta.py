"""Rayleigh remaining-work regressions; run directly or with pytest."""
import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec
from rhonet.coordinator import Coordinator


class EtaTests(unittest.TestCase):
    def setUp(self):
        self.spec = ec.RoundSpec.load(str(Path(__file__).resolve().parents[1] / 'rounds/r32.json'))
        self.coord = Coordinator(self.spec, ':memory:')
        self.addCleanup(self.coord.db.close)

    def test_expected_remaining_at_one_and_two_means(self):
        mean = self.spec.expected_steps
        for multiple, low, high in ((1, 0.4, 0.65), (2, 0.2, 0.4)):
            ratio = self.coord.eta_posterior(multiple * mean, 100)['expected_remaining_steps'] / mean
            self.assertGreater(ratio, low)
            self.assertLess(ratio, high)
        self.assertAlmostEqual(self.coord.eta_posterior(0, 100)['expected_remaining_steps'], mean)

    def test_quantiles_survival_and_positive_values_past_expectation(self):
        mean = self.spec.expected_steps
        n_eff = (1.25 ** 2 * 2 / math.pi) * self.spec.curve.n
        for multiple in (0, 0.5, 1, 2, 10, 100, 1e12):
            with self.subTest(multiple=multiple):
                s0, rate = multiple * mean, 123
                eta = self.coord.eta_posterior(s0, rate)
                self.assertLess(eta['p05_remaining_steps'], eta['median_remaining_steps'])
                self.assertLess(eta['median_remaining_steps'], eta['p95_remaining_steps'])
                for key, value in eta.items():
                    self.assertIsNotNone(value, key)
                    self.assertTrue(math.isfinite(value), key)
                    self.assertGreater(value, 0, key)
                for name, survival in (('p05', .95), ('median', .5), ('p95', .05)):
                    u = eta[name + '_remaining_steps']
                    self.assertAlmostEqual(math.exp(-u * (2 * s0 + u) / (2 * n_eff)), survival)
                    self.assertAlmostEqual(eta[name + '_remaining_seconds'], u / rate)
                u = rate * 3600
                self.assertAlmostEqual(eta['p_complete_next_hour'], -math.expm1(-u * (2 * s0 + u) / (2 * n_eff)))
        self.assertAlmostEqual(self.coord.eta_posterior(100 * mean, 123)['expected_remaining_steps'],
                               n_eff / (100 * mean))

    def test_zero_rate_retains_work_quantiles(self):
        eta = self.coord.eta_posterior(2 * self.spec.expected_steps, 0)
        self.assertIsNone(eta['p_complete_next_hour'])
        for name in ('p05', 'median', 'p95'):
            self.assertGreater(eta[name + '_remaining_steps'], 0)
            self.assertIsNone(eta[name + '_remaining_seconds'])

    def test_status_uses_reported_search_work_and_median_alias(self):
        search = int(2 * self.spec.expected_steps)
        self.coord.db.execute(
            'INSERT INTO miners(pubkey,payout_addr,ticket,admitted_at,admitted_epoch,ticket_steps) '
            'VALUES(?,?,?,?,?,?)', ('ab', '0x' + '11' * 20, '{}', 0, 0, search * 10))
        self.coord.db.commit()
        self.coord.submit('ab', [], steps_done=search)
        status = self.coord.status_view()
        self.assertEqual(status['total_credited_steps'], 0)
        self.assertEqual(status['steps_per_sec'], search / 60)
        self.assertEqual(status['eta'], self.coord.eta_posterior(search, search / 60))
        self.assertEqual(status['eta_seconds'], status['eta']['median_remaining_seconds'])
        self.assertGreater(status['eta_seconds'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
