"""H-1 branch regressions, runnable directly or under pytest."""
import itertools
import sys
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rhonet import ec, gencurve

ROUND = Path(__file__).resolve().parents[1] / "rounds/r32.json"


class BranchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = ec.RoundSpec.load(ROUND)
        cls.table = ec.walk_table(cls.spec)
        cls.pk = "ab" * 32

    def collect_dps(self, count):
        walker = ec.BatchWalker(self.spec, self.table, self.pk, batch=32,
                                rng_t=itertools.count().__next__)
        found = []
        # Bound failure time if a regression prevents DP discovery.
        for _ in range(count * (1 << self.spec.w)):
            found.extend(walker.step())
            if len(found) >= count:
                return found[:count]
        self.fail(f"Only found {len(found)} of {count} DPs")

    def test_T5_branches_out_of_distinguished_points_are_spread(self):
        spec = self.spec
        dps = self.collect_dps(300)
        branches = Counter()
        for dp in dps:
            self.assertTrue(ec.is_dp(dp["x"], spec.w))
            # Resume each DP for one step and record the branch actually taken.
            with patch.object(ec, "branch_index", wraps=ec.branch_index) as branch:
                ec.replay(spec, self.table, dp["a"], dp["b"],
                          (dp["x"], dp["y"]), 1)
                branch.assert_called_once_with(dp["x"], spec.r, spec.w)
            branches[ec.branch_index(dp["x"], spec.r, spec.w)] += 1
        self.assertGreaterEqual(len(branches), spec.r // 4)
        self.assertLessEqual(max(branches.values()), len(dps) * 0.25)
        old_branches = {dp["x"] & (spec.r - 1) for dp in dps}
        self.assertEqual(old_branches, {0})  # The old rule always exits via branch 0.
        print(f"T5: {len(dps)} DPs, {len(branches)}/{spec.r} branches, "
              f"largest share={max(branches.values()) / len(dps):.2%}, "
              f"old-rule branches={old_branches}", flush=True)

    def test_batch_reference_and_replay_agree(self):
        spec = self.spec
        for dp in self.collect_dps(20):
            self.assertTrue(ec.dp_verify(spec, self.table, self.pk, dp))
            start = ec.derive_start(spec, self.pk, dp["t"])
            expected = (dp["a"], dp["b"], (dp["x"], dp["y"]), dp["steps"])
            self.assertEqual(ec.walk_to_dp(spec, self.table, *start, spec.w,
                                           ec.MAX_REPLAY_STEPS(spec) + 1), expected)
            # Ticket predicates must also use spec.w for branch selection.
            self.assertEqual(ec.walk_to_dp(spec, self.table, *start, spec.ticket_d,
                                           ec.TICKET_VERIFY_CAP(spec)),
                             self.ticket_reference(start))

    def ticket_reference(self, start):
        state = start
        for steps in range(1, ec.TICKET_VERIFY_CAP(self.spec)):
            state = ec.replay(self.spec, self.table, *state, 1)
            if state is None or state[2] is ec.INF:
                return None
            if ec.is_dp(state[2][0], self.spec.ticket_d):
                return (*state, steps)
        return None

    def test_branch_bit_budget(self):
        needed = self.spec.w + self.spec.r.bit_length() - 1
        replace(self.spec, bits=needed).validate()
        for deep in (True, False):
            with self.assertRaisesRegex(ValueError, r"w \+ log2\(r\) must be <= bits"):
                replace(self.spec, bits=needed - 1).validate(deep=deep)
        with patch.object(gencurve, "gen") as gen:
            with self.assertRaisesRegex(SystemExit, "must be <= --bits"):
                gencurve.main(["--bits", "12", "--w", "6", "--out", "unused.json"])
            gen.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
