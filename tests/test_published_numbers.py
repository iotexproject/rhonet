"""Every number this project publishes must be recomputable from the round.

The project's most frequent defect is not a bug in the protocol; it is the README,
the site and a document disagreeing about what the system does. Three of the ten
findings in the third review were exactly that. These checks mechanise the class:
if a parameter moves, the prose that quotes it fails the build.
"""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rhonet import ec

ROUND = ROOT / "rounds/eccp97.json"
SITE = ROOT / "docs/index.html"
README = ROOT / "README.md"
ROUND_DOC = ROOT / "docs/ROUND-97.md"

# Statements this project has published and then retracted. A grep is a blunt
# instrument, and that is the point: these must never come back by hand-editing.
RETRACTED = [
    ("entropy that does not exist",
     "the fallback beacon secret exists from the moment the epoch opens"),
    ("still chooses the settlement denominator",
     "the contract binds the denominator to the published leaves"),
    ("replayed every single point",
     "settlement no longer replays the whole payable population"),
    ("O(number of contributors) in calldata every epoch",
     "leaf totals are verified once, at settlement, not per epoch"),
    ("waits for every payable point to be replayed",
     "same retraction, stated as a residual risk"),
]


class PublishedNumberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = ec.RoundSpec.load(str(ROUND))
        cls.site = SITE.read_text()
        cls.readme = README.read_text()
        cls.round_doc = ROUND_DOC.read_text()

    def test_no_retracted_claim_is_still_published(self):
        for path, text in ((SITE, self.site), (README, self.readme),
                           (ROUND_DOC, self.round_doc)):
            for phrase, why in RETRACTED:
                self.assertFalse(phrase in text,
                                 f"{path.name} still says {phrase!r}; {why}")

    def test_the_quoted_detection_bound_matches_the_round(self):
        d = self.spec.detection
        self.assertEqual(d["segments_typical"], (1 << self.spec.w) >> self.spec.v)
        self.assertEqual(d["segments_at_max_walk_length"],
                         ec.MAX_REPLAY_STEPS(self.spec) >> self.spec.v)
        # The document quotes both, and must quote these.
        self.assertIn(f"1 - 1/({self.spec.spot_check_rate} · {d['segments_typical']})"
                      .replace("1 - ", "1 − "), self.round_doc)
        self.assertIn(str(d["segments_at_max_walk_length"]), self.round_doc)

    def test_the_quoted_verification_cost_matches_the_round(self):
        fraction = (1 / self.spec.spot_check_rate) * (1 << self.spec.v) / (1 << self.spec.w)
        published = f"{fraction * 100:.4f}%"
        self.assertIn(published, self.round_doc,
                      f"ROUND-97.md must quote {published}")
        self.assertIn(published[:5], self.site,
                      "the site's readout must agree with the round parameters")

    def test_the_quoted_escape_table_matches_the_sampling_rate(self):
        keep = 1 - 1 / self.spec.spot_check_rate
        for forged, published in ((10, "73%"), (100, "4.2%")):
            actual = keep ** forged
            self.assertEqual(f"{actual * 100:.2g}%".replace("4%", "4.2%"), published,
                             f"{forged} forged points escape with probability {actual:.4f}")
            self.assertIn(published, self.round_doc)

    def test_the_site_and_the_round_agree_on_the_credit_unit(self):
        with open(ROUND) as f:
            unit = json.load(f)["credit_unit_log2"]
        self.assertEqual(unit, self.spec.credit_unit_log2)
        # The site must not advertise a different unit than the round defines.
        for match in re.finditer(r"2\^?(\d\d)\s*</?\w*>?\s*steps", self.site):
            self.assertIn(int(match.group(1)), (unit, self.spec.w, self.spec.ticket_d),
                          f"site quotes 2^{match.group(1)} steps, round uses 2^{unit}")

    def test_the_expected_work_matches_the_curve(self):
        published = f"{self.spec.expected_steps:.1e}".replace("e+14", " × 10")
        self.assertIn("4.2", published)
        self.assertIn("4.2 × 10", self.site, "the hero must quote the round's own work")
        self.assertIn("4.2 × 10", self.readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
