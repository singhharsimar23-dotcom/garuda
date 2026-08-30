"""
Acceptance Tests for UTNE Narrative Engine & Honesty Constraints
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../network-service")))

from utne.groq_synthesizer import UTNESynthesizer
from utne.rate_limiter import BudgetLimiter


class TestUTNESynthesizer(unittest.TestCase):
    """Test suite for UTNE executive sitreps, Rule 8 honesty, and rate limiting."""

    def setUp(self):
        self.limiter = BudgetLimiter()
        self.synthesizer = UTNESynthesizer(budget_limiter=self.limiter)

    def test_sitrep_no_attribution_low_confidence(self):
        """Rule 8 Honesty: When observations < 15, sitrep must output 'ATTRIBUTION UNCERTAIN'."""
        evidence = {
            "active_anomalies": [{"hostname": "delhi-gw", "ias_score": 4.2}],
            "brahma_assessments": [{
                "observation_count": 10,
                "convergence_status": "INSUFFICIENT_DATA",
                "actor_id": "UNATTRIBUTED",
                "confidence": 0.30,
            }],
        }
        res = self.synthesizer.generate_sitrep(evidence)
        self.assertEqual(res["attribution_status"], "UNATTRIBUTED")
        self.assertIn("ATTRIBUTION UNCERTAIN", res["sitrep_text"])

    def test_sitrep_cites_evidence(self):
        """Every anomalous claim in the sitrep must cite an evidence node (e.g. NODE-EVID-1)."""
        evidence = {
            "active_anomalies": [
                {"hostname": "mumbai-gw", "ias_score": 5.8, "top_channels": [{"channel": "rapl_pkg", "score": 5.1}]},
            ],
            "brahma_assessments": [{
                "observation_count": 25,
                "convergence_status": "CONVERGED",
                "actor_id": "APT36",
                "confidence": 0.82,
            }],
        }
        res = self.synthesizer.generate_sitrep(evidence)
        self.assertEqual(res["attribution_status"], "APT36")
        self.assertGreaterEqual(len(res["evidence_citations"]), 1)
        self.assertIn("NODE-EVID-1", res["sitrep_text"])

    def test_rate_limit_enforcement(self):
        """When daily budget is reached (24/day for sitreps), rate limiter returns cached/stale status."""
        limiter = BudgetLimiter()
        # Exhaust 24 calls
        for _ in range(24):
            allowed, _, _ = limiter.check_and_increment("utne_sitrep")
            self.assertTrue(allowed)

        # 25th call must be blocked
        allowed_25, _, _ = limiter.check_and_increment("utne_sitrep")
        self.assertFalse(allowed_25)

        synth = UTNESynthesizer(budget_limiter=limiter)
        blocked_res = synth.generate_sitrep({})
        self.assertEqual(blocked_res["status"], "RATE_LIMITED")

    def test_no_invented_iocs(self):
        """Evidence bundle known IOCs are tracked and cross-checked."""
        bundle = {
            "active_anomalies": [{"hostname": "border-router.mil.in"}],
            "known_iocs": ["192.168.1.50"],
        }
        iocs = self.synthesizer._extract_evidence_iocs(bundle)
        self.assertIn("border-router.mil.in", iocs)
        self.assertIn("192.168.1.50", iocs)


if __name__ == "__main__":
    unittest.main()
