"""
Acceptance Tests for IAS Computer & Baseline Statistics
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))

from axiom.models.telemetry import AnomalyLevel
from axiom.services.almanac_service import AlmanacService
from axiom.services.ias_computer import (
    compute_gaussian_kl,
    compute_ias,
    update_baseline_ema,
    calibrate_thresholds,
)


class TestIASComputer(unittest.TestCase):
    """Test suite for IAS Computer and Gaussian KL divergence."""

    def test_ias_identical_distributions(self):
        """Identical mean and standard deviation distributions must yield IAS ≈ 0.0."""
        mu_val = 15000000.0
        sigma_val = 500000.0
        kl = compute_gaussian_kl(mu_val, sigma_val, mu_val, sigma_val)
        self.assertAlmostEqual(kl, 0.0, places=5)

        observed = {
            "rapl_pkg_uw": mu_val,
            "rapl_pkg_sigma": sigma_val,
            "rapl_dram_uw": 2000000.0,
            "rapl_dram_sigma": 100000.0,
        }
        baseline = {
            "mu": {"rapl_pkg": mu_val, "rapl_dram": 2000000.0},
            "sigma": {"rapl_pkg": sigma_val, "rapl_dram": 100000.0},
            "thresholds": {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0},
            "trust_established": True,
        }

        res = compute_ias(observed, baseline)
        self.assertAlmostEqual(res.score, 0.0, places=4)
        self.assertEqual(res.level, AnomalyLevel.CLEAN)

    def test_ias_partial_channels(self):
        """When only 3 channels are available, weights should renormalize and calculate without error."""
        observed = {
            "rapl_pkg_uw": 18000000.0,
            "entropy_avail": 3500.0,
            "sched_delay_ratio": 0.05,
        }
        baseline = {
            "mu": {"rapl_pkg": 15000000.0, "entropy": 3800.0, "schedstat": 0.02},
            "sigma": {"rapl_pkg": 1000000.0, "entropy": 200.0, "schedstat": 0.01},
            "thresholds": {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0},
            "trust_established": True,
        }

        res = compute_ias(observed, baseline)
        self.assertIsNotNone(res.score)
        self.assertGreater(res.score, 0.0)
        # Weights should sum correctly and not raise ZeroDivisionError
        self.assertIn("rapl_pkg", res.channel_scores)

    def test_ias_zero_std_baseline(self):
        """Zero standard deviation in baseline must not trigger ZeroDivisionError due to epsilon guard."""
        observed = {"rapl_pkg_uw": 15000000.0}
        baseline = {
            "mu": {"rapl_pkg": 15000000.0},
            "sigma": {"rapl_pkg": 0.0},  # Degenerate zero variance
            "thresholds": {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0},
            "trust_established": True,
        }
        res = compute_ias(observed, baseline)
        self.assertIsNotNone(res.score)
        self.assertFalse(res.score != res.score)  # Not NaN

    def test_ias_threshold_classification(self):
        """Score thresholds determine CLEAN, LOG, MEDIUM, CRITICAL."""
        thresholds = {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0}

        # Substantial divergence resulting in CRITICAL
        observed_crit = {"rapl_pkg_uw": 45000000.0}  # Large deviation
        baseline = {
            "mu": {"rapl_pkg": 15000000.0},
            "sigma": {"rapl_pkg": 2000000.0},
            "thresholds": thresholds,
            "trust_established": True,
        }
        res_crit = compute_ias(observed_crit, baseline, thresholds)
        self.assertEqual(res_crit.level, AnomalyLevel.CRITICAL)

        # Mild deviation
        observed_clean = {"rapl_pkg_uw": 15500000.0}
        res_clean = compute_ias(observed_clean, baseline, thresholds)
        self.assertEqual(res_clean.level, AnomalyLevel.CLEAN)

    def test_baseline_not_contaminated(self):
        """AlmanacService should reject baseline updates when IAS >= LOG threshold."""
        import asyncio

        async def _test():
            service = AlmanacService()
            obs = {"rapl_pkg_uw": 99999999.0}
            # Score 3.5 exceeds LOG threshold 1.5 -> Must return None (skipped)
            updated = await service.update_baseline(
                agent_id="test-agent",
                workload_class="IDLE",
                observation=obs,
                ias_score=3.5,
                log_threshold=1.5,
            )
            self.assertIsNone(updated)

            # Clean score 0.2 -> Baseline is updated
            updated_clean = await service.update_baseline(
                agent_id="test-agent",
                workload_class="IDLE",
                observation={"rapl_pkg_uw": 15000000.0},
                ias_score=0.2,
                log_threshold=1.5,
            )
            self.assertIsNotNone(updated_clean)
            self.assertEqual(updated_clean["observation_count"], 1)

        asyncio.run(_test())

    def test_calibrate_thresholds(self):
        """Auto-calibration calculates 2*p99, 4*p99, 8*p99 across 500+ clean events."""
        clean_scores = [0.1 + (i % 10) * 0.05 for i in range(600)]
        thresholds = calibrate_thresholds("test-agent", "IDLE", clean_scores)
        self.assertIn("LOG", thresholds)
        self.assertIn("MEDIUM", thresholds)
        self.assertIn("CRITICAL", thresholds)
        self.assertLess(thresholds["LOG"], thresholds["MEDIUM"])
        self.assertLess(thresholds["MEDIUM"], thresholds["CRITICAL"])


if __name__ == "__main__":
    unittest.main()
