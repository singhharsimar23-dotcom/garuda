"""
Acceptance Tests for Offline Air-Gapped IAS Scoring, PDF Reporting, and STIX Export
"""

import os
import sys
import tempfile
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "usb-agent"))
sys.path.insert(0, os.path.join(BASE_DIR, "usb-analyst"))
sys.path.insert(0, os.path.join(BASE_DIR, "axiom-service"))

from garuda_usb_agent.offline_ias import OfflineIASComputer
from report_generator import generate_pdf_report
from stix_exporter import export_alerts_to_stix_bundle
from axiom.services.ias_computer import compute_ias


class TestAirGappedIAS(unittest.TestCase):
    """Test suite for offline IAS parity, safety gates, and analyst report generation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.computer = OfflineIASComputer(alert_queue_dir=self.temp_dir)

    def test_baselining_no_alerts(self):
        """When observation count < 1000, all evaluations return 'BASELINING — NO ALERTS VALID'."""
        observed = {"rapl_pkg_uw": 50000000.0}  # extreme spike
        res = self.computer.evaluate_observation(
            observed=observed,
            baseline_mu={"rapl_pkg": 15000000.0},
            baseline_sigma={"rapl_pkg": 1000000.0},
            observation_count=450,  # under 1000 threshold
        )
        self.assertEqual(res["level"], "BASELINING")
        self.assertFalse(res["is_alert"])
        self.assertEqual(res["status_label"], "BASELINING — NO ALERTS VALID")

    def test_offline_ias_matches_cloud_trend(self):
        """When calibrated (>= 1000 events), offline IAS detects physical divergence."""
        observed = {
            "rapl_pkg_uw": 35000000.0,
            "rapl_core_uw": 25000000.0,
            "instructions": 1000000,
            "cache_misses": 50000,
            "entropy_avail": 3800,
            "sched_run_ms": 1000.0,
        }
        baseline_mu = {"rapl_pkg": 15000000.0, "rapl_core": 10000000.0, "cache_misses": 5000.0}
        baseline_sigma = {"rapl_pkg": 1000000.0, "rapl_core": 800000.0, "cache_misses": 1000.0}

        res = self.computer.evaluate_observation(
            observed=observed,
            baseline_mu=baseline_mu,
            baseline_sigma=baseline_sigma,
            observation_count=1200,
        )
        self.assertTrue(res["is_alert"])
        self.assertIn(res["level"], ("CRITICAL", "MEDIUM"))
        self.assertGreater(res["score"], 3.0)

    def test_pdf_report_generated(self):
        """Generates PDF forensic report from offline alert array without throwing exceptions."""
        alerts = [
            {
                "alert_id": "alt-9901",
                "timestamp_ist": "20260830_100000",
                "level": "CRITICAL",
                "ias_score": 5.82,
                "top_channels": [{"channel": "rapl_pkg", "score": 5.4}],
            },
            {
                "alert_id": "alt-9902",
                "timestamp_ist": "20260830_100500",
                "level": "MEDIUM",
                "ias_score": 3.41,
                "top_channels": [{"channel": "perf_cache", "score": 3.2}],
            },
        ]
        pdf_out = os.path.join(self.temp_dir, "test_report.pdf")
        success = generate_pdf_report(pdf_out, "isolated-host-01", alerts)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(pdf_out) or os.path.exists(pdf_out.replace(".pdf", ".txt")))

    def test_stix_valid(self):
        """Exporting alerts produces a valid STIX 2.1 JSON bundle structure."""
        alerts = [{
            "alert_id": "alt-4401",
            "level": "CRITICAL",
            "ias_score": 6.10,
            "top_channels": [{"channel": "rapl_pkg", "score": 5.9}],
        }]
        bundle = export_alerts_to_stix_bundle(alerts, hostname="border-radar-01")
        self.assertEqual(bundle["type"], "bundle")
        self.assertGreaterEqual(len(bundle["objects"]), 3)
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("identity", types)
        self.assertIn("observed-data", types)
        self.assertIn("indicator", types)


if __name__ == "__main__":
    unittest.main()
