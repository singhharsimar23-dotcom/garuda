"""
Acceptance Tests for AXIOM Telemetry API Endpoint
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))

from axiom.main import app
from axiom.config import get_settings


class TestTelemetryEndpoint(unittest.TestCase):
    """Test suite for POST /api/v1/telemetry."""

    def setUp(self):
        self.client = TestClient(app)
        self.settings = get_settings()
        self.settings.agent_api_key = "test-secret-agent-key-12345"

    def test_invalid_api_key(self):
        """Request with missing or invalid Bearer token must return 401 Unauthorized."""
        payload = {
            "agent_id": "test-agent-01",
            "hostname": "test-node",
            "timestamp": 1700000000.0,
            "readings": [{"timestamp": 1700000000.0, "rapl_pkg_uw": 15000000.0}],
        }
        # No header
        resp = self.client.post("/api/v1/telemetry", json=payload)
        self.assertEqual(resp.status_code, 401)

        # Bad token
        resp_bad = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        self.assertEqual(resp_bad.status_code, 401)

    def test_baselining_phase(self):
        """New agent with <1000 observations returns BASELINING status and CLEAN level."""
        payload = {
            "agent_id": "fresh-agent-99",
            "hostname": "uncalibrated-node",
            "timestamp": 1700000000.0,
            "readings": [
                {
                    "timestamp": 1700000000.0,
                    "rapl_pkg_uw": 15200000.0,
                    "instructions": 1000000.0,
                    "cache_misses": 5000.0,
                    "cycles": 800000.0,
                    "ipc": 1.25,
                }
            ],
        }
        headers = {"Authorization": f"Bearer {self.settings.agent_api_key}"}
        resp = self.client.post("/api/v1/telemetry", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "BASELINING")
        self.assertEqual(data["anomaly_level"], "CLEAN")
        self.assertFalse(data["calibrated"])

    def test_missing_rapl_channels(self):
        """Observations with missing RAPL channels should degrade gracefully without error."""
        payload = {
            "agent_id": "no-rapl-agent",
            "hostname": "vm-node",
            "timestamp": 1700000000.0,
            "readings": [
                {
                    "timestamp": 1700000000.0,
                    "rapl_pkg_uw": None,
                    "rapl_dram_uw": None,
                    "instructions": 2000000.0,
                    "cache_misses": 12000.0,
                    "entropy_avail": 3800.0,
                }
            ],
        }
        headers = {"Authorization": f"Bearer {self.settings.agent_api_key}"}
        resp = self.client.post("/api/v1/telemetry", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ias_score", data)

    @patch("axiom.routers.telemetry.trigger_dharma")
    @patch("axiom.routers.telemetry.AlmanacService.get_baseline")
    def test_critical_ias_triggers_dharma(self, mock_get_baseline, mock_trigger):
        """CRITICAL IAS anomaly triggers DHARMA dispatch."""
        # Establish trusted baseline
        mock_get_baseline.return_value = {
            "agent_id": "compromised-node",
            "workload_class": "IDLE",
            "mu": {"rapl_pkg": 10000000.0},
            "sigma": {"rapl_pkg": 500000.0},
            "thresholds": {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0},
            "trust_established": True,
            "observation_count": 1200,
        }
        mock_trigger.return_value = True

        # Huge anomaly payload (50W package power vs 10W baseline)
        payload = {
            "agent_id": "compromised-node",
            "hostname": "compromised-node",
            "timestamp": 1700000000.0,
            "readings": [
                {
                    "timestamp": 1700000000.0,
                    "rapl_pkg_uw": 50000000.0,
                }
            ],
        }
        headers = {"Authorization": f"Bearer {self.settings.agent_api_key}"}
        resp = self.client.post("/api/v1/telemetry", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["anomaly_level"], "CRITICAL")
        self.assertEqual(data["recommended_poll_interval_sec"], 0.1)  # 10Hz intensification
        mock_trigger.assert_called_once()


if __name__ == "__main__":
    unittest.main()
