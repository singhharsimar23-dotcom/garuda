"""
Acceptance Tests for BRAHMA REST API Endpoints
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from brahma.main import app
from brahma.config import get_settings


class TestBrahmaEndpoints(unittest.TestCase):
    """Test suite for BRAHMA FastAPI endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        self.settings = get_settings()
        self.settings.inter_service_secret = "test-secret-service-key-99"

    def test_update_endpoint_authenticated(self):
        """POST /api/v1/brahma/update must reject requests without valid X-Inter-Service-Secret with 401."""
        payload = {
            "agent_id": "test-agent-01",
            "hostname": "test-host",
            "ias_score": 4.5,
            "anomaly_level": "MEDIUM",
            "top_channels": [{"channel": "rapl_pkg", "score": 4.0}],
        }
        # No header
        resp = self.client.post("/api/v1/brahma/update", json=payload)
        self.assertEqual(resp.status_code, 401)

        # Invalid secret
        resp_bad = self.client.post(
            "/api/v1/brahma/update",
            json=payload,
            headers={"X-Inter-Service-Secret": "wrong-secret"},
        )
        self.assertEqual(resp_bad.status_code, 401)

    def test_assessment_returns_uncertainty(self):
        """GET /api/v1/brahma/assessment/{agent_id} on a fresh agent returns INSUFFICIENT_DATA and UNATTRIBUTED."""
        resp = self.client.get("/api/v1/brahma/assessment/unobserved-node-99")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["actor_id"], "UNATTRIBUTED")
        self.assertEqual(data["convergence_status"], "INSUFFICIENT_DATA")
        self.assertEqual(data["observation_count"], 0)
        self.assertIn("execution", data["kill_chain_posterior"])

    def test_posterior_persisted(self):
        """Valid authenticated update successfully processes event and returns prediction."""
        payload = {
            "agent_id": "monitored-server-01",
            "hostname": "delhi-border-gw",
            "ias_score": 5.8,
            "anomaly_level": "CRITICAL",
            "top_channels": [
                {"channel": "rapl_pkg", "score": 5.1},
                {"channel": "perf_cache", "score": 3.8},
            ],
        }
        headers = {"X-Inter-Service-Secret": self.settings.inter_service_secret}
        resp = self.client.post("/api/v1/brahma/update", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "PROCESSED")
        self.assertGreater(data["observation_count"], 0)
        self.assertIn("map_tactic", data)
        self.assertIn("predicted_next_tactic", data)


if __name__ == "__main__":
    unittest.main()
