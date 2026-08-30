"""
Unit, Acceptance, and Negative Tests for garuda-axiom-service.
Covers real-time IAS evaluation, Welford baseline learning with contamination protection,
fleet-wide multi-sensor fusion, BRAHMA/DHARMA triggers, and resilient Supabase error handling.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add axiom-service directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))

from baseline import AlmanacBaselineStore, get_baseline_store
from brahma_trigger import trigger_brahma_observe
from config import get_settings
from dharma_trigger import trigger_dharma_actions
from fusion import FleetFusionEngine, get_fusion_engine
from ias_engine import IASEngine, get_ias_engine
from main import app
from models import TelemetryInput


class TestAxiomService(unittest.TestCase):
    """Test suite for AXIOM-II Telemetry & Physics Invariant Service."""

    def setUp(self):
        self.client = TestClient(app)
        self.settings = get_settings()
        self.auth_headers = {"Authorization": f"Bearer {self.settings.agent_api_key}"}

    def _create_sample_payload(
        self,
        hostname: str = "drdo-server-01",
        pkg_w: float = 28.5,
        dram_w: float = 4.2,
        instructions: float = 1_200_000.0,
        cache_misses: float = 45_000.0,
        entropy_bits: int = 3800,
        steal_ratio: float = 0.01,
        rapl_unavailable: bool = False,
    ) -> dict:
        return {
            "agent_id": "550e8400-e29b-41d4-a716-446655440000",
            "hostname": hostname,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "rapl": {
                "pkg_w": pkg_w,
                "dram_w": dram_w,
                "core_w": 18.0,
                "unavailable": rapl_unavailable,
            },
            "perf": {
                "instructions_ps": instructions,
                "cache_misses_ps": cache_misses,
                "cycles_ps": 2_500_000.0,
                "unavailable": False,
            },
            "entropy": {
                "bits": entropy_bits,
                "depleting": False,
                "sustained_low_s": 0,
            },
            "schedstat": {
                "steal_ratio": steal_ratio,
            },
            "ias": {
                "score": 0.2,
                "uncalibrated": False,
                "workload_class": "WEB_SERVER",
                "channel_sigmas": {},
            },
            "flags": [],
        }

    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    @patch("auth.get_supabase_client")
    @patch("telemetry.get_supabase_client")
    def test_1_valid_telemetry_post(self, mock_telemetry_sb, mock_auth_sb):
        """1. POST /api/v1/telemetry with valid RAPL data: assert 200, physics_observations row created."""
        mock_sb = MagicMock()
        mock_insert = MagicMock()
        mock_insert.execute.return_value = MagicMock(data=[{"id": "obs_123"}])
        mock_sb.table.return_value.insert.return_value = mock_insert
        mock_sb.table.return_value.upsert.return_value.execute.return_value = MagicMock(data=[{}])

        mock_telemetry_sb.return_value = mock_sb
        mock_auth_sb.return_value = mock_sb

        payload = self._create_sample_payload()
        response = self.client.post("/api/v1/telemetry", headers=self.auth_headers, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("computed_ias", data)
        self.assertEqual(data["observation_id"], "obs_123")

    @patch("telemetry.trigger_brahma_observe")
    @patch("telemetry.trigger_dharma_actions")
    @patch("auth.get_supabase_client")
    @patch("telemetry.get_supabase_client")
    def test_2_ias_critical_triggers_dharma_and_brahma(
        self, mock_telemetry_sb, mock_auth_sb, mock_dharma, mock_brahma
    ):
        """2. POST with IAS >= 5.0 (CRITICAL): assert DHARMA action enqueued and BRAHMA triggered."""
        mock_sb = MagicMock()
        mock_sb.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "obs_crit"}])
        mock_sb.table.return_value.upsert.return_value.execute.return_value = MagicMock(data=[{}])
        mock_telemetry_sb.return_value = mock_sb
        mock_auth_sb.return_value = mock_sb

        # Massive physics anomaly payload (extreme power, instructions, cache misses, low entropy)
        extreme_payload = self._create_sample_payload(
            pkg_w=150.0,
            dram_w=40.0,
            instructions=50_000_000.0,
            cache_misses=5_000_000.0,
            entropy_bits=50,
            steal_ratio=0.85,
        )

        response = self.client.post("/api/v1/telemetry", headers=self.auth_headers, json=extreme_payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["computed_ias"], 5.0)
        self.assertEqual(data["anomaly_level"], "CRITICAL")
        self.assertIn("BRAHMA_OBSERVE", data["triggers"])
        self.assertIn("DHARMA_CRITICAL_RESPONSE", data["triggers"])

    def test_3_baseline_updated_when_ias_clean(self):
        """3. POST with clean/normal IAS (< 1.5): assert baseline updated (sample_count incremented)."""
        store = AlmanacBaselineStore()
        hostname = "drdo-host-clean"
        wclass = "WEB_SERVER"
        channel = "rapl_pkg"

        # Initial baseline sample_count = 0
        b_before = store.get_baseline(hostname, wclass, channel)
        self.assertEqual(b_before["sample_count"], 0)

        # Update with clean IAS = 0.5
        b_after = store.update_baseline(hostname, wclass, channel, current_val=20.0, ias_score=0.5)
        self.assertEqual(b_after["sample_count"], 1)
        self.assertEqual(b_after["mean"], 20.0)

    def test_4_contamination_prevention_on_elevated_ias(self):
        """4. Contamination Prevention: When IAS >= 1.5, assert baseline is NOT updated."""
        store = AlmanacBaselineStore()
        hostname = "drdo-host-attack"
        wclass = "WEB_SERVER"
        channel = "rapl_pkg"

        # Prime with 1 sample
        store.update_baseline(hostname, wclass, channel, current_val=15.0, ias_score=0.2)
        b_clean = store.get_baseline(hostname, wclass, channel)
        count_before = b_clean["sample_count"]
        mean_before = b_clean["mean"]

        # Attack reading with IAS = 1.8 (>= 1.5)
        b_after = store.update_baseline(hostname, wclass, channel, current_val=95.0, ias_score=1.8)
        self.assertEqual(b_after["sample_count"], count_before)
        self.assertEqual(b_after["mean"], mean_before)

    def test_5_invalid_agent_api_key_returns_401(self):
        """5. POST with invalid AGENT_API_KEY: assert 401 Unauthorized."""
        invalid_headers = {"Authorization": "Bearer INVALID_COMPROMISED_KEY"}
        payload = self._create_sample_payload()
        response = self.client.post("/api/v1/telemetry", headers=invalid_headers, json=payload)
        self.assertEqual(response.status_code, 401)
        self.assertIn("AGENT_KEY_REJECTED", response.json()["detail"])

    def test_6_fleet_wide_fusion_lateral_movement_alert(self):
        """6. Fleet fusion: 3 hosts with IAS >= 3.0 in 5-minute window generates LATERAL_MOVEMENT alert."""
        fusion_engine = FleetFusionEngine()
        now = datetime.now(timezone.utc)

        # Record 3 distinct hosts with elevated IAS in same workload class
        fusion_engine.record_observation({
            "hostname": "nic-delhi-01",
            "workload_class": "DATABASE",
            "ias_score": 3.6,
            "observed_at_dt": now - timedelta(minutes=1),
        })
        fusion_engine.record_observation({
            "hostname": "nic-delhi-02",
            "workload_class": "DATABASE",
            "ias_score": 3.8,
            "observed_at_dt": now - timedelta(minutes=2),
        })
        fusion_engine.record_observation({
            "hostname": "nic-delhi-03",
            "workload_class": "DATABASE",
            "ias_score": 4.1,
            "observed_at_dt": now - timedelta(minutes=3),
        })

        alerts = fusion_engine.evaluate_fleet_fusion()
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "LATERAL_MOVEMENT")
        self.assertEqual(alert.confidence_source, "FLEET_CORRELATION")
        self.assertEqual(len(alert.affected_hosts), 3)
        self.assertIn("nic-delhi-01", alert.affected_hosts)

    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    @patch("telemetry.buffer_in_redis")
    @patch("auth.get_supabase_client")
    @patch("telemetry.get_supabase_client")
    def test_neg_1_supabase_down_buffers_and_returns_503(
        self, mock_telemetry_sb, mock_auth_sb, mock_redis_buffer
    ):
        """Negative 1: Supabase connection down: returns 503 and buffers locally in Redis."""
        mock_sb = MagicMock()
        mock_sb.table.return_value.insert.side_effect = Exception("Supabase connection timeout")
        mock_telemetry_sb.return_value = mock_sb
        mock_auth_sb.return_value = mock_sb

        payload = self._create_sample_payload()
        response = self.client.post("/api/v1/telemetry", headers=self.auth_headers, json=payload)

        self.assertEqual(response.status_code, 503)
        mock_redis_buffer.assert_called_once()

    @patch("httpx.AsyncClient.post", side_effect=Exception("BRAHMA network unreachable"))
    @patch("auth.get_supabase_client")
    @patch("telemetry.get_supabase_client")
    def test_neg_2_brahma_down_does_not_fail_ingestion(
        self, mock_telemetry_sb, mock_auth_sb, mock_http
    ):
        """Negative 2: BRAHMA service down: logs error, continues ingestion, does NOT fail telemetry POST."""
        mock_sb = MagicMock()
        mock_sb.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "obs_brahma_down"}])
        mock_sb.table.return_value.upsert.return_value.execute.return_value = MagicMock(data=[{}])
        mock_telemetry_sb.return_value = mock_sb
        mock_auth_sb.return_value = mock_sb

        # Elevated IAS to trigger BRAHMA
        payload = self._create_sample_payload(pkg_w=60.0)
        response = self.client.post("/api/v1/telemetry", headers=self.auth_headers, json=payload)
        self.assertEqual(response.status_code, 200)

    def test_neg_3_malformed_payload_returns_422(self):
        """Negative 3: Malformed payload (missing hostname): returns 422 with field-level error."""
        bad_payload = self._create_sample_payload()
        del bad_payload["hostname"]

        response = self.client.post("/api/v1/telemetry", headers=self.auth_headers, json=bad_payload)
        self.assertEqual(response.status_code, 422)

    @patch("auth.get_supabase_client")
    @patch("telemetry.get_supabase_client")
    def test_neg_4_rapl_unavailable_computes_partial_ias(
        self, mock_telemetry_sb, mock_auth_sb
    ):
        """Negative 4: RAPL_UNAVAILABLE=true: accepts payload, marks rapl as null, still computes partial IAS."""
        mock_sb = MagicMock()
        mock_sb.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "obs_no_rapl"}])
        mock_sb.table.return_value.upsert.return_value.execute.return_value = MagicMock(data=[{}])
        mock_telemetry_sb.return_value = mock_sb
        mock_auth_sb.return_value = mock_sb

        payload = self._create_sample_payload(rapl_unavailable=True)
        response = self.client.post("/api/v1/telemetry", headers=self.auth_headers, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNotNone(data["computed_ias"])
        self.assertEqual(data["status"], "success")


if __name__ == "__main__":
    unittest.main()
