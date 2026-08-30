"""
Acceptance and Negative Tests for garuda-brahma-service.
Covers real MITRE ATT&CK G0134 extraction, Dirichlet-Multinomial Bayesian update,
strict Rule 8 attribution gating (>=15 observations), and absence of fake confidence percentages.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add brahma-service directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from brahma.bayesian_engine import BayesianEngine, HostBayesianState, get_bayesian_engine
from brahma.config import get_settings
from brahma.main import app
from brahma.mitre_pipeline import MitreTrainingPipeline, TACTIC_NAMES, get_mitre_pipeline


class TestBrahmaService(unittest.TestCase):
    """Test suite for BRAHMA Adversary Modeling Microservice."""

    def setUp(self):
        self.client = TestClient(app)
        self.settings = get_settings()
        self.auth_headers = {"X-Inter-Service-Secret": self.settings.inter_service_secret}

    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    def test_1_mitre_attack_empirical_prior_non_uniform(self):
        """1. Download/Parse MITRE ATT&CK: assert G0134 techniques found, alpha_counts non-uniform."""
        pipeline = MitreTrainingPipeline()
        
        # Test extraction with mocked or fallback MITRE bundle
        sample_stix = {
            "objects": [
                {
                    "id": "intrusion-set--apt36",
                    "type": "intrusion-set",
                    "name": "APT36",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "G0134"}],
                },
                {
                    "id": "attack-pattern--process-injection",
                    "type": "attack-pattern",
                    "name": "Process Injection",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                },
                {
                    "id": "attack-pattern--c2-protocols",
                    "type": "attack-pattern",
                    "name": "Application Layer Protocol",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}],
                },
                {
                    "id": "rel--1",
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": "intrusion-set--apt36",
                    "target_ref": "attack-pattern--process-injection",
                },
                {
                    "id": "rel--2",
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": "intrusion-set--apt36",
                    "target_ref": "attack-pattern--c2-protocols",
                },
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = sample_stix

        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            asyncio.run(pipeline.run_pipeline())

            self.assertEqual(len(pipeline.alpha_prior), 14)
            # Alpha counts must be non-uniform (execution / c2 have higher prior)
            self.assertNotEqual(min(pipeline.alpha_prior), max(pipeline.alpha_prior))
            self.assertIn("T1055", pipeline.technique_inventory)

    def test_2_post_observe_updates_alpha_counts(self):
        """2. POST /internal/observe with IAS=3.5, workload=execution: assert alpha_counts updated."""
        hostname = "drdo-border-node-01"
        engine = get_bayesian_engine()
        state_before = engine.get_or_create_state(hostname)
        initial_alphas = list(state_before.alphas)
        initial_sum = sum(initial_alphas)

        payload = {
            "hostname": hostname,
            "ias_score": 3.5,
            "channel_sigmas": {"rapl_pkg": 3.8, "perf_cache_miss": 3.2},
            "workload_class": "EXECUTION",
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }

        response = self.client.post("/internal/observe", headers=self.auth_headers, json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["hostname"], hostname)
        self.assertGreater(data["observation_count"], 0)

        # Alpha counts must have increased
        state_after = engine.get_or_create_state(hostname)
        updated_sum = sum(state_after.alphas)
        self.assertGreater(updated_sum, initial_sum)

    def test_3_fourteen_observations_shows_accumulating_status(self):
        """3. After 14 observations: assert attribution_status = 'ACCUMULATING EVIDENCE (14/15 minimum)'."""
        hostname = "drdo-border-node-14"
        engine = get_bayesian_engine()
        state = engine.get_or_create_state(hostname)
        state.observation_count = 13  # Next will be 14th

        payload = {
            "hostname": hostname,
            "ias_score": 3.5,
            "channel_sigmas": {"rapl_pkg": 3.4},
            "workload_class": "EXECUTION",
        }

        response = self.client.post("/internal/observe", headers=self.auth_headers, json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["observation_count"], 14)
        self.assertEqual(data["attribution_status"], "ACCUMULATING EVIDENCE (14/15 minimum)")

    def test_4_fifteen_plus_observations_attributes_actor(self):
        """4. After 15+ observations with physics corroboration: assert attribution_status = 'ATTRIBUTED — APT36 (Transparent Tribe)'."""
        hostname = "drdo-border-node-15"
        engine = get_bayesian_engine()
        state = engine.get_or_create_state(hostname)
        state.observation_count = 14
        state.medium_ias_observations = 2
        state.has_distinctive_physics_corroboration = True
        state.max_distinctive_sigma = 4.2
        # Concentrate mass on execution
        state.alphas[TACTIC_NAMES.index("execution")] += 50.0

        payload = {
            "hostname": hostname,
            "ias_score": 4.5,
            "channel_sigmas": {"rapl_pkg": 4.2, "perf_cache_miss": 3.8},
            "workload_class": "EXECUTION",
        }

        response = self.client.post("/internal/observe", headers=self.auth_headers, json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["observation_count"], 15)
        self.assertEqual(data["attribution_status"], "ATTRIBUTED — APT36 (Transparent Tribe)")

    def test_5_get_kill_chain_no_confidence_percentage(self):
        """5. GET /api/v1/kill-chain/{hostname}: assert NO 'Confidence' key with percentage in response."""
        hostname = "drdo-verified-node"
        response = self.client.get(f"/api/v1/kill-chain/{hostname}")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Anti-Hallucination Charter: No fake confidence percentages
        self.assertNotIn("confidence", data)
        self.assertIn("attribution_status", data)
        self.assertIn("posterior", data)
        self.assertIn("top_tactic_mass", data)

        # Posterior sum must be approximately 1.0
        posterior_sum = sum(data["posterior"].values())
        self.assertAlmostEqual(posterior_sum, 1.0, places=3)

    def test_6_alpha_counts_sum_invariant(self):
        """6. GET /api/v1/kill-chain: assert alpha_counts increases deterministically per evidence update."""
        hostname = "drdo-math-test"
        engine = get_bayesian_engine()
        state = engine.get_or_create_state(hostname)
        initial_sum = sum(state.alphas)

        # Send observation
        payload = {
            "hostname": hostname,
            "ias_score": 3.0,
            "channel_sigmas": {"rapl_pkg": 2.0},
        }
        self.client.post("/internal/observe", headers=self.auth_headers, json=payload)

        resp = self.client.get(f"/api/v1/kill-chain/{hostname}")
        data = resp.json()
        new_sum = sum(data["alpha_counts"])

        self.assertGreater(new_sum, initial_sum)

    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    def test_neg_1_mitre_url_down_uses_fallback_prior(self):
        """Negative 1: MITRE URL down at startup: load from empirical fallback prior without crashing."""
        pipeline = MitreTrainingPipeline()
        with patch("httpx.AsyncClient.get", side_effect=Exception("MITRE DNS resolution failure")):
            asyncio.run(pipeline.run_pipeline())
            self.assertEqual(len(pipeline.alpha_prior), 14)
            self.assertGreater(sum(pipeline.alpha_prior), 14.0)

    def test_neg_2_otx_down_proceeds_with_mitre_only(self):
        """Negative 2: OTX down: skip OTX enrichment, proceed with MITRE-only prior."""
        pipeline = MitreTrainingPipeline(otx_api_key="TEST_KEY")
        
        async def mock_get(url, *args, **kwargs):
            if "alienvault" in url:
                raise Exception("OTX API 500 error")
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"objects": []}
            return mock_resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            asyncio.run(pipeline.run_pipeline())
            self.assertEqual(len(pipeline.alpha_prior), 14)

    def test_neg_3_under_15_observations_returns_accumulating(self):
        """Negative 3: < 15 observations: GET kill-chain returns ACCUMULATING status, NOT attribution."""
        hostname = "drdo-young-node"
        engine = get_bayesian_engine()
        state = engine.get_or_create_state(hostname)
        state.observation_count = 5

        resp = self.client.get(f"/api/v1/kill-chain/{hostname}")
        data = resp.json()
        self.assertIn("ACCUMULATING EVIDENCE", data["attribution_status"])
        self.assertNotIn("ATTRIBUTED —", data["attribution_status"])

    def test_neg_4_low_ias_observation_minimal_alpha_update(self):
        """Negative 4: Inject observation with IAS=0.5: assert alpha_counts change is minimal."""
        hostname = "drdo-clean-node"
        engine = get_bayesian_engine()
        state = engine.get_or_create_state(hostname)
        initial_alphas = list(state.alphas)
        initial_sum = sum(initial_alphas)

        payload = {
            "hostname": hostname,
            "ias_score": 0.5,
            "channel_sigmas": {"rapl_pkg": 0.2},
        }
        self.client.post("/internal/observe", headers=self.auth_headers, json=payload)

        state_after = engine.get_or_create_state(hostname)
        delta_sum = sum(state_after.alphas) - initial_sum

        # Low-evidence update indicator is 0.05, so delta sum across 14 tactics should be <= 0.25
        self.assertLess(delta_sum, 0.25)

    def test_neg_5_unauthorized_internal_observe_returns_401(self):
        """Negative 5: POST /internal/observe without valid INTER_SERVICE_SECRET returns 401."""
        bad_headers = {"X-Inter-Service-Secret": "WRONG_SECRET"}
        payload = {"hostname": "drdo-node", "ias_score": 2.0}
        resp = self.client.post("/internal/observe", headers=bad_headers, json=payload)
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
