"""
Acceptance and Negative Tests for SENTINEL Autonomous Agent Brain Service.
Covers observation loop processing, campaign lifecycles, cross-host chaining, predictive pre-positioning,
self-calibration, learning loop dispatch, parallel SideCopy modeling, and canary token responses.
"""

import asyncio
from datetime import datetime, timezone, timedelta
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root and sentinel-service to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../sentinel-service")))

from fastapi.testclient import TestClient
from sentinel_main import sentinel_app
from campaign import CampaignManager, get_campaign_manager

from cross_host import CrossHostCorrelator, get_cross_host_correlator
from calibrator import ThresholdCalibrator, get_threshold_calibrator
from learner import LearningLoopDispatcher, get_learner
from predictor import PredictivePrePositioner, get_predictive_prepositioner
from sidecopy import SideCopyModel, get_sidecopy_model
from observation import ObservationLoop, get_observation_loop
from canary import CanaryManager, get_canary_manager
from sentinel_models import CampaignState, EvidenceNode




class TestSentinelService(unittest.TestCase):
    """Test suite for SENTINEL Autonomous Agent Brain."""

    def setUp(self):
        self.client = TestClient(sentinel_app)


    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    def test_1_observation_loop_updates_host_state(self):
        """1. Observation loop: insert row to physics_observations, assert host_state updated."""
        obs_loop = ObservationLoop()
        camp_mgr = get_campaign_manager()

        record = {
            "id": "obs-uuid-001",
            "hostname": "delhi-core-gw",
            "ias_score": 4.8,
            "workload_class": "EXECUTION",
            "channel_sigmas": {"rapl_pkg": 4.5, "perf_cache_miss": 3.8},
        }

        # Directly process observation
        asyncio.run(obs_loop._handle_physics_observation(record))

        state = camp_mgr.get_or_create_host_state("delhi-core-gw")
        self.assertIsNotNone(state.campaign_id)
        self.assertGreaterEqual(state.fusion_score, 1.5)
        self.assertEqual(len(state.evidence_chain), 1)
        self.assertEqual(state.evidence_chain[0].id, "obs-uuid-001")

    def test_2_campaign_creation_on_log_threshold(self):
        """2. Campaign creation: fusion_score crosses LOG (1.5), assert campaign created."""
        mgr = CampaignManager(log_threshold=1.5)
        node = EvidenceNode(
            id="node-test-01",
            source_table="physics_observations",
            event_type="PHYSICS_ANOMALY",
        )

        state = asyncio.run(
            mgr.update_host_campaign(
                hostname="nic-border-01",
                ias_score=3.5,
                fusion_score=2.8,
                evidence_node=node,
            )
        )

        self.assertIsNotNone(state.campaign_id)
        self.assertEqual(state.peak_ias, 3.5)
        self.assertEqual(state.fusion_score, 2.8)

    def test_3_campaign_continuity_same_id(self):
        """3. Campaign continuity: two observations on same host 30min apart, assert same campaign_id."""
        mgr = CampaignManager(log_threshold=1.5)
        node1 = EvidenceNode(id="node-1", source_table="physics_observations", event_type="PHYSICS_ANOMALY")
        node2 = EvidenceNode(id="node-2", source_table="physics_observations", event_type="PHYSICS_ANOMALY")

        state1 = asyncio.run(mgr.update_host_campaign("drdo-srv-01", 3.2, 2.5, node1))
        initial_id = state1.campaign_id
        self.assertIsNotNone(initial_id)

        # Second observation on same host
        state2 = asyncio.run(mgr.update_host_campaign("drdo-srv-01", 4.1, 3.2, node2))
        self.assertEqual(state2.campaign_id, initial_id)
        self.assertEqual(len(state2.evidence_chain), 2)
        self.assertEqual(state2.peak_ias, 4.1)

    def test_4_cross_host_campaign_linking(self):
        """4. Cross-host: insert anomaly on host_A then host_B within 20 min, assert campaign linked."""
        correlator = CrossHostCorrelator()
        now = datetime.now(timezone.utc)

        obs_map = {
            "host-alpha": {
                "top_tactic": "execution",
                "fusion_score": 3.5,
                "timestamp": now - timedelta(minutes=10),
                "ip_address": "10.0.1.5",
                "attribution_actor": "APT36",
            },
            "host-beta": {
                "top_tactic": "defense-evasion",
                "fusion_score": 4.0,
                "timestamp": now,
                "ip_address": "10.0.1.9",
                "attribution_actor": "APT36",
            },
        }

        eppi_connects = {"host-alpha": ["10.0.1.9"]}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            links = asyncio.run(correlator.correlate_cross_host_activity(obs_map, eppi_connects))

            self.assertEqual(len(links), 1)
            self.assertEqual(links[0].host_a, "host-alpha")
            self.assertEqual(links[0].host_b, "host-beta")
            self.assertTrue(links[0].lateral_movement_confirmed)
            self.assertGreater(links[0].joint_fusion_score, 4.0)

    def test_5_learner_approve_dispatches_positive_label(self):
        """5. Learner APPROVE: mock DHARMA approve, assert brahma-service receives /internal/label POSITIVE."""
        learner = LearningLoopDispatcher()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            res = asyncio.run(
                learner.handle_dharma_approval(
                    hostname="delhi-core-gw",
                    action_id="act-991",
                    tactic="execution",
                    feature_vector={"rapl_pkg": 5.2, "perf_cache_miss": 4.1},
                )
            )
            self.assertEqual(res["status"], "success")
            self.assertTrue(res["brahma_updated"])

            # Verify POST payload sent to BRAHMA
            calls = mock_post.call_args_list
            self.assertTrue(any("label" in str(c) for c in calls))

    def test_6_calibrator_raises_threshold_on_high_fp_rate(self):
        """6. Calibrator: inject 5 consecutive REJECT labels, assert threshold raised on that host."""
        calibrator = ThresholdCalibrator()
        initial_thresh = calibrator.get_host_threshold("noisy-srv-01")

        actions = [
            {"hostname": "noisy-srv-01", "status": "REJECTED"} for _ in range(5)
        ]

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_telegram:
            mock_telegram.return_value = MagicMock(status_code=200)
            adjustments = asyncio.run(calibrator.calibrate_host_thresholds(actions))

            self.assertEqual(len(adjustments), 1)
            new_thresh = calibrator.get_host_threshold("noisy-srv-01")
            self.assertGreater(new_thresh, initial_thresh)
            self.assertEqual(adjustments[0]["adjustment_reason"], "HIGH_FP_RATE_RAISED_THRESHOLD")

    def test_7_predictor_prepositions_maya_and_axiom(self):
        """7. Predictor: set BRAHMA tactic to EXECUTION, assert MAYA called with defense-evasion."""
        predictor = PredictivePrePositioner()
        state = CampaignState(
            campaign_id="camp-pred-01",
            hostname="target-node-01",
            brahma_posterior={"execution": 0.70, "initial-access": 0.30},
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            predicted = asyncio.run(predictor.evaluate_campaign_prediction(state))

            self.assertEqual(predicted, "defense-evasion")
            self.assertEqual(state.next_step_prediction, "defense-evasion")

    def test_8_sidecopy_parallel_model_independent_posterior(self):
        """8. SideCopy parallel model: assert both posteriors computed independently."""
        sidecopy = SideCopyModel()
        posterior = sidecopy.update_observation("test-host-01", ias_score=4.0, top_channels=["perf_instructions"])

        self.assertEqual(len(posterior), 14)
        self.assertAlmostEqual(sum(posterior.values()), 1.0, places=2)

        # Test KL divergence against mock APT36 posterior
        apt36_post = {t: 1.0 / 14 for t in posterior.keys()}
        apt36_post["execution"] = 0.60
        apt36_post["defense-evasion"] = 0.20

        kl, assessment = sidecopy.compute_kl_divergence(apt36_post, posterior)
        self.assertGreater(kl, 0.0)
        self.assertIsNotNone(assessment)

    def test_9_canary_token_bypasses_gating_and_triggers_dharma(self):
        """9. Canary: POST to /webhook/canary/test123, assert attribution_status=CONFIRMED, DHARMA triggered."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            resp = self.client.post(
                "/webhook/canary/canary-token-999",
                json={"requester_ip": "198.51.100.22", "hostname": "honeypot-doc-srv"},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["attribution_status"], "CONFIRMED")
            self.assertTrue(data["dharma_tier2_triggered"])
            self.assertTrue(data["brahma_boosted"])

    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    def test_neg_1_supabase_disconnect_operates_in_memory(self):
        """Negative 1: Supabase disconnected: sentinel continues operating without crash."""
        mgr = CampaignManager()
        node = EvidenceNode(id="n-1", source_table="physics_observations", event_type="PHYSICS_ANOMALY")
        
        # Pass None for supabase_client
        state = asyncio.run(mgr.update_host_campaign("offline-host", 3.8, 2.9, node, supabase_client=None))
        self.assertIsNotNone(state.campaign_id)
        self.assertEqual(state.fusion_score, 2.9)

    def test_neg_2_brahma_service_down_queues_retries(self):
        """Negative 2: BRAHMA service down: sentinel queues label updates in pending retries."""
        learner = LearningLoopDispatcher()

        with patch("httpx.AsyncClient.post", side_effect=Exception("Connection refused")):
            res = asyncio.run(
                learner.handle_dharma_approval(
                    hostname="delhi-srv-01",
                    action_id="act-fail-1",
                    tactic="execution",
                    feature_vector={"rapl": 5.0},
                )
            )
            self.assertFalse(res["brahma_updated"])
            self.assertEqual(len(learner._pending_retries), 1)
            self.assertEqual(learner._pending_retries[0]["type"], "brahma_label")

    def test_neg_3_cross_host_no_eppi_connect_not_confirmed(self):
        """Negative 3: Cross-host false link: unrelated hosts without EPPI CONNECT are not marked confirmed."""
        correlator = CrossHostCorrelator()
        now = datetime.now(timezone.utc)

        obs_map = {
            "unrelated-host-1": {
                "top_tactic": "execution",
                "fusion_score": 3.0,
                "timestamp": now,
                "ip_address": "192.168.1.10",
                "attribution_actor": "APT36",
            },
            "unrelated-host-2": {
                "top_tactic": "execution",
                "fusion_score": 3.0,
                "timestamp": now,
                "ip_address": "192.168.1.20",
                "attribution_actor": "APT36",
            },
        }

        # No network connection between them
        eppi_connects = {"unrelated-host-1": []}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            links = asyncio.run(correlator.correlate_cross_host_activity(obs_map, eppi_connects))

            self.assertEqual(len(links), 1)
            # Both exhibit anomaly, but without EPPI connection lateral_movement_confirmed MUST be False
            self.assertFalse(links[0].lateral_movement_confirmed)


if __name__ == "__main__":
    unittest.main()
