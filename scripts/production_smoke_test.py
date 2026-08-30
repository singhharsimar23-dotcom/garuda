"""
GARUDA End-to-End Production Readiness & Cross-Integration Smoke Test
Validates environment configurations, SQL schemas, inter-service API contracts, and live telemetry flows.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import sys
from typing import Any, Dict, List
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../network-service")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../sentinel-service")))


class TestProductionReadiness(unittest.TestCase):
    """Deep production integration verification test suite."""

    def test_1_environment_configuration_completeness(self):
        """1. Verify .env.example contains all required production secrets and URLs."""
        env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.env.example"))
        self.assertTrue(os.path.exists(env_path))

        with open(env_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_keys = [
            "SUPABASE_URL",
            "SUPABASE_SERVICE_ROLE_KEY",
            "INTER_SERVICE_SECRET",
            "AGENT_API_KEY",
            "GROQ_API_KEY",
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_ZONE_ID",
            "UPSTASH_REDIS_REST_URL",
            "TELEGRAM_BOT_TOKEN",
            "AXIOM_SERVICE_URL",
            "BRAHMA_SERVICE_URL",
            "SENTINEL_SERVICE_URL",
            "UTNE_SERVICE_URL",
        ]
        for key in required_keys:
            self.assertIn(key, content, f"Missing {key} in .env.example")

    def test_2_render_yaml_all_four_microservices(self):
        """2. Verify render.yaml declares all 4 microservices with health checks."""
        yaml_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../render.yaml"))
        self.assertTrue(os.path.exists(yaml_path))

        with open(yaml_path, "r", encoding="utf-8") as f:
            content = f.read()

        expected_services = [
            "garuda-axiom-service",
            "garuda-brahma-service",
            "garuda-utne-service",
            "garuda-sentinel-service",
        ]
        for s in expected_services:
            self.assertIn(f"name: {s}", content)
            self.assertIn("healthCheckPath: /health", content)

    def test_3_sql_schema_integrity_and_rls(self):
        """3. Verify master SQL schema enables RLS across all 16 Phase 3 tables."""
        schema_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../migrations/000_master_production_schema.sql")
        )
        self.assertTrue(os.path.exists(schema_path))

        with open(schema_path, "r", encoding="utf-8") as f:
            sql = f.read()

        required_tables = [
            "agent_registry",
            "agent_heartbeats",
            "physics_observations",
            "almanac_baselines",
            "eppi_provdag_graphs",
            "brahma_program_models",
            "brahma_label_history",
            "model_drift_log",
            "dharma_action_log",
            "kali_discoveries",
            "kali_technique_estimates",
            "campaigns",
            "multi_host_campaigns",
            "prediction_log",
            "host_calibration",
            "calibration_log",
        ]
        for tbl in required_tables:
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {tbl}", sql)
            self.assertIn(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY", sql)

    def test_4_cross_service_telemetry_to_sentinel_pipeline(self):
        """4. End-to-end telemetry pipeline: Agent Telemetry -> AXIOM IAS -> BRAHMA -> SENTINEL."""
        from garuda_agent.ias import gaussian_kl_divergence
        from brahma.learner import get_brahma_online_learner
        from sentinel_fusion import get_fusion_engine
        from campaign import get_campaign_manager
        from sentinel_models import EvidenceNode


        # Step 1: Agent IAS computation
        kl = gaussian_kl_divergence(mu1=45.0, sigma1=5.0, mu2=15.0, sigma2=3.0)
        self.assertGreater(kl, 3.0)
        ias_score = round(kl, 2)


        # Step 2: Multi-stream Evidence Fusion
        fusion = get_fusion_engine()
        fusion_score = fusion.compute_fusion_score(
            ias_score=ias_score,
            recent_eppi_events=[{"event_type": "MMAP_EXEC", "comm": "payload_worker"}],
            stix_matches=2,
            tension_index=0.60,
        )
        self.assertGreater(fusion_score, 4.0)

        # Step 3: Campaign Initiation in SENTINEL
        camp_mgr = get_campaign_manager()
        node = EvidenceNode(id="obs-smoke-01", source_table="physics_observations", event_type="PHYSICS_ANOMALY")
        state = asyncio.run(
            camp_mgr.update_host_campaign(
                hostname="nic-delhi-core",
                ias_score=ias_score,
                fusion_score=fusion_score,
                evidence_node=node,
            )
        )

        self.assertIsNotNone(state.campaign_id)
        self.assertEqual(state.attribution_status, "ACCUMULATING EVIDENCE (1/15)")

        # Step 4: Operator Feedback closes the loop in BRAHMA
        learner = get_brahma_online_learner()
        label_res = asyncio.run(
            learner.apply_label(
                hostname="nic-delhi-core",
                tactic="execution",
                label="POSITIVE",
            )
        )
        self.assertEqual(label_res["status"], "applied")

    def test_5_offline_model_artifacts_present_and_valid(self):
        """5. Verify all trained model artifacts exist in data/ directory."""
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
        
        required_artifacts = [
            "apt36_transition_matrix.json",
            "sidecopy_transition_matrix.json",
            "physics_likelihood.json",
            "workload_classifier.pkl",
            "workload_classifier_metadata.json",
        ]
        for art in required_artifacts:
            path = os.path.join(data_dir, art)
            self.assertTrue(os.path.exists(path), f"Missing artifact: {art}")


if __name__ == "__main__":
    unittest.main()
