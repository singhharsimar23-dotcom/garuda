"""
GARUDA Phase 3 — End-to-End System Integration Test Suite
Validates the complete cross-service pipeline:
garuda-agent -> AXIOM-II (Physics) -> BRAHMA (Adversary) -> DHARMA (Response) -> UTNE (Narrative) -> KALI-PRIME
"""

import asyncio
import os
import sys
import unittest

# Ensure all service paths are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "axiom-service"))
sys.path.insert(0, os.path.join(BASE_DIR, "brahma-service"))
sys.path.insert(0, os.path.join(BASE_DIR, "network-service"))
sys.path.insert(0, BASE_DIR)

from axiom.models.telemetry import ChannelObservation, TelemetryRequest, WorkloadClass
from axiom.services.ias_computer import compute_ias
from brahma.services.bayesian_updater import BayesianUpdater
from dharma.plan_cache import PlanCache
from dharma.rollback_manager import RollbackManager
from dharma.tier0_executor import Tier0Executor
from dharma.tier1_authorizer import Tier1Authorizer
from kali.anps_batch import ANPSBatchRunner
from kali.dharma_populator import DharmaPopulator
from utne.groq_synthesizer import UTNESynthesizer
from utne.rate_limiter import BudgetLimiter


class TestEndToEndPhase3Pipeline(unittest.TestCase):
    """Full end-to-end multi-service integration tests."""

    def setUp(self):
        self.agent_id = "test-e2e-node-01"
        self.hostname = "delhi-core-border.nic.in"
        self.updater = BayesianUpdater()
        self.plan_cache = PlanCache()
        self.rollback_mgr = RollbackManager()
        self.tier0 = Tier0Executor(None, None, self.plan_cache, None, self.rollback_mgr)
        self.tier1 = Tier1Authorizer(None, self.plan_cache, None, self.rollback_mgr)
        self.synthesizer = UTNESynthesizer(budget_limiter=BudgetLimiter())

    def test_01_full_telemetry_and_ias_cycle(self):
        """Test 1: Agent readings processed by IAS computer produce clean baseline scores."""
        # Clean baseline reading
        reading = ChannelObservation(
            timestamp=1700000000.0,
            rapl_pkg_uw=15200000.0,
            rapl_core_uw=10100000.0,
            instructions=1000000,
            cache_misses=5000,
            cycles=1200000,
            ipc=0.83,
            entropy_avail=3800,
            sched_run_ms=1000.0,
            sched_wait_ms=20.0,
        )
        obs_dict = reading.model_dump()
        baseline = {
            "mu": {"rapl_pkg": 15000000.0, "rapl_core": 10000000.0},
            "sigma": {"rapl_pkg": 1000000.0, "rapl_core": 800000.0},
            "trust_established": True,
        }
        ias_res = compute_ias(obs_dict, baseline)
        self.assertLess(ias_res.score, 3.0)
        self.assertTrue(ias_res.calibrated)

    def test_02_critical_anomaly_and_response_cascade(self):
        """Test 2: CRITICAL IAS anomaly cascades through BRAHMA Bayesian update, DHARMA Tier 0/1, and UTNE."""
        async def _run():
            # 1. Simulate CRITICAL physical anomaly
            ias_score = 5.8
            top_channels = [
                {"channel": "rapl_pkg", "score": 5.2},
                {"channel": "perf_cache", "score": 4.1},
            ]

            # 2. Update BRAHMA adversary state
            brahma_res = await self.updater.process_anomaly_event(
                agent_id=self.agent_id,
                hostname=self.hostname,
                ias_score=ias_score,
                top_channels=top_channels,
            )
            self.assertIn("map_tactic", brahma_res)
            self.assertAlmostEqual(sum(brahma_res["posterior"].values()), 1.0, places=4)

            # 3. Trigger DHARMA Tier 0 Sensor Intensification (10Hz)
            t0_res = await self.tier0.execute_sensor_intensification(self.agent_id, ias_score)
            self.assertEqual(t0_res["status"], "EXECUTED")
            self.assertEqual(t0_res["rate_hz"], 10)

            # 4. Queue DHARMA Tier 1 Process Isolation for PID 9140
            t1_queued = self.tier1.queue_process_isolation(
                agent_id=self.agent_id,
                target_pid=9140,
                ias_score=ias_score,
                evidence_summary="L3 Cache Miss Spike + Microarchitectural Power Surge",
            )
            self.assertEqual(t1_queued["status"], "PENDING_APPROVAL")

            # 5. Build evidence bundle and generate UTNE SITREP
            evidence = {
                "active_anomalies": [{"hostname": self.hostname, "ias_score": ias_score, "top_channels": top_channels}],
                "brahma_assessments": [brahma_res],
                "pending_tier1_actions": 1,
            }
            sitrep_res = self.synthesizer.generate_sitrep(evidence)
            self.assertEqual(sitrep_res["status"], "SUCCESS")
            self.assertIn("GARUDA UTNE OPERATIONAL SITUATION REPORT", sitrep_res["sitrep_text"])
            self.assertIn("NODE-EVID-1", sitrep_res["sitrep_text"])

        asyncio.run(_run())

    def test_03_tier1_authorization_and_rollback(self):
        """Test 3: Operator approves Tier 1 action, executes containment, and computes rollback."""
        async def _run():
            # Queue action
            queued = self.tier1.queue_process_isolation(
                agent_id=self.agent_id,
                target_pid=4412,
                ias_score=6.1,
                evidence_summary="Reflective DLL Injection detected.",
            )
            action_id = queued["action_id"]

            # Approve action
            auth_res = await self.tier1.authorize_action(action_id, decision="APPROVE")
            self.assertTrue(auth_res["success"])
            self.assertEqual(auth_res["decision"], "APPROVED")

            # Verify rollback execution
            rb_state = queued["rollback_state"]
            self.assertEqual(rb_state["action_type"], "SIGCONT_PID")
            rb_success = self.rollback_mgr.execute_rollback(rb_state)
            self.assertTrue(rb_success)

        asyncio.run(_run())

    def test_04_brahma_bayesian_convergence(self):
        """Test 4: 20 sequential C2/Execution anomalies lead to Bayesian convergence & APT36 attribution."""
        async def _run():
            last_res = None
            for _ in range(20):
                last_res = await self.updater.process_anomaly_event(
                    agent_id=self.agent_id,
                    hostname=self.hostname,
                    ias_score=6.0,
                    top_channels=[
                        {"channel": "rapl_pkg", "score": 5.5},
                        {"channel": "entropy", "score": 4.2},
                    ],
                )

            self.assertEqual(last_res["observation_count"], 20)
            self.assertIn(last_res["actor_id"], ["APT36", "APT36 (possible)"])
            self.assertIn(last_res["convergence_status"], ["CONVERGED", "CONVERGING"])

        asyncio.run(_run())

    def test_05_kali_anps_and_dharma_caching(self):
        """Test 5: KALI ANPS discovers candidate paths and pre-populates DHARMA plan cache."""
        runner = ANPSBatchRunner(max_batch_size=15)
        discoveries = runner.synthesize_candidate_paths(actor_id="APT36")
        self.assertGreater(len(discoveries), 0)

        populator = DharmaPopulator()
        cached_count = populator.populate_top_paths(discoveries, actor_id="APT36", top_n=10)
        self.assertEqual(cached_count, min(10, len(discoveries)))

        plans = populator.get_cached_plans()
        first_key = list(plans.keys())[0]
        self.assertIn("dharma:plan:APT36:", first_key)


if __name__ == "__main__":
    unittest.main()
