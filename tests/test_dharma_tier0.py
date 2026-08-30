"""
Acceptance Tests for DHARMA Autonomous Response Engine (Tier 0 & Tier 1)
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from dharma.action_log import ActionLogRepository
from dharma.agent_commander import AgentCommander
from dharma.cloudflare_dns import CloudflareDNS
from dharma.plan_cache import PlanCache
from dharma.rollback_manager import RollbackManager
from dharma.tier0_executor import Tier0Executor
from dharma.tier1_authorizer import Tier1Authorizer


class TestDharmaTier0(unittest.TestCase):
    """Test suite for Tier 0 containment, Tier 1 authorization, and rollback management."""

    def setUp(self):
        self.commander = AgentCommander()
        self.plan_cache = PlanCache()
        self.action_log = ActionLogRepository()
        self.rollback_mgr = RollbackManager(self.commander)
        self.tier0 = Tier0Executor(
            self.commander, None, self.plan_cache, self.action_log, self.rollback_mgr
        )
        self.tier1 = Tier1Authorizer(
            self.commander, self.plan_cache, self.action_log, self.rollback_mgr
        )

    def test_sensor_intensification_via_supabase(self):
        """CRITICAL anomaly triggers sensor intensification (10Hz) and caches timer."""
        async def _test():
            res = await self.tier0.execute_sensor_intensification(
                agent_id="test-node-01",
                ias_score=6.4,
                rate_hz=10,
                duration_seconds=3600,
            )
            self.assertEqual(res["status"], "EXECUTED")
            self.assertEqual(res["rate_hz"], 10)
            
            # Verify cached timer
            cached = self.plan_cache.get_plan("dharma:intensify:test-node-01")
            self.assertIsNotNone(cached)
            self.assertEqual(cached.get("rate_hz"), 10)

        asyncio.run(_test())

    def test_rollback_state_computed(self):
        """Every action must have a valid pre-computed deterministic rollback state."""
        rb_intensify = self.rollback_mgr.compute_rollback_state(
            "SENSOR_INTENSIFICATION", "agent-hq-01", {"previous_rate_hz": 1.0, "agent_id": "agent-hq-01"}
        )
        self.assertIn("rollback_id", rb_intensify)
        self.assertEqual(rb_intensify["action_type"], "REVERT_SENSOR_POLL_RATE")

        rb_proc = self.rollback_mgr.compute_rollback_state(
            "PROCESS_ISOLATION", "4521", {"pid": 4521, "agent_id": "agent-hq-01"}
        )
        self.assertEqual(rb_proc["action_type"], "SIGCONT_PID")
        self.assertEqual(rb_proc["target_pid"], 4521)

    def test_sla_enforcement(self):
        """Unanswered Tier 1 action queued in Redis triggers escalation when age >= timeout."""
        # Queue action with 0 second age threshold for immediate test
        queued = self.tier1.queue_process_isolation(
            agent_id="agent-01",
            target_pid=9821,
            ias_score=7.1,
            evidence_summary="Heavy crypto memory burst.",
            ttl_seconds=900,
        )
        self.assertIn("action_id", queued)
        self.assertEqual(queued["status"], "PENDING_APPROVAL")

        # Check SLA with 0 threshold to verify escalation logic
        escalated = self.tier1.enforce_sla(max_pending_age_sec=0)
        self.assertGreaterEqual(len(escalated), 1)
        self.assertEqual(escalated[0]["action_id"], queued["action_id"])
        self.assertEqual(escalated[0]["status"], "ESCALATED_UNANSWERED")

    def test_dns_sinkhole_gating(self):
        """DNS sinkhole must reject unverified domains not present in threat intel."""
        cf = CloudflareDNS()
        res = cf.sinkhole_domain("random-legitimate-website.org")
        self.assertFalse(res["success"])
        self.assertIn("REJECTED_GATING", res["reason"])


if __name__ == "__main__":
    unittest.main()
