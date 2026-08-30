"""
DHARMA Tier 1 Human-in-the-Loop Authorizer & SLA Enforcer
Manages pending containment actions requiring operator approval with 15-minute SLA timeout.
"""

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from .action_log import ActionLogRepository
from .agent_commander import AgentCommander
from .plan_cache import PlanCache
from .rollback_manager import RollbackManager

logger = logging.getLogger("brahma.dharma.tier1")


class Tier1Authorizer:
    """
    Manages Tier 1 human-authorized actions (Process Isolation via SIGSTOP) and SLA enforcement.
    """

    def __init__(
        self,
        commander: Optional[AgentCommander] = None,
        plan_cache: Optional[PlanCache] = None,
        action_log: Optional[ActionLogRepository] = None,
        rollback_mgr: Optional[RollbackManager] = None,
    ):
        self.commander = commander or AgentCommander()
        self.plan_cache = plan_cache or PlanCache()
        self.action_log = action_log or ActionLogRepository()
        self.rollback_mgr = rollback_mgr or RollbackManager(self.commander)

    def queue_process_isolation(
        self,
        agent_id: str,
        target_pid: int,
        ias_score: float,
        evidence_summary: str,
        ttl_seconds: int = 900,  # 15 minutes
    ) -> Dict[str, Any]:
        """
        Queues a process isolation action awaiting operator authorization.
        """
        action_id = f"act-iso-{uuid.uuid4().hex[:8]}"
        rollback_state = self.rollback_mgr.compute_rollback_state(
            "PROCESS_ISOLATION",
            str(target_pid),
            {"agent_id": agent_id, "pid": target_pid},
        )

        item = {
            "action_id": action_id,
            "action_type": "PROCESS_ISOLATION",
            "tier": 1,
            "agent_id": agent_id,
            "target_pid": target_pid,
            "ias_score": ias_score,
            "evidence_summary": evidence_summary,
            "status": "PENDING_APPROVAL",
            "queued_at": time.time(),
            "ttl_seconds": ttl_seconds,
            "rollback_state": rollback_state,
            "authorization_url": f"https://garuda-ochre.vercel.app/dharma/auth?action_id={action_id}",
        }

        # Queue in Redis plan cache with 15-min TTL
        self.plan_cache.set_plan(f"dharma:pending:{action_id}", item, ttl_seconds=ttl_seconds)
        logger.info(f"Queued Tier 1 Process Isolation for PID {target_pid} on {agent_id} (ID: {action_id}).")
        return item

    async def authorize_action(
        self,
        action_id: str,
        decision: str = "APPROVE",
        operator_id: str = "operator_hq",
    ) -> Dict[str, Any]:
        """
        Processes operator approval or rejection for a pending Tier 1 action.
        """
        item = self.plan_cache.get_plan(f"dharma:pending:{action_id}")
        if not item:
            return {
                "success": False,
                "action_id": action_id,
                "message": "Action not found or expired from pending queue.",
            }

        decision_upper = decision.upper()
        if decision_upper == "APPROVE":
            # 1. Execute process isolation via agent command
            agent_id = item.get("agent_id")
            pid = item.get("target_pid")
            cmd = {"command": "sigstop_pid", "pid": pid}
            self.commander.send_command(agent_id, cmd)

            # 2. Append to immutable action log
            await self.action_log.log_action(
                action_id=action_id,
                action_type="PROCESS_ISOLATION",
                tier=1,
                target=f"pid_{pid}",
                ias_score_before=item.get("ias_score", 0.0),
                rollback_available=True,
                rollback_state=item.get("rollback_state"),
                operator_id=operator_id,
            )

            # 3. Clean up queue
            self.plan_cache.delete_plan(f"dharma:pending:{action_id}")
            logger.info(f"Tier 1 Action {action_id} APPROVED by {operator_id}. SIGSTOP dispatched for PID {pid}.")
            return {
                "success": True,
                "action_id": action_id,
                "decision": "APPROVED",
                "message": f"Process {pid} on agent {agent_id} isolated via SIGSTOP.",
            }

        else:
            # Operator rejected
            self.plan_cache.delete_plan(f"dharma:pending:{action_id}")
            logger.info(f"Tier 1 Action {action_id} REJECTED by {operator_id}.")
            return {
                "success": True,
                "action_id": action_id,
                "decision": "REJECTED",
                "message": "Action cancelled by operator.",
            }

    def enforce_sla(self, max_pending_age_sec: int = 900) -> List[Dict[str, Any]]:
        """
        Checks for expired or unanswered Tier 1 actions and triggers escalation.
        """
        escalated = []
        now = time.time()
        pending_items = self.plan_cache.get_all_pending_actions()

        for item in pending_items:
            age = now - item.get("queued_at", now)
            if age >= max_pending_age_sec:
                action_id = item.get("action_id")
                logger.warning(f"SLA breached for action {action_id} (age: {age:.0f}s >= {max_pending_age_sec}s). Escalating!")
                escalated.append({
                    "action_id": action_id,
                    "agent_id": item.get("agent_id"),
                    "status": "ESCALATED_UNANSWERED",
                    "age_sec": age,
                })
        return escalated
