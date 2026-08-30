"""
DHARMA Tier 0 Autonomous Executor
Executes deterministic, low-risk containment actions in < 5 seconds upon CRITICAL IAS detection.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from .action_log import ActionLogRepository
from .agent_commander import AgentCommander
from .cloudflare_dns import CloudflareDNS
from .plan_cache import PlanCache
from .rollback_manager import RollbackManager

logger = logging.getLogger("brahma.dharma.tier0")


class Tier0Executor:
    """
    Executes automated Tier 0 containment directives:
    1. Sensor Intensification (10Hz)
    2. Credential Shadow Rotation (Canary tokens)
    3. DNS Sinkholing (Strictly gated by STIX threat intel)
    """

    def __init__(
        self,
        commander: Optional[AgentCommander] = None,
        cloudflare: Optional[CloudflareDNS] = None,
        plan_cache: Optional[PlanCache] = None,
        action_log: Optional[ActionLogRepository] = None,
        rollback_mgr: Optional[RollbackManager] = None,
    ):
        self.commander = commander or AgentCommander()
        self.cloudflare = cloudflare or CloudflareDNS()
        self.plan_cache = plan_cache or PlanCache()
        self.action_log = action_log or ActionLogRepository()
        self.rollback_mgr = rollback_mgr or RollbackManager(self.commander)

    async def execute_sensor_intensification(
        self,
        agent_id: str,
        ias_score: float,
        rate_hz: int = 10,
        duration_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """
        Commands the agent to intensify physical and kernel polling to 10Hz.
        """
        action_id = f"act-intensify-{uuid.uuid4().hex[:8]}"
        cmd = {"command": "set_poll_rate", "rate_hz": rate_hz, "duration_sec": duration_seconds}

        # 1. Pre-compute rollback state
        rollback_state = self.rollback_mgr.compute_rollback_state(
            "SENSOR_INTENSIFICATION",
            agent_id,
            {"previous_rate_hz": 1.0, "agent_id": agent_id},
        )

        # 2. Dispatch command to agent
        self.commander.send_command(agent_id, cmd)

        # 3. Store timer in cache
        self.plan_cache.set_plan(
            f"dharma:intensify:{agent_id}",
            {"rate_hz": rate_hz, "action_id": action_id},
            ttl_seconds=duration_seconds,
        )

        # 4. Log action
        await self.action_log.log_action(
            action_id=action_id,
            action_type="SENSOR_INTENSIFICATION",
            tier=0,
            target=agent_id,
            ias_score_before=ias_score,
            rollback_available=True,
            rollback_state=rollback_state,
        )

        logger.info(f"Sensor intensification (10Hz) dispatched for agent {agent_id}.")
        return {
            "action_id": action_id,
            "status": "EXECUTED",
            "action_type": "SENSOR_INTENSIFICATION",
            "rate_hz": rate_hz,
            "rollback_state": rollback_state,
        }

    async def execute_credential_rotation(
        self,
        agent_id: str,
        ias_score: float,
    ) -> Dict[str, Any]:
        """
        Deploys shadow canary credentials to detect unauthorized lateral file access.
        """
        action_id = f"act-canary-{uuid.uuid4().hex[:8]}"
        canary_id = uuid.uuid4().hex[:10]
        canary_path = f"/etc/garuda_maya/creds_{canary_id}.txt"
        canary_content = f"# GARUDA CANARY CREDENTIALS\nAWS_SECRET_KEY=AKIA{uuid.uuid4().hex.upper()[:16]}\n"

        rollback_state = self.rollback_mgr.compute_rollback_state(
            "CREDENTIAL_SHADOW_ROTATION",
            canary_path,
            {"agent_id": agent_id},
        )

        cmd = {"command": "write_canary", "path": canary_path, "content": canary_content}
        self.commander.send_command(agent_id, cmd)

        await self.action_log.log_action(
            action_id=action_id,
            action_type="CREDENTIAL_SHADOW_ROTATION",
            tier=0,
            target=canary_path,
            ias_score_before=ias_score,
            rollback_available=True,
            rollback_state=rollback_state,
        )

        return {
            "action_id": action_id,
            "status": "EXECUTED",
            "canary_path": canary_path,
            "rollback_state": rollback_state,
        }

    async def execute_dns_sinkhole(
        self,
        domain: str,
        ias_score: float,
    ) -> Dict[str, Any]:
        """
        Sinkholes verified malicious C2 domain to 127.0.0.1.
        """
        action_id = f"act-sinkhole-{uuid.uuid4().hex[:8]}"
        rollback_state = self.rollback_mgr.compute_rollback_state("DNS_SINKHOLE", domain)

        res = self.cloudflare.sinkhole_domain(domain)
        if res.get("success"):
            await self.action_log.log_action(
                action_id=action_id,
                action_type="DNS_SINKHOLE",
                tier=0,
                target=domain,
                ias_score_before=ias_score,
                rollback_available=True,
                rollback_state=rollback_state,
            )

        return {
            "action_id": action_id,
            "result": res,
            "rollback_state": rollback_state,
        }
