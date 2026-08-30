"""
DHARMA Autonomous Containment & Authorization Router
Exposes endpoints for CRITICAL IAS response triggering, pending action polling, operator authorization, and rollback.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from ..config import BrahmaSettings, get_settings
from ..db.pool import get_db_pool
from dharma.action_log import ActionLogRepository
from dharma.agent_commander import AgentCommander
from dharma.plan_cache import PlanCache
from dharma.rollback_manager import RollbackManager
from dharma.tier0_executor import Tier0Executor
from dharma.tier1_authorizer import Tier1Authorizer

router = APIRouter(prefix="/api/v1/dharma", tags=["DHARMA Autonomous Response"])


class CriticalAnomalyTriggerRequest(BaseModel):
    agent_id: str
    hostname: str
    ias_score: float
    top_channels: List[Dict[str, Any]] = Field(default_factory=list)
    suspect_pid: Optional[int] = None
    suspect_domain: Optional[str] = None


class AuthorizeActionRequest(BaseModel):
    action_id: str
    decision: str = "APPROVE"  # 'APPROVE' or 'REJECT'
    operator_id: str = "operator_hq"


class RollbackActionRequest(BaseModel):
    rollback_state: Dict[str, Any]


def verify_inter_service_auth(
    x_inter_service_secret: Optional[str] = Header(None),
    settings: BrahmaSettings = Depends(get_settings),
) -> str:
    if not settings.inter_service_secret:
        return "unrestricted"
    if not x_inter_service_secret or x_inter_service_secret != settings.inter_service_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Inter-Service-Secret.",
        )
    return x_inter_service_secret


@router.post("/critical")
async def handle_critical_anomaly_trigger(
    request: CriticalAnomalyTriggerRequest,
    auth: str = Depends(verify_inter_service_auth),
    settings: BrahmaSettings = Depends(get_settings),
):
    """
    Executes automated Tier 0 actions (Intensification + Canary + Sinkhole)
    and queues Tier 1 Process Isolation for operator approval.
    """
    db_pool = await get_db_pool()
    plan_cache = PlanCache()
    action_log = ActionLogRepository(db_pool)
    commander = AgentCommander(settings.supabase_url, settings.supabase_service_key)
    rollback_mgr = RollbackManager(commander)

    tier0 = Tier0Executor(commander, None, plan_cache, action_log, rollback_mgr)
    tier1 = Tier1Authorizer(commander, plan_cache, action_log, rollback_mgr)

    # 1. Execute Tier 0 Sensor Intensification (10Hz)
    t0_intensify = await tier0.execute_sensor_intensification(request.agent_id, request.ias_score)

    # 2. Execute Tier 0 Credential Shadow Rotation
    t0_canary = await tier0.execute_credential_rotation(request.agent_id, request.ias_score)

    # 3. Optional Tier 0 DNS Sinkhole if suspect domain provided
    t0_sinkhole = None
    if request.suspect_domain:
        t0_sinkhole = await tier0.execute_dns_sinkhole(request.suspect_domain, request.ias_score)

    # 4. Queue Tier 1 Process Isolation if suspect PID provided
    t1_queued = None
    if request.suspect_pid:
        t1_queued = tier1.queue_process_isolation(
            agent_id=request.agent_id,
            target_pid=request.suspect_pid,
            ias_score=request.ias_score,
            evidence_summary=f"Physical IAS score {request.ias_score:.2f} divergence.",
        )

    return {
        "status": "CONTAINMENT_DISPATCHED",
        "agent_id": request.agent_id,
        "tier0_actions": {
            "sensor_intensification": t0_intensify,
            "credential_rotation": t0_canary,
            "dns_sinkhole": t0_sinkhole,
        },
        "tier1_pending": t1_queued,
    }


@router.get("/pending")
async def get_pending_actions():
    """Returns all active Tier 1 actions awaiting operator authorization."""
    plan_cache = PlanCache()
    return {
        "pending_actions": plan_cache.get_all_pending_actions(),
    }


@router.post("/authorize")
async def authorize_action(request: AuthorizeActionRequest):
    """Processes operator approval or rejection for a Tier 1 action."""
    db_pool = await get_db_pool()
    plan_cache = PlanCache()
    action_log = ActionLogRepository(db_pool)
    commander = AgentCommander()
    rollback_mgr = RollbackManager(commander)
    tier1 = Tier1Authorizer(commander, plan_cache, action_log, rollback_mgr)

    result = await tier1.authorize_action(
        action_id=request.action_id,
        decision=request.decision,
        operator_id=request.operator_id,
    )
    return result


@router.post("/rollback")
async def trigger_rollback(request: RollbackActionRequest):
    """Executes pre-computed rollback instructions."""
    commander = AgentCommander()
    rollback_mgr = RollbackManager(commander)
    success = rollback_mgr.execute_rollback(request.rollback_state)
    return {"status": "ROLLED_BACK" if success else "FAILED", "success": success}
