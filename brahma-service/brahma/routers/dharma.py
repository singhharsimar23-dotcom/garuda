"""
DHARMA Response Router
Provides operator endpoints for containment authorization, SLA countdowns, and Telegram webhooks.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from dharma.action_log import get_dharma_action_log_repo
from dharma.execution_tiers import get_dharma_execution_engine
from dharma.redis_sla import get_redis_sla_manager

logger = logging.getLogger("brahma.routers.dharma")
router = APIRouter(prefix="/api/v1/dharma", tags=["DHARMA Defensive Execution"])


class EvaluateDharmaRequest(BaseModel):
    hostname: str
    ias_score: float
    attribution_status: str = "ACCUMULATING EVIDENCE (0/15 minimum)"
    target_pid: Optional[int] = None
    target_domain: Optional[str] = None
    lateral_movement_suspected: bool = False
    ioc_evidence: Dict[str, Any] = Field(default_factory=dict)
    physics_evidence: Dict[str, Any] = Field(default_factory=dict)


class ActionDecisionRequest(BaseModel):
    operator_id: str = "operator_hq"
    resume_process: bool = False


@router.post("/evaluate", status_code=status.HTTP_200_OK)
async def evaluate_dharma_event(payload: EvaluateDharmaRequest):
    """Evaluate telemetry event against Tier 0..3 criteria and dispatch or queue actions."""
    engine = get_dharma_execution_engine()
    result = await engine.evaluate_and_dispatch(
        hostname=payload.hostname,
        ias_score=payload.ias_score,
        attribution_status=payload.attribution_status,
        target_pid=payload.target_pid,
        target_domain=payload.target_domain,
        lateral_movement_suspected=payload.lateral_movement_suspected,
        ioc_evidence=payload.ioc_evidence,
        physics_evidence=payload.physics_evidence,
    )
    return result


@router.post("/approve/{action_id}", status_code=status.HTTP_200_OK)
async def approve_dharma_action(action_id: str, body: ActionDecisionRequest = ActionDecisionRequest()):
    """Approve and execute real SSH SIGSTOP or Cloudflare DNS sinkhole."""
    engine = get_dharma_execution_engine()
    result = await engine.approve_action(action_id=action_id, operator_id=body.operator_id)
    if not result.get("success"):
        logger.warning(f"Action {action_id} execution failed or partially applied.")
    return result


@router.post("/reject/{action_id}", status_code=status.HTTP_200_OK)
async def reject_dharma_action(action_id: str, body: ActionDecisionRequest = ActionDecisionRequest()):
    """Reject containment action and optionally resume process via SIGCONT."""
    engine = get_dharma_execution_engine()
    result = await engine.reject_action(
        action_id=action_id,
        operator_id=body.operator_id,
        resume_process=body.resume_process,
    )
    return result


@router.get("/ttl/{action_id}", status_code=status.HTTP_200_OK)
async def get_action_ttl(action_id: str):
    """Retrieve remaining Redis SLA TTL countdown in seconds."""
    redis_sla = get_redis_sla_manager()
    ttl = await redis_sla.get_remaining_ttl(action_id)
    return {"action_id": action_id, "ttl_seconds": ttl, "expired": ttl == 0 or ttl == -1}


@router.get("/actions", status_code=status.HTTP_200_OK)
async def get_recent_actions(limit: int = 50):
    """List recent immutable events from dharma_action_log."""
    log_repo = get_dharma_action_log_repo()
    actions = await log_repo.get_recent_actions(limit=limit)
    return {"status": "success", "count": len(actions), "actions": actions}


@router.post("/webhook/telegram", status_code=status.HTTP_200_OK)
async def telegram_webhook(request: Request):
    """Process Telegram inline keyboard callback commands (/dharma_approve_{id} and /dharma_reject_{id})."""
    engine = get_dharma_execution_engine()
    try:
        data = await request.json()
        callback_query = data.get("callback_query", {})
        callback_data = callback_query.get("data", "")
        sender = callback_query.get("from", {}).get("username", "telegram_operator")

        if callback_data.startswith("/dharma_approve_"):
            action_id = callback_data.replace("/dharma_approve_", "").strip()
            res = await engine.approve_action(action_id=action_id, operator_id=f"telegram:{sender}")
            return {"status": "success", "action": "APPROVED", "result": res}

        elif callback_data.startswith("/dharma_reject_"):
            action_id = callback_data.replace("/dharma_reject_", "").strip()
            res = await engine.reject_action(action_id=action_id, operator_id=f"telegram:{sender}")
            return {"status": "success", "action": "REJECTED", "result": res}

    except Exception as e:
        logger.warning(f"Error handling Telegram webhook: {e}")

    return {"status": "ignored"}
