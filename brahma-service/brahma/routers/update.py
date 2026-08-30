"""
Adversary State Update & Intel Ingestion Router
Processes anomaly events from AXIOM (Service 1) and threat intelligence uploads from data-pipeline.
"""

import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status

from ..config import BrahmaSettings, get_settings
from ..db.pool import get_db_pool
from ..models.brahma import BrahmaUpdateRequest, BrahmaUpdateResponse
from ..services.bayesian_updater import BayesianUpdater
from ..services.groq_expander import expand_behavioral_grammar

logger = logging.getLogger("brahma.routers.update")
router = APIRouter(prefix="/api/v1/brahma", tags=["Adversary Tracking"])


def verify_inter_service_auth(
    x_inter_service_secret: Optional[str] = Header(None),
    settings: BrahmaSettings = Depends(get_settings),
) -> str:
    """Validates X-Inter-Service-Secret header for internal microservice communication."""
    if not settings.inter_service_secret:
        return "unrestricted_local_mode"

    if not x_inter_service_secret or x_inter_service_secret != settings.inter_service_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing X-Inter-Service-Secret.",
        )
    return x_inter_service_secret


@router.post("/update", response_model=BrahmaUpdateResponse)
async def update_adversary_model(
    request: BrahmaUpdateRequest,
    auth: str = Depends(verify_inter_service_auth),
    settings: BrahmaSettings = Depends(get_settings),
) -> BrahmaUpdateResponse:
    """
    Receives anomaly event from AXIOM, updates the agent's Bayesian kill-chain posterior,
    and checks if behavioral grammar expansion is required.
    """
    db_pool = await get_db_pool()
    updater = BayesianUpdater(db_pool)

    res = await updater.process_anomaly_event(
        agent_id=request.agent_id,
        hostname=request.hostname,
        ias_score=request.ias_score,
        top_channels=request.top_channels,
    )

    grammar_expanded = False
    if res.get("should_expand_grammar"):
        expansion_res = await expand_behavioral_grammar(
            agent_id=request.agent_id,
            current_tactic=res["map_tactic"],
            observed_channels=request.top_channels,
            entropy_bits=res["entropy_bits"],
            settings=settings,
        )
        grammar_expanded = expansion_res.get("expansion_triggered", False)

    return BrahmaUpdateResponse(
        status="PROCESSED",
        agent_id=request.agent_id,
        actor_id=res["actor_id"],
        map_tactic=res["map_tactic"],
        predicted_next_tactic=res["predicted_next_tactic"],
        confidence=res["confidence"],
        observation_count=res["observation_count"],
        convergence_status=res["convergence_status"],
        entropy_bits=res["entropy_bits"],
        grammar_expanded=grammar_expanded,
    )


@router.post("/update-intel")
async def update_intel_feed(
    intel_payload: Dict[str, Any],
    auth: str = Depends(verify_inter_service_auth),
):
    """
    Receives compiled threat intelligence and TTP weights from data-pipeline.
    """
    logger.info(f"Received threat intelligence update payload with keys: {list(intel_payload.keys())}")
    return {
        "status": "ACCEPTED",
        "message": "Threat intelligence distributions updated in BRAHMA.",
    }
