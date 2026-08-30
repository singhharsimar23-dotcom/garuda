"""
Adversary Assessment Query Router
Exposes current kill-chain posterior, entropy, and predicted adversary tactics for a monitored host.
"""

import math
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, status

from ..db.pool import get_db_pool
from ..db.queries import get_brahma_model
from ..models.brahma import AdversaryAssessmentResponse
from ..services.kill_chain_tracker import KillChainTracker
from ..bayesian_engine import get_bayesian_engine

logger = logging.getLogger("brahma.routers.assessment")
router = APIRouter(prefix="/api/v1/brahma", tags=["Adversary Assessment"])

@router.get("/state/active")
@router.get("/state/{hostname}")
async def get_active_brahma_state(hostname: str = "active"):
    """
    Returns the real-time Dirichlet-Multinomial Bayesian posterior and attribution status.
    """
    engine = get_bayesian_engine()
    state = engine.get_or_create_state(hostname)

    posterior = state.get_posterior()
    top_tactic, top_mass = state.get_top_tactic()
    attribution_status = state.evaluate_attribution_status()

    # Calculate entropy bits from posterior
    entropy_bits = 0.0
    for p in posterior.values():
        if p > 0.0:
            entropy_bits -= p * math.log2(p)

    return {
        "actor_id": "APT36 (Transparent Tribe)",
        "attribution_status": attribution_status,
        "map_tactic": top_tactic.upper(),
        "predicted_next_tactic": "PERSISTENCE" if top_tactic == "execution" else "COMMAND-AND-CONTROL",
        "observation_count": state.observation_count,
        "entropy_bits": round(entropy_bits, 2),
        "posterior": posterior,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/assessment/{agent_id}", response_model=AdversaryAssessmentResponse)
async def get_adversary_assessment(agent_id: str) -> AdversaryAssessmentResponse:
    """
    Returns the active adversary kill-chain state and Bayesian posterior for an agent.
    If no observations have occurred yet, returns default uncalibrated state.
    """
    db_pool = await get_db_pool()
    saved = await get_brahma_model(db_pool, agent_id) if db_pool else None

    if saved:
        return AdversaryAssessmentResponse(
            agent_id=saved["agent_id"],
            actor_id=saved["actor_id"],
            map_tactic=saved["kill_chain_tactic"],
            predicted_next_tactic=saved["predicted_next_tactic"] or "unknown",
            confidence=saved["confidence"],
            observation_count=saved["observation_count"],
            convergence_status=saved["convergence_status"],
            entropy_bits=saved["entropy_bits"],
            kill_chain_posterior=saved["posterior"],
            grammar_rules=saved.get("grammar_rules"),
            last_anomaly_at=saved["last_anomaly_at"],
        )

    # Fresh unobserved agent
    fresh_tracker = KillChainTracker(agent_id=agent_id)
    actor, conv_status, conf = fresh_tracker.evaluate_attribution()

    return AdversaryAssessmentResponse(
        agent_id=agent_id,
        actor_id=actor,
        map_tactic=fresh_tracker.get_map_tactic(),
        predicted_next_tactic=fresh_tracker.predict_next_tactic(),
        confidence=conf,
        observation_count=0,
        convergence_status=conv_status,
        entropy_bits=fresh_tracker.get_entropy_bits(),
        kill_chain_posterior=fresh_tracker.posterior,
        grammar_rules=None,
        last_anomaly_at=datetime.now(timezone.utc).isoformat(),
    )
