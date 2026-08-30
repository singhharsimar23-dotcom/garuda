"""
Internal Observe Router
Receives physics evidence forwarded from AXIOM-II telemetry engine with INTER_SERVICE_SECRET authentication.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Header, HTTPException, status

from ..bayesian_engine import get_bayesian_engine
from ..config import get_settings
from ..models.brahma import ObserveInput, ObserveResponse

logger = logging.getLogger("brahma.routers.observe")
router = APIRouter(tags=["Internal Observe"])


def verify_inter_service_secret(
    x_inter_service_secret: Optional[str] = Header(None, alias="X-Inter-Service-Secret"),
    authorization: Optional[str] = Header(None),
) -> None:
    """Validate internal inter-service shared secret."""
    settings = get_settings()
    expected = settings.inter_service_secret

    token = x_inter_service_secret
    if not token and authorization:
        if authorization.startswith("Bearer "):
            token = authorization.split("Bearer ", 1)[1].strip()
        else:
            token = authorization.strip()

    if not token or token != expected:
        logger.warning("Unauthorized call to /internal/observe: Invalid INTER_SERVICE_SECRET.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid inter-service secret",
        )


@router.post(
    "/internal/observe",
    response_model=ObserveResponse,
    status_code=status.HTTP_200_OK,
)
async def observe_physics_event(
    payload: ObserveInput,
    x_inter_service_secret: Optional[str] = Header(None, alias="X-Inter-Service-Secret"),
    authorization: Optional[str] = Header(None),
):
    """
    Ingest physics anomaly evidence and execute conjugate Dirichlet-Multinomial Bayesian update.
    """
    verify_inter_service_secret(x_inter_service_secret, authorization)

    engine = get_bayesian_engine()
    result = engine.update_from_observation(
        hostname=payload.hostname,
        ias_score=payload.ias_score,
        channel_sigmas=payload.channel_sigmas,
        workload_class=payload.workload_class,
        observed_at_iso=payload.observed_at,
        eppi_technique_id=payload.eppi_technique_id,
    )

    return ObserveResponse(
        status="success",
        hostname=result["hostname"],
        observation_count=result["observation_count"],
        attribution_status=result["attribution_status"],
        top_tactic=result["top_tactic"],
        top_tactic_mass=result["top_tactic_mass"],
        posterior=result["posterior"],
    )
