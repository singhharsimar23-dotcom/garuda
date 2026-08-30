"""
BRAHMA Online Label Router
Receives ground-truth analyst feedback (/internal/label) from SENTINEL service.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from ..learner import get_brahma_online_learner

router = APIRouter(prefix="/internal", tags=["Online Learning"])


class LabelPayload(BaseModel):
    hostname: str = "default-node"
    tactic: str
    label: str  # POSITIVE, NEGATIVE
    feature_vector: Optional[Dict[str, Any]] = None
    evidence_ids: Optional[List[str]] = None
    confidence: Optional[str] = "HIGH"


@router.post(
    "/label",
    status_code=status.HTTP_200_OK,
)
async def ingest_ground_truth_label(
    payload: LabelPayload,
    x_inter_service_secret: Optional[str] = Header(None),
):
    """
    Apply operator ground-truth label to update Bayesian Dirichlet alpha counts.
    """
    learner = get_brahma_online_learner()
    res = await learner.apply_label(
        hostname=payload.hostname,
        tactic=payload.tactic,
        label=payload.label,
        feature_vector=payload.feature_vector,
        evidence_ids=payload.evidence_ids,
    )
    return res
