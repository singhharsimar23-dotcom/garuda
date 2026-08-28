"""
GARUDA — Operator Clusters & Campaign Fingerprints API
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from garuda.database import (
    create_operator_cluster,
    get_campaign_fingerprints,
    get_cluster_review_queue,
    get_operator_clusters,
    insert_campaign_fingerprint,
    update_cluster_review_decision,
)
from garuda.intelligence.cluster_similarity import (
    compute_fingerprint_similarity,
    propose_cluster_attribution,
)

logger = logging.getLogger("garuda.api.routes.clusters")

router = APIRouter(tags=["Operator Clusters & Campaign Attribution"])


class CreateClusterRequest(BaseModel):
    label: str = Field(..., description="Internal working label (e.g. cluster-a-nic-mod)")
    first_observed: Optional[str] = Field(None, description="Date first observed (YYYY-MM-DD)")
    notes: Optional[str] = Field(None, description="Adversary behavioral notes")


class RegisterFingerprintRequest(BaseModel):
    domain: str = Field(..., description="Campaign infrastructure domain")
    registrar: Optional[str] = None
    registrar_account_pattern: Optional[str] = None
    nameserver_sequence: Optional[List[str]] = None
    hosting_asn: Optional[str] = None
    cert_issued_at: Optional[str] = None
    geopolitical_event_ref: Optional[str] = None
    lure_theme: Optional[str] = None
    target_sector: Optional[str] = None
    cves_used: Optional[List[str]] = None
    stix_indicator_id: Optional[str] = None
    cluster_id: Optional[str] = None


class ProposeAttributionRequest(BaseModel):
    fingerprint_id: str = Field(..., description="ID of the unclustered campaign fingerprint")
    min_threshold: float = Field(0.70, ge=0.0, le=1.0, description="Minimum similarity score threshold")


class ReviewDecisionRequest(BaseModel):
    decision: str = Field(..., description="'approved' or 'rejected'")
    analyst_id: str = Field(..., description="Analyst identifier")
    justification: str = Field(..., description="Mandatory attribution justification")


# ==============================================================================
# Endpoint 1: Operator Clusters
# ==============================================================================


@router.post("/clusters", include_in_schema=False)
@router.post("/clusters/")
@router.post("/api/v1/clusters", include_in_schema=False)
@router.post("/api/v1/clusters/")
async def create_cluster_endpoint(req: CreateClusterRequest):
    """Create a documented operator working cluster."""
    cluster = await create_operator_cluster(
        label=req.label,
        first_observed=req.first_observed,
        notes=req.notes,
    )
    return {
        "status": "ok",
        "cluster": cluster,
    }


@router.get("/clusters", include_in_schema=False)
@router.get("/clusters/")
@router.get("/api/v1/clusters", include_in_schema=False)
@router.get("/api/v1/clusters/")
async def list_clusters_endpoint():
    """List all documented operator clusters."""
    clusters = await get_operator_clusters()
    return {
        "status": "ok",
        "total_clusters": len(clusters),
        "clusters": clusters,
    }


# ==============================================================================
# Endpoint 2: Campaign Infrastructure Fingerprints
# ==============================================================================


@router.post("/clusters/fingerprints", include_in_schema=False)
@router.post("/clusters/fingerprints/")
@router.post("/api/v1/clusters/fingerprints", include_in_schema=False)
@router.post("/api/v1/clusters/fingerprints/")
async def register_fingerprint_endpoint(req: RegisterFingerprintRequest):
    """
    Ingest a campaign infrastructure fingerprint. Starts unclustered by default.
    """
    fp = await insert_campaign_fingerprint(req.model_dump())
    return {
        "status": "ok",
        "fingerprint": fp,
    }


@router.get("/clusters/fingerprints", include_in_schema=False)
@router.get("/clusters/fingerprints/")
@router.get("/api/v1/clusters/fingerprints", include_in_schema=False)
@router.get("/api/v1/clusters/fingerprints/")
async def list_fingerprints_endpoint(cluster_id: Optional[str] = None):
    """List campaign fingerprints, optionally filtered by cluster."""
    fps = await get_campaign_fingerprints(cluster_id=cluster_id)
    return {
        "status": "ok",
        "total_returned": len(fps),
        "fingerprints": fps,
    }


# ==============================================================================
# Endpoint 3: Human-in-the-Loop Review Queue
# ==============================================================================


@router.post("/clusters/propose", include_in_schema=False)
@router.post("/clusters/propose/")
@router.post("/api/v1/clusters/propose", include_in_schema=False)
@router.post("/api/v1/clusters/propose/")
async def propose_attribution_endpoint(req: ProposeAttributionRequest):
    """
    Run deterministic similarity scoring for an unclustered fingerprint against
    known clusters. Candidate matches above threshold are staged into review queue.
    """
    candidates = await propose_cluster_attribution(
        fingerprint_id=req.fingerprint_id,
        min_threshold=req.min_threshold,
    )
    return {
        "status": "ok",
        "staged_candidates": len(candidates),
        "candidates": candidates,
    }


@router.get("/clusters/review-queue", include_in_schema=False)
@router.get("/clusters/review-queue/")
@router.get("/api/v1/clusters/review-queue", include_in_schema=False)
@router.get("/api/v1/clusters/review-queue/")
async def list_review_queue_endpoint(
    status_filter: Optional[str] = Query("pending", alias="status"),
):
    """List staged attribution review candidates."""
    items = await get_cluster_review_queue(status=status_filter)
    return {
        "status": "ok",
        "total_queued": len(items),
        "review_items": items,
    }


@router.post("/clusters/review-queue/{review_id}/decide", include_in_schema=False)
@router.post("/clusters/review-queue/{review_id}/decide/")
@router.post("/api/v1/clusters/review-queue/{review_id}/decide", include_in_schema=False)
@router.post("/api/v1/clusters/review-queue/{review_id}/decide/")
@router.post("/api/attribution/queue/{review_id}/decide", include_in_schema=False)
@router.post("/api/attribution/queue/{review_id}/decide/")
async def decide_attribution_endpoint(review_id: str, req: ReviewDecisionRequest):
    """
    Analyst review decision (approved/rejected).
    Upon approval, assigns the cluster_id to the fingerprint.
    """
    if not req.justification or not req.justification.strip() or len(req.justification.strip()) < 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Justification is mandatory and must be at least 50 characters for all attribution decisions.",
        )

    try:
        updated = await update_cluster_review_decision(
            review_id=review_id,
            decision=req.decision,
            analyst_id=req.analyst_id,
            justification=req.justification,
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Review queue item {review_id} not found.",
            )
        return {
            "status": "ok",
            "message": f"Review item {review_id} marked as {req.decision}.",
            "review_item": updated,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


class AssignAttributionRequest(BaseModel):
    analyst_id: Optional[str] = Field("soc_lead_analyst", description="Analyst ID")
    justification: str = Field(..., min_length=50, description="Mandatory justification (min 50 chars)")


class RejectAttributionRequest(BaseModel):
    analyst_id: Optional[str] = Field("soc_lead_analyst", description="Analyst ID")
    justification: Optional[str] = Field("Rejected similarity correlation upon manual analyst audit.", description="Reason for rejection")


@router.post("/api/attribution/queue/{review_id}/assign")
@router.post("/attribution/queue/{review_id}/assign")
async def assign_attribution_endpoint(review_id: str, req: AssignAttributionRequest):
    """Analyst assigns fingerprint to candidate cluster."""
    dec_req = ReviewDecisionRequest(
        decision="approved",
        analyst_id=req.analyst_id or "soc_lead_analyst",
        justification=req.justification,
    )
    return await decide_attribution_endpoint(review_id, dec_req)


@router.post("/api/attribution/queue/{review_id}/reject")
@router.post("/attribution/queue/{review_id}/reject")
async def reject_attribution_endpoint(review_id: str, req: RejectAttributionRequest):
    """Analyst rejects candidate cluster match."""
    dec_req = ReviewDecisionRequest(
        decision="rejected",
        analyst_id=req.analyst_id or "soc_lead_analyst",
        justification=req.justification or "Rejected by analyst.",
    )
    return await decide_attribution_endpoint(review_id, dec_req)


# Additional Attribution Aliases
@router.get("/api/attribution/clusters")
@router.get("/attribution/clusters")
async def alias_list_clusters():
    return await list_clusters_endpoint()


@router.get("/api/attribution/fingerprints")
@router.get("/attribution/fingerprints")
async def alias_list_fingerprints(cluster_id: Optional[str] = None):
    return await list_fingerprints_endpoint(cluster_id=cluster_id)


@router.get("/api/attribution/queue")
@router.get("/attribution/queue")
async def alias_list_queue(status_filter: Optional[str] = Query("pending", alias="status")):
    return await list_review_queue_endpoint(status_filter=status_filter)

