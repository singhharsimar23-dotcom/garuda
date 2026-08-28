"""
GARUDA — Predictive Domain Pre-Registration API (Session 12)

POST /api/predictive/analyze  → run prediction pipeline, return scored candidates
POST /api/predictive/register → analyst-approved Porkbun registration (never auto)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from anthropic import AsyncAnthropic
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from garuda.config import settings
from garuda.database import upsert_predictive_domain
from garuda.detection.nic_ground_truth import NIC_DOMAINS
from garuda.intelligence.tension_index import fetch_tension_index
from garuda.modules.predictive.domain_generator import (
    build_score_rationale,
    filter_available_candidates,
    generate_candidate_domains,
    score_candidate,
)
from garuda.modules.predictive.registrar import (
    check_availability_porkbun,
    check_registration_budget,
    register_domain_porkbun,
)
from garuda.modules.predictive.vocabulary_extractor import (
    extract_target_keywords_from_narrative,
    get_ispr_narrative,
)

logger = logging.getLogger("garuda.api.routes.predictive")

router = APIRouter(tags=["Predictive Domain Pre-Registration"])


class RegisterDomainRequest(BaseModel):
    domain: str
    analyst_id: str = Field(..., min_length=1)
    justification: str = Field(..., min_length=30)

    @field_validator("analyst_id")
    @classmethod
    def analyst_id_required(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("analyst_id is required")
        return v.strip()

    @field_validator("justification")
    @classmethod
    def justification_min_length(cls, v: str) -> str:
        if len(v.strip()) < 30:
            raise ValueError("justification must be at least 30 characters")
        return v.strip()


def _verify_admin_token(authorization: Optional[str]) -> None:
    if not settings.TAXII_ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TAXII_ADMIN_TOKEN not configured.",
        )
    expected = f"Bearer {settings.TAXII_ADMIN_TOKEN}"
    if not authorization or authorization.strip() != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid TAXII_ADMIN_TOKEN.",
        )


def _get_anthropic_client() -> AsyncAnthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ANTHROPIC_API_KEY not configured.",
        )
    return AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)


@router.post("/predictive/analyze")
@router.post("/api/predictive/analyze")
async def predictive_analyze(
    authorization: Optional[str] = Header(None),
    hours_back: int = 72,
) -> Dict[str, Any]:
    """
    Run the full prediction pipeline and return scored domain candidates.

    Auth: TAXII_ADMIN_TOKEN (Bearer).
    """
    _verify_admin_token(authorization)

    narrative = await get_ispr_narrative(hours_back=hours_back)
    target_keywords = await extract_target_keywords_from_narrative(
        narrative,
        settings.TIER_1_PATTERNS,
    )

    if not target_keywords:
        target_keywords = settings.TIER_1_PATTERNS[:10]

    tension_index = await fetch_tension_index()
    client = _get_anthropic_client()
    raw_candidates = await generate_candidate_domains(target_keywords, client)
    available = await filter_available_candidates(raw_candidates)

    nic_list = NIC_DOMAINS or []
    scored: List[Dict[str, Any]] = []

    for domain in available:
        domain_score = score_candidate(domain, target_keywords, tension_index, nic_list)
        rationale = build_score_rationale(domain, target_keywords, tension_index, domain_score)
        entry = {
            "domain": domain,
            "score": domain_score,
            "rationale": rationale,
        }
        scored.append(entry)

        await upsert_predictive_domain({
            "domain": domain,
            "prediction_score": domain_score,
            "narrative_keywords": target_keywords,
            "cluster_context": f"ispr_narrative_{hours_back}h",
            "status": "candidate",
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    recommended = [c["domain"] for c in scored if c["score"] > 0.7][:5]

    return {
        "status": "ok",
        "narrative_snippets": len(narrative),
        "target_keywords": target_keywords,
        "tension_index": tension_index,
        "candidates": scored,
        "recommended": recommended,
    }


@router.post("/predictive/register")
@router.post("/api/predictive/register")
async def predictive_register(
    payload: RegisterDomainRequest,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Analyst-approved domain registration via Porkbun.

    REQUIRED: analyst_id and justification ≥ 30 chars.
    Budget gate enforced — never auto-registers.
    Auth: TAXII_ADMIN_TOKEN (Bearer).
    """
    _verify_admin_token(authorization)

    if not settings.PORKBUN_API_KEY or not settings.PORKBUN_API_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Porkbun API credentials not configured.",
        )

    allowed, budget_msg = await check_registration_budget()
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=budget_msg,
        )

    domain = payload.domain.strip().lower()
    api_key = settings.PORKBUN_API_KEY
    api_secret = settings.PORKBUN_API_SECRET

    try:
        available = await check_availability_porkbun(domain, api_key, api_secret)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    if not available:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain {domain} is not available for registration.",
        )

    try:
        result = await register_domain_porkbun(
            domain,
            api_key,
            api_secret,
            analyst_id=payload.analyst_id,
            justification=payload.justification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("[predictive/register] Registration failed for %s: %s", domain, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Domain registration failed: {exc}",
        ) from exc

    return {
        "status": "ok",
        "message": "Domain registered with analyst approval. Honeypot route configured.",
        **result,
    }
