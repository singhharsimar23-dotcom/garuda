"""
GARUDA — Passive DNS Correlation & Defence IP Management Endpoints
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from garuda.database import (
    get_monitored_defence_ips,
    get_pdns_observations,
    upsert_monitored_defence_ip,
)
from garuda.intelligence.pdns_correlator import correlate_domain_pdns

logger = logging.getLogger("garuda.api.routes.pdns")

router = APIRouter(tags=["Passive DNS Correlation & Infrastructure Overlap"])


class CorrelateDomainRequest(BaseModel):
    domain: str = Field(..., description="Threat indicator domain to analyze")
    stix_indicator_id: Optional[str] = Field(None, description="Source STIX 2.1 indicator ID")
    confidence: int = Field(80, ge=0, le=100, description="Threat confidence score")
    actor_name: str = Field("APT36", description="Associated threat actor working group")
    send_alert: bool = Field(True, description="Whether to dispatch Telegram alert on overlap")


class RegisterDefenceIpRequest(BaseModel):
    ip: str = Field(..., description="IP address or CIDR netblock (e.g. 59.160.0.0/16)")
    org_name: str = Field(..., description="Organisation name (e.g. DRDO, HAL, BEL, NIC)")
    source: str = Field(..., description="MANDATORY provenance citation (e.g. APNIC Whois, IRINN record)")
    verified_on: Optional[str] = Field(None, description="Date verified (YYYY-MM-DD)")
    notes: Optional[str] = Field(None, description="Analyst notes regarding asset allocation")


# ==============================================================================
# Endpoint 1: Correlate Domain Against Passive DNS
# ==============================================================================


@router.post("/pdns/correlate", include_in_schema=False)
@router.post("/pdns/correlate/")
@router.post("/api/v1/pdns/correlate", include_in_schema=False)
@router.post("/api/v1/pdns/correlate/")
async def run_pdns_correlation(req: CorrelateDomainRequest):
    """
    Run reactive passive DNS correlation for a threat domain against documented defence netblocks.
    """
    result = await correlate_domain_pdns(
        domain=req.domain,
        stix_indicator_id=req.stix_indicator_id,
        confidence=req.confidence,
        actor_name=req.actor_name,
        send_alert=req.send_alert,
    )
    return {
        "status": "ok",
        "result": result,
    }


# ==============================================================================
# Endpoint 2: List Recorded Passive DNS Observations
# ==============================================================================


@router.get("/pdns/observations", include_in_schema=False)
@router.get("/pdns/observations/")
@router.get("/api/v1/pdns/observations", include_in_schema=False)
@router.get("/api/v1/pdns/observations/")
@router.get("/api/pdns/observations", include_in_schema=False)
@router.get("/api/pdns/observations/")
@router.get("/api/pdns/matches", include_in_schema=False)
@router.get("/api/pdns/matches/")
@router.get("/pdns/matches", include_in_schema=False)
@router.get("/pdns/matches/")
async def list_pdns_observations(limit: int = Query(100, ge=1, le=1000)):
    """Retrieve recorded passive DNS correlation observations."""
    obs = await get_pdns_observations(limit=limit)
    return {
        "status": "ok",
        "total_returned": len(obs),
        "observations": obs,
        "matches": obs,
    }


@router.get("/api/pdns/matches/{alert_id}")
@router.get("/pdns/matches/{alert_id}")
async def get_alert_pdns_matches(alert_id: str):
    """Retrieve passive DNS correlation observations matching a specific alert."""
    from garuda.database import get_alert_by_id
    alert = await get_alert_by_id(alert_id)
    domain = alert.get("domain") if alert else None

    obs = await get_pdns_observations(limit=500)
    matched = []
    for o in obs:
        if domain and o.get("queried_domain") == domain:
            matched.append(o)
        elif o.get("stix_indicator_id") == alert_id or o.get("id") == alert_id:
            matched.append(o)

    return {
        "status": "ok",
        "alert_id": alert_id,
        "domain": domain,
        "total_matches": len(matched),
        "observations": matched,
        "matches": matched,
    }


# ==============================================================================
# Endpoint 3: Register Monitored Defence IP / CIDR
# ==============================================================================


@router.post("/pdns/defence-ips", include_in_schema=False)
@router.post("/pdns/defence-ips/")
@router.post("/api/v1/pdns/defence-ips", include_in_schema=False)
@router.post("/api/v1/pdns/defence-ips/")
async def register_defence_ip(req: RegisterDefenceIpRequest):
    """
    Register a documented defence IP address or CIDR range.
    Strictly requires non-empty source provenance.
    """
    if not req.source or not req.source.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Source provenance is mandatory. Never guess or fabricate defence IP ranges.",
        )

    try:
        row = await upsert_monitored_defence_ip(
            ip=req.ip,
            org_name=req.org_name,
            source=req.source,
            verified_on=req.verified_on,
            notes=req.notes,
        )
        return {
            "status": "ok",
            "message": f"Registered monitored IP {req.ip} for {req.org_name}",
            "record": row,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ==============================================================================
# Endpoint 4: List Documented Defence IPs
# ==============================================================================


@router.get("/pdns/defence-ips", include_in_schema=False)
@router.get("/pdns/defence-ips/")
@router.get("/api/v1/pdns/defence-ips", include_in_schema=False)
@router.get("/api/v1/pdns/defence-ips/")
async def list_defence_ips():
    """Retrieve all documented defence IP netblocks and registries."""
    ips = await get_monitored_defence_ips()
    return {
        "status": "ok",
        "total_documented": len(ips),
        "defence_ips": ips,
    }
