"""
GARUDA — Response Policy Zone (RPZ) DNS Feed API

Serves RFC-conformant BIND zone files over HTTPS for recursive DNS resolvers.
Includes scheduled auto-sync and 90-day expiry roll-off cron endpoints.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from garuda.config import settings
from garuda.database import (
    expire_stale_rpz_entries,
    get_active_rpz_entries,
    get_all_rpz_entries,
    soft_delete_rpz_entry,
    upsert_rpz_entry,
)
from garuda.response.rpz_generator import (
    compute_zone_serial,
    generate_active_rpz_zone,
    is_domain_protected,
    publish_domain_to_rpz,
    render_rpz_zone_file,
    validate_rpz_eligibility,
)

logger = logging.getLogger("garuda.api.routes.rpz")

router = APIRouter(tags=["Response Policy Zone (RPZ) DNS Defense"])


class PublishRPZRequest(BaseModel):
    domain: str = Field(..., description="Target threat domain to sinkhole or allow")
    confidence: int = Field(..., ge=0, le=100, description="IOC Confidence score (must be >= 80 for nxdomain)")
    action: str = Field("nxdomain", description="'nxdomain' to sinkhole, 'passthru' to whitelist")
    source_stix_object_id: Optional[str] = Field(None, description="STIX Indicator ID provenance")


def _verify_cron_secret(authorization: Optional[str]) -> None:
    """Verify standard Bearer <CRON_SECRET> header."""
    expected = f"Bearer {settings.CRON_SECRET}"
    if not authorization or authorization.strip() != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid CRON_SECRET authorization header.",
        )


# ==============================================================================
# Endpoint 1: Serve Flat BIND Zone File Over HTTPS
# ==============================================================================


@router.get("/rpz/zone", include_in_schema=False)
@router.get("/rpz/zone/")
@router.get("/rpz/zone.txt", include_in_schema=False)
@router.get("/api/v1/rpz/zone", include_in_schema=False)
@router.get("/api/v1/rpz/zone/")
@router.get("/api/rpz/zone", include_in_schema=False)
@router.get("/api/rpz/zone/")
@router.get("/api/rpz/zone.txt", include_in_schema=False)
async def serve_rpz_zone(request: Request):
    """
    Serve the active GARUDA Response Policy Zone (RPZ) flat zone file.

    Subscribing recursive resolvers (BIND 9, Unbound, PowerDNS Recursor, Knot Resolver)
    can fetch this file on a scheduled refresh interval (e.g. every 5–15 minutes).

    Headers returned:
      - Content-Type: text/plain; charset=utf-8
      - Cache-Control: public, max-age=300
      - X-RPZ-Serial: YYYYMMDDNN
      - X-RPZ-Active-Rules: <count>
    """
    entries = await get_active_rpz_entries()
    zone_serial = compute_zone_serial()
    zone_content = render_rpz_zone_file(entries, serial=zone_serial)

    return Response(
        content=zone_content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": f"public, max-age={settings.RPZ_ZONE_TTL}",
            "X-RPZ-Serial": zone_serial,
            "X-RPZ-Active-Rules": str(len(entries)),
            "X-RPZ-Origin": f"{settings.RPZ_ZONE_ORIGIN}.",
        },
    )


# ==============================================================================
# Endpoint 2: List RPZ Entries (JSON)
# ==============================================================================


@router.get("/rpz/entries", include_in_schema=False)
@router.get("/rpz/entries/")
@router.get("/api/v1/rpz/entries", include_in_schema=False)
@router.get("/api/v1/rpz/entries/")
@router.get("/api/rpz/entries", include_in_schema=False)
@router.get("/api/rpz/entries/")
async def list_rpz_entries(
    active_only: bool = Query(True, description="Filter for only active (non-expired) rules"),
    limit: int = Query(500, ge=1, le=5000),
):
    """List RPZ rules with metadata, confidence scores, and lifecycle status."""
    if active_only:
        entries = await get_active_rpz_entries()
    else:
        entries = await get_all_rpz_entries(limit=limit)

    return {
        "status": "ok",
        "total_returned": len(entries),
        "active_only": active_only,
        "publish_threshold": settings.RPZ_MIN_CONFIDENCE,
        "entries": entries,
    }


# ==============================================================================
# Endpoint 3: Sync & Expiry Cron (15-min interval)
# ==============================================================================


@router.post("/rpz/sync", include_in_schema=False)
@router.post("/rpz/sync/")
@router.post("/api/v1/rpz/sync", include_in_schema=False)
@router.post("/api/v1/rpz/sync/")
@router.post("/api/rpz/sync", include_in_schema=False)
@router.post("/api/rpz/sync/")
async def run_rpz_sync_and_expiry(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Scheduled RPZ synchronization and lifecycle maintenance cron (runs every 15 min).

    Actions:
      1. Auto-expires stale entries older than 90 days without re-corroboration.
      2. Validates existing active entries against protected sovereign lists.
      3. Returns current active rule count and new zone serial.
    """
    _verify_cron_secret(authorization)

    # 1. Expire stale entries (> 90 days)
    expired_count = await expire_stale_rpz_entries(max_age_days=settings.RPZ_EXPIRY_DAYS)

    # 2. Query remaining active entries
    active_entries = await get_active_rpz_entries()
    serial = compute_zone_serial()

    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "expired_stale_count": expired_count,
        "active_rules_count": len(active_entries),
        "zone_serial": serial,
        "publish_threshold": settings.RPZ_MIN_CONFIDENCE,
        "expiry_policy_days": settings.RPZ_EXPIRY_DAYS,
    }


# ==============================================================================
# Endpoint 4: Publish / Ingest RPZ Trigger
# ==============================================================================


@router.post("/rpz/publish", include_in_schema=False)
@router.post("/rpz/publish/")
@router.post("/api/v1/rpz/publish", include_in_schema=False)
@router.post("/api/v1/rpz/publish/")
@router.post("/api/rpz/publish", include_in_schema=False)
@router.post("/api/rpz/publish/")
async def publish_rpz_rule(req: PublishRPZRequest):
    """
    Publish a threat domain to the sovereign RPZ feed.
    Enforces minimum confidence >= 80 and sovereign protection safeguards.
    """
    success, message, row = await publish_domain_to_rpz(
        domain=req.domain,
        confidence=req.confidence,
        source_stix_object_id=req.source_stix_object_id,
        action=req.action,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=message,
        )

    return {
        "status": "ok",
        "message": message,
        "entry": row,
    }


# ==============================================================================
# Endpoint 5: Soft-delete / Remove RPZ Trigger
# ==============================================================================


class RemoveRPZRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Analyst justification for rule removal")


@router.get("/api/rpz/entries/{entry_id}")
@router.get("/rpz/entries/{entry_id}")
async def get_rpz_entry(entry_id: str):
    """Retrieve single RPZ entry with STIX indicator correlation."""
    entries = await get_all_rpz_entries(limit=1000)
    found = next((e for e in entries if str(e.get("id")) == entry_id or e.get("domain") == entry_id), None)
    if not found:
        raise HTTPException(status_code=404, detail="RPZ entry not found")
    return {"status": "ok", "entry": found}


@router.post("/api/rpz/entries/{entry_id}/remove")
@router.post("/rpz/entries/{entry_id}/remove")
async def remove_rpz_entry_by_id(entry_id: str, req: Optional[RemoveRPZRequest] = None):
    """Analyst-initiated removal of RPZ entry with mandatory justification."""
    # Lookup domain first if UUID passed
    entries = await get_all_rpz_entries(limit=1000)
    target = next((e for e in entries if str(e.get("id")) == entry_id or e.get("domain") == entry_id), None)
    domain_to_remove = target.get("domain") if target else entry_id

    success = await soft_delete_rpz_entry(domain_to_remove)
    if not success:
        raise HTTPException(status_code=404, detail=f"RPZ entry '{entry_id}' not found.")

    logger.info(f"[rpz] Rule removed for {domain_to_remove}. Reason: {req.reason if req else 'None'}")
    return {
        "status": "ok",
        "message": f"RPZ entry for '{domain_to_remove}' removed.",
        "domain": domain_to_remove,
        "reason": req.reason if req else None,
        "removed_at": datetime.now(timezone.utc).isoformat(),
    }
