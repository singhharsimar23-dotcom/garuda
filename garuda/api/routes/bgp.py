"""
GARUDA — BGP RPKI REST Monitor API (Session 8)

GET /api/bgp/check     → Vercel Cron target (*/15 * * * *)
GET /api/bgp/status      → current status of all watched prefixes
GET /api/bgp/incidents   → incident history
POST /api/bgp/seed       → run RPKI watchlist seeding (admin auth required)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query, status

from garuda.config import settings
from garuda.modules.bgp.hijack_detector import (
    RPKI_WATCHLIST,
    run_bgp_hijack_check,
    seed_rpki_watchlist_from_ripe,
)
from garuda.modules.bgp.ripe_stat import get_routing_status, validate_rpki

logger = logging.getLogger("garuda.api.routes.bgp")

router = APIRouter(tags=["BGP RPKI Monitor"])


def _verify_cron_secret(authorization: Optional[str]) -> None:
    expected = f"Bearer {settings.CRON_SECRET}"
    if not authorization or authorization.strip() != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid CRON_SECRET.",
        )


def _get_supabase_client():
    from garuda.database import get_supabase_client
    return get_supabase_client()


@router.get("/bgp/check")
@router.get("/api/bgp/check")
async def bgp_check(
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Vercel Cron — run BGP hijack check every 15 minutes."""
    _verify_cron_secret(authorization)

    if not settings.ENABLE_BGP_MONITOR:
        return {"status": "disabled", "reason": "ENABLE_BGP_MONITOR=false", "incidents": []}

    incidents = await run_bgp_hijack_check()
    return {
        "status": "ok",
        "incidents_detected": len(incidents),
        "incidents": incidents,
    }


@router.get("/bgp/status")
@router.get("/api/bgp/status")
async def bgp_status() -> Dict[str, Any]:
    """Current RPKI/routing status for all watched prefixes."""
    if not settings.ENABLE_BGP_MONITOR:
        return {"status": "disabled", "prefixes": []}

    client = _get_supabase_client()
    watchlist: List[Dict[str, Any]] = []

    if client:
        try:
            res = client.table("bgp_watchlist").select("*").eq("active", True).execute()
            watchlist = res.data or []
        except Exception as exc:
            logger.warning("[bgp/status] Supabase query failed: %s", exc)

    if not watchlist:
        watchlist = [
            {"prefix": p, "expected_asn": a, "org_label": o}
            for p, a, o in RPKI_WATCHLIST
        ]

    statuses = []
    for entry in watchlist:
        prefix = entry.get("prefix", "")
        expected_asn = int(entry.get("expected_asn", 0))
        try:
            rpki = await validate_rpki(expected_asn, prefix)
            routing = await get_routing_status(prefix)
        except Exception as exc:
            statuses.append({
                "prefix": prefix,
                "expected_asn": expected_asn,
                "org_label": entry.get("org_label"),
                "error": str(exc),
            })
            continue

        statuses.append({
            "prefix": prefix,
            "expected_asn": expected_asn,
            "org_label": entry.get("org_label"),
            "rpki_status": rpki,
            "routing": routing,
        })

    return {"status": "ok", "prefix_count": len(statuses), "prefixes": statuses}


@router.get("/bgp/incidents")
@router.get("/api/bgp/incidents")
async def bgp_incidents(
    limit: int = Query(50, ge=1, le=500),
    unresolved_only: bool = Query(False),
) -> Dict[str, Any]:
    """BGP incident history."""
    client = _get_supabase_client()
    if client:
        try:
            query = client.table("bgp_incidents").select("*").order("detected_at", desc=True).limit(limit)
            if unresolved_only:
                query = query.is_("resolved_at", "null")
            res = query.execute()
            return {"status": "ok", "incidents": res.data or []}
        except Exception as exc:
            logger.error("[bgp/incidents] Query failed: %s", exc)

    from garuda.database import _IN_MEMORY_BGP_INCIDENTS
    incidents = list(reversed(_IN_MEMORY_BGP_INCIDENTS[-limit:]))
    if unresolved_only:
        incidents = [i for i in incidents if not i.get("resolved_at")]
    return {"status": "ok", "incidents": incidents}


@router.post("/bgp/seed")
@router.post("/api/bgp/seed")
async def bgp_seed(
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Seed RPKI watchlist from live RIPE Stat data (admin/cron auth required)."""
    _verify_cron_secret(authorization)

    if not settings.ENABLE_BGP_MONITOR:
        return {"status": "disabled", "reason": "ENABLE_BGP_MONITOR=false", "seeded": 0}

    seeded = await seed_rpki_watchlist_from_ripe()
    return {"status": "ok", "seeded": len(seeded), "entries": seeded}
