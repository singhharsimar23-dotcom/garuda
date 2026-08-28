"""
RIPE Stat REST API client — serverless-safe BGP/RPKI polling.

VERIFIED ENDPOINTS — RIPE Stat REST API (stat.ripe.net)
DO NOT use RIS Live WebSocket feed — cannot run serverless.

Rate limit: not stated; be polite — 1 req/sec max.
All responses cached in Upstash TTL=900 (prefixes TTL=3600).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

import httpx
from pydantic import BaseModel, Field, ValidationError

from garuda.cache import get_cached_json, set_cached_json

logger = logging.getLogger("garuda.modules.bgp.ripe_stat")

RIPE_STAT_BASE = "https://stat.ripe.net/data"
_CACHE_TTL = 900
_PREFIX_CACHE_TTL = 3600
_MIN_REQUEST_INTERVAL = 1.0  # 1 req/sec max

_last_request_ts: float = 0.0
_rate_lock = asyncio.Lock()


# ==============================================================================
# Pydantic response validators — reject non-matching RIPE Stat payloads (RULE 1)
# ==============================================================================


class AnnouncedPrefixEntry(BaseModel):
    prefix: str = Field(min_length=3)


class AnnouncedPrefixesData(BaseModel):
    prefixes: list[AnnouncedPrefixEntry] = Field(default_factory=list)


class AnnouncedPrefixesResponse(BaseModel):
    status: str
    data: AnnouncedPrefixesData


class BgpUpdateAttrs(BaseModel):
    prefix: Optional[str] = None
    path: list[int] = Field(default_factory=list)
    next_hop: Optional[str] = Field(default=None, alias="next-hop")
    peer_asn: Optional[int] = Field(default=None, alias="peer_asn")


class BgpUpdateEntry(BaseModel):
    type: Literal["A", "W"]
    attrs: BgpUpdateAttrs


class BgpUpdatesData(BaseModel):
    updates: list[BgpUpdateEntry] = Field(default_factory=list)


class BgpUpdatesResponse(BaseModel):
    status: str
    data: BgpUpdatesData


class RpkiValidationData(BaseModel):
    status: Literal["valid", "invalid", "unknown"]


class RpkiValidationResponse(BaseModel):
    status: str
    data: RpkiValidationData


class RoutingSeenEntry(BaseModel):
    time: Optional[str] = None
    origin: Optional[int] = None


class RoutingStatusBlock(BaseModel):
    first_seen: Optional[RoutingSeenEntry] = None
    last_seen: Optional[RoutingSeenEntry] = None


class RoutingStatusData(BaseModel):
    routing_status: RoutingStatusBlock


class RoutingStatusResponse(BaseModel):
    status: str
    data: RoutingStatusData


def _validate_response(model: type[BaseModel], payload: dict[str, Any]) -> BaseModel:
    """Parse and validate a RIPE Stat JSON payload; raises ValidationError on mismatch."""
    return model.model_validate(payload)


async def _rate_limit() -> None:
    """Enforce 1 req/sec polite rate limit across all RIPE Stat calls."""
    global _last_request_ts
    async with _rate_lock:
        now = asyncio.get_event_loop().time()
        elapsed = now - _last_request_ts
        if elapsed < _MIN_REQUEST_INTERVAL:
            await asyncio.sleep(_MIN_REQUEST_INTERVAL - elapsed)
        _last_request_ts = asyncio.get_event_loop().time()


async def _ripe_get(
    endpoint: str,
    params: dict[str, Any],
    cache_key: str,
    cache_ttl: int = _CACHE_TTL,
) -> dict[str, Any]:
    """GET a RIPE Stat endpoint with cache + rate limiting."""
    cached = await get_cached_json(cache_key)
    if cached is not None:
        return cached

    await _rate_limit()
    url = f"{RIPE_STAT_BASE}/{endpoint}/data.json"

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.error("[ripe_stat] HTTP error on %s: %s", endpoint, exc)
        raise
    except Exception as exc:
        logger.error("[ripe_stat] Unexpected error on %s: %s", endpoint, exc)
        raise

    await set_cached_json(cache_key, data, ex=cache_ttl)
    return data


async def get_announced_prefixes(asn: int) -> list[str]:
    """
    Get all BGP-announced prefixes for an ASN.
    GET https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}
    Cache key: garuda:bgp:prefixes:AS{asn} TTL=3600
    """
    cache_key = f"garuda:bgp:prefixes:AS{asn}"
    raw = await _ripe_get(
        "announced-prefixes",
        {"resource": f"AS{asn}"},
        cache_key,
        cache_ttl=_PREFIX_CACHE_TTL,
    )
    parsed = _validate_response(AnnouncedPrefixesResponse, raw)
    return [entry.prefix for entry in parsed.data.prefixes]


async def get_bgp_updates(resource: str, timespan_minutes: int = 15) -> list[dict]:
    """
    Get BGP updates for a prefix or ASN over last N minutes.
    GET https://stat.ripe.net/data/bgp-updates/data.json
        ?resource={resource}&starttime={iso}&endtime={iso}
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=timespan_minutes)
    cache_key = f"garuda:bgp:updates:{resource}:{timespan_minutes}:{start.strftime('%Y%m%d%H%M')}"

    raw = await _ripe_get(
        "bgp-updates",
        {
            "resource": resource,
            "starttime": start.strftime("%Y-%m-%d %H:%M"),
            "endtime": end.strftime("%Y-%m-%d %H:%M"),
        },
        cache_key,
    )
    parsed = _validate_response(BgpUpdatesResponse, raw)
    return [update.model_dump() for update in parsed.data.updates]


async def validate_rpki(asn: int, prefix: str) -> str:
    """
    Validate RPKI Route Origin Authorisation for a prefix.
    GET https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}
    Returns: "valid" | "invalid" | "unknown"
    """
    cache_key = f"garuda:bgp:rpki:AS{asn}:{prefix}"
    raw = await _ripe_get(
        "rpki-validation",
        {"resource": f"AS{asn}", "prefix": prefix},
        cache_key,
    )
    parsed = _validate_response(RpkiValidationResponse, raw)
    return parsed.data.status


async def get_routing_status(resource: str) -> dict:
    """
    Get current routing status for a prefix or ASN.
    GET https://stat.ripe.net/data/routing-status/data.json?resource={resource}
    Returns: {announced: bool, first_seen: str, last_seen: str}
    """
    cache_key = f"garuda:bgp:routing_status:{resource}"
    raw = await _ripe_get(
        "routing-status",
        {"resource": resource},
        cache_key,
    )
    parsed = _validate_response(RoutingStatusResponse, raw)
    rs = parsed.data.routing_status
    first = rs.first_seen.time if rs.first_seen else None
    last = rs.last_seen.time if rs.last_seen else None
    announced = last is not None
    return {
        "announced": announced,
        "first_seen": first or "",
        "last_seen": last or "",
        "origin_asn": rs.last_seen.origin if rs.last_seen else None,
    }


def extract_origin_asn_from_updates(updates: list[dict]) -> Optional[int]:
    """Return the most recent announcement origin ASN from BGP update path."""
    for update in reversed(updates):
        if update.get("type") != "A":
            continue
        attrs = update.get("attrs") or {}
        path = attrs.get("path") or []
        if path:
            return int(path[-1])
    return None
