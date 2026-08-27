import json
import logging
from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Response
from stix2 import Bundle

from garuda.cache import get_cached_json, set_cached_json
from garuda.database import get_supabase_client
from garuda.response.stix_export import create_stix_bundle, export_to_json

logger = logging.getLogger("garuda.api.routes.stix")

router = APIRouter(prefix="/stix", tags=["STIX 2.1 Threat Sharing"])
STIX_FEED_CACHE_KEY = "garuda:stix:feed_bundle"


@router.get("")
@router.get("/feed")
async def get_stix_threat_feed() -> Response:
    """
    Export all analyst-confirmed IOCs as a standardized STIX 2.1 JSON Bundle.

    Responses are cached in Upstash Redis with a 300-second TTL.
    """
    cached_bundle = await get_cached_json(STIX_FEED_CACHE_KEY)
    if cached_bundle and isinstance(cached_bundle, str):
        return Response(content=cached_bundle, media_type="application/json")

    client = get_supabase_client()
    confirmed_alerts = []

    if client:
        try:
            res = client.table("alerts").select("*").eq("status", "confirmed").limit(500).execute()
            confirmed_alerts = res.data or []
        except Exception as e:
            logger.error(f"[api.stix] Error fetching confirmed alerts: {e}")

    # Build bundled objects
    stix_objects = []
    for alert in confirmed_alerts:
        try:
            bundle = create_stix_bundle(alert)
            stix_objects.extend(bundle.objects)
        except Exception as e:
            logger.warning(f"[api.stix] Error creating STIX object for {alert.get('domain')}: {e}")

    final_bundle = Bundle(objects=stix_objects)
    serialized_json = export_to_json(final_bundle)

    # Cache feed for 5 minutes
    await set_cached_json(STIX_FEED_CACHE_KEY, serialized_json, ex=300)
    return Response(content=serialized_json, media_type="application/json")


@router.get("/{alert_id}")
async def get_single_alert_stix(alert_id: str) -> Response:
    """
    Generate and retrieve a dedicated STIX 2.1 Bundle for an individual alert.
    """
    client = get_supabase_client()
    alert_record: Dict[str, Any] = {
        "id": alert_id,
        "domain": "target-threat.space",
        "score": 85,
        "sector": "Defense",
    }

    if client:
        try:
            res = client.table("alerts").select("*").ilike("id", f"{alert_id}%").limit(1).execute()
            if res.data:
                alert_record = res.data[0]
        except Exception as e:
            logger.warning(f"[api.stix] Database lookup warning for STIX export: {e}")

    bundle = create_stix_bundle(alert_record)
    serialized = export_to_json(bundle)
    return Response(content=serialized, media_type="application/json")
