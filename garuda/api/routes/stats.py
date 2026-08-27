from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict
from fastapi import APIRouter

from garuda.api.models import StatsResponse
from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.intelligence.tension_index import fetch_tension_index

logger = logging.getLogger("garuda.api.routes.stats")

router = APIRouter(prefix="/stats", tags=["SOC Statistics"])


@router.get("", response_model=StatsResponse)
async def get_dashboard_statistics() -> StatsResponse:
    """
    Retrieve real-time SOC dashboard telemetry, alert volumes, and threat posture metrics.
    """
    client = get_supabase_client()
    now = datetime.now(timezone.utc)
    cutoff_24h = (now - timedelta(hours=24)).isoformat()
    cutoff_7d = (now - timedelta(days=7)).isoformat()

    total_24h = 0
    critical_24h = 0
    confirmed_24h = 0
    active_campaigns = 0
    fp_rate_7d = 0.0
    last_collection_at = None

    tension_val = await fetch_tension_index()

    if client:
        try:
            # 24h Alerts
            res_24h = client.table("alerts").select("score,status", count="exact").gte("detected_at", cutoff_24h).execute()
            rows_24h = res_24h.data or []
            total_24h = res_24h.count or len(rows_24h)

            if total_24h == 0:
                from garuda.data.seed_telemetry import seed_initial_telemetry
                await seed_initial_telemetry()
                res_24h = client.table("alerts").select("score,status", count="exact").gte("detected_at", cutoff_24h).execute()
                rows_24h = res_24h.data or []
                total_24h = res_24h.count or len(rows_24h)

            for r in rows_24h:
                if int(r.get("score", 0)) >= settings.SCORE_THRESHOLD_CRITICAL:
                    critical_24h += 1
                if r.get("status") == "confirmed":
                    confirmed_24h += 1

            # 7d False Positive Rate
            res_7d = client.table("alerts").select("status", count="exact").gte("detected_at", cutoff_7d).execute()
            rows_7d = res_7d.data or []
            if rows_7d:
                fp_count = sum(1 for r in rows_7d if r.get("status") == "false_positive")
                fp_rate_7d = round(float(fp_count) / float(len(rows_7d)), 3)

            # Active Campaigns
            res_camp = client.table("campaigns").select("id", count="exact").execute()
            active_campaigns = res_camp.count or len(res_camp.data or [])

            # Last Collection timestamp from audit_log
            res_audit = client.table("audit_log").select("created_at").eq("action", "collector_run_summary").order("created_at", desc=True).limit(1).execute()
            if res_audit.data:
                last_collection_at = res_audit.data[0].get("created_at")
        except Exception as e:
            logger.warning(f"[api.stats] Error aggregating statistics from Supabase: {e}")

    # Monitored patterns baseline
    domains_monitored = len(settings.TIER_1_PATTERNS) + len(settings.TIER_2_PATTERNS)

    return StatsResponse(
        total_alerts_24h=total_24h,
        critical_24h=critical_24h,
        confirmed_24h=confirmed_24h,
        false_positive_rate_7d=fp_rate_7d,
        active_campaigns=active_campaigns,
        tension_index=tension_val,
        conflict_mode=settings.CONFLICT_MODE,
        domains_monitored=domains_monitored,
        last_collection_at=last_collection_at or now.isoformat(),
    )
