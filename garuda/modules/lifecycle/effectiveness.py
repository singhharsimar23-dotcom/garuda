"""
Lifecycle effectiveness metrics — lead time and burn cadence analysis.

Computes how far ahead of public disclosure GARUDA detected IOCs, and median
burn rates per cluster. Cached in Upstash Redis TTL=86400.
"""

from __future__ import annotations

import logging
import statistics
from datetime import date, datetime, timezone
from typing import Any, Optional

from garuda.cache import get_cached_json, set_cached_json

logger = logging.getLogger("garuda.modules.lifecycle.effectiveness")

_METRICS_CACHE_KEY = "garuda:lifecycle:effectiveness_metrics"
_METRICS_TTL = 86400


def _parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


async def compute_lead_time_metrics(supabase_client: Any) -> dict[str, Any]:
    """
    Compute lead-time and burn-cadence metrics from confirmed alerts.

    lead_time_days = public_disclosure_date - detected_at (positive = GARUDA was first)
    mean_burn_days_by_cluster: median days from detection to death per cluster

    Results cached in Upstash Redis TTL=86400.
    """
    metrics: dict[str, Any] = {
        "mean_lead_time_days": None,
        "median_lead_time_days": None,
        "count_positive_lead_time": 0,
        "total_with_disclosure_date": 0,
        "mean_burn_days_by_cluster": {},
        "burn_rate_assessment": "insufficient_data",
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }

    rows: list[dict] = []
    if supabase_client:
        try:
            res = supabase_client.table("alerts").select(
                "id,cluster_id,detected_at,public_disclosure_date,lifecycle_state,status"
            ).eq("status", "confirmed").execute()
            rows = res.data or []
        except Exception as exc:
            logger.error("[lifecycle/effectiveness] Supabase query failed: %s", exc)
    else:
        from garuda.database import _IN_MEMORY_LIFECYCLE_ALERTS
        rows = list(_IN_MEMORY_LIFECYCLE_ALERTS)

    lead_times: list[int] = []
    burn_by_cluster: dict[str, list[int]] = {}

    for row in rows:
        disclosure = _parse_date(row.get("public_disclosure_date"))
        detected = _parse_datetime(row.get("detected_at"))

        if disclosure and detected:
            lead_days = (disclosure - detected.date()).days
            lead_times.append(lead_days)
            metrics["total_with_disclosure_date"] += 1
            if lead_days > 0:
                metrics["count_positive_lead_time"] += 1

        if row.get("lifecycle_state") == "dead" and detected:
            cluster_id = row.get("cluster_id") or "unclustered"
            updated = _parse_datetime(row.get("lifecycle_updated_at"))
            if updated:
                burn_days = max(0, (updated - detected).days)
                burn_by_cluster.setdefault(cluster_id, []).append(burn_days)

    if lead_times:
        metrics["mean_lead_time_days"] = round(statistics.mean(lead_times), 1)
        metrics["median_lead_time_days"] = round(statistics.median(lead_times), 1)

    cluster_medians: dict[str, float] = {}
    all_medians: list[float] = []
    for cluster_id, burns in burn_by_cluster.items():
        if burns:
            med = statistics.median(burns)
            cluster_medians[cluster_id] = round(med, 1)
            all_medians.append(med)
    metrics["mean_burn_days_by_cluster"] = cluster_medians

    if all_medians:
        overall_median = statistics.median(all_medians)
        if overall_median > 14:
            metrics["burn_rate_assessment"] = "low_burn_operators_likely_unaware"
        elif overall_median < 3:
            metrics["burn_rate_assessment"] = "high_burn_operators_may_detect_garuda"
        else:
            metrics["burn_rate_assessment"] = "moderate_burn_cadence"

    await set_cached_json(_METRICS_CACHE_KEY, metrics, ex=_METRICS_TTL)
    return metrics


async def get_cached_effectiveness_metrics() -> dict[str, Any]:
    """Return cached effectiveness metrics or compute empty defaults."""
    cached = await get_cached_json(_METRICS_CACHE_KEY)
    if cached:
        return cached
    return {
        "mean_lead_time_days": None,
        "median_lead_time_days": None,
        "count_positive_lead_time": 0,
        "total_with_disclosure_date": 0,
        "mean_burn_days_by_cluster": {},
        "burn_rate_assessment": "not_computed",
        "computed_at": None,
    }
