import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import PlainTextResponse

from garuda.api.models import AlertListResponse, AlertResponse
from garuda.database import get_supabase_client
from garuda.intelligence.graph_builder import build_ioc_graph
from garuda.response.yara_generator import generate_yara_rule

logger = logging.getLogger("garuda.api.routes.alerts")

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def _format_alert_dict(row: Dict[str, Any]) -> AlertResponse:
    """Helper to convert database row to AlertResponse model."""
    signals = row.get("signals") or {}
    age_days = signals.get("domain_age_days")
    nic_match = signals.get("nic_match")
    nic_sim = signals.get("nic_similarity")

    return AlertResponse(
        id=str(row.get("id", "")),
        domain=row.get("domain", ""),
        score=int(row.get("score", 0)),
        status=row.get("status", "pending"),
        signals=signals,
        sector=row.get("sector"),
        registrar=row.get("registrar"),
        hosting_ip=row.get("hosting_ip"),
        hosting_asn=row.get("hosting_asn"),
        nic_match=nic_match,
        nic_similarity=float(nic_sim) if nic_sim is not None else None,
        detected_at=str(row.get("detected_at", "")),
        registered_at=str(row.get("registered_at", "")) if row.get("registered_at") else None,
        cluster_id=row.get("cluster_id"),
        llm_narrative=row.get("llm_narrative"),
        screenshot_url=row.get("screenshot_url"),
        age_days=int(age_days) if age_days is not None else None,
        created_at=str(row.get("created_at", "")),
    )


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (e.g. 'pending', 'confirmed', 'false_positive')"),
    score_min: int = Query(0, ge=0, le=100, description="Minimum threat score threshold"),
    sector: Optional[str] = Query(None, description="Filter by target sector substring"),
    cluster_id: Optional[str] = Query(None, description="Filter by campaign cluster ID"),
) -> AlertListResponse:
    """
    Retrieve a paginated list of threat intelligence alerts with multi-criteria filtering.
    """
    client = get_supabase_client()
    if not client:
        # Fallback empty list for unconfigured environment
        return AlertListResponse(alerts=[], total=0, page=page, limit=limit)

    try:
        offset = (page - 1) * limit
        query = client.table("alerts").select("*", count="exact")

        if status_filter:
            query = query.eq("status", status_filter)
        if score_min > 0:
            query = query.gte("score", score_min)
        if sector:
            query = query.ilike("sector", f"%{sector}%")
        if cluster_id:
            query = query.eq("cluster_id", cluster_id)

        res = query.order("detected_at", desc=True).range(offset, offset + limit - 1).execute()
        total_count = res.count or len(res.data or [])

        if total_count == 0 and not status_filter and score_min == 0:
            from garuda.data.seed_telemetry import seed_initial_telemetry
            await seed_initial_telemetry()
            res = query.order("detected_at", desc=True).range(offset, offset + limit - 1).execute()
            total_count = res.count or len(res.data or [])

        alerts_list = [_format_alert_dict(row) for row in (res.data or [])]

        return AlertListResponse(
            alerts=alerts_list,
            total=total_count,
            page=page,
            limit=limit,
        )
    except Exception as e:
        logger.warning(f"[api.alerts] Warning listing alerts: {e}")
        return AlertListResponse(
            alerts=[],
            total=0,
            page=page,
            limit=limit,
        )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert_detail(alert_id: str) -> AlertResponse:
    """
    Retrieve complete dossier and signals breakdown for a single threat alert.
    """
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=404, detail="Database client not configured.")

    try:
        res = client.table("alerts").select("*").ilike("id", f"{alert_id}%").limit(1).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
        return _format_alert_dict(res.data[0])
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[api.alerts] Error retrieving alert {alert_id}: {e}")
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")


@router.get("/{alert_id}/graph")
async def get_alert_graph(alert_id: str) -> Dict[str, Any]:
    """
    Generate or retrieve the 4-pivot interactive infrastructure graph for D3/Cytoscape visualization.
    """
    client = get_supabase_client()
    if not client:
        return {"nodes": [{"id": alert_id, "type": "domain", "domain": "mock.space", "score": 85}], "edges": []}

    try:
        res = client.table("alerts").select("*").ilike("id", f"{alert_id}%").limit(1).execute()
        if not res.data:
            return {"nodes": [{"id": alert_id, "type": "domain", "domain": "target.space", "score": 85}], "edges": []}

        row = res.data[0]
        signals = row.get("signals") or {}
        cached_graph = signals.get("graph")
        if cached_graph and isinstance(cached_graph, dict):
            return cached_graph

        # Build graph dynamically
        graph = await build_ioc_graph(row.get("domain", ""), row)
        return graph
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[api.alerts] Warning building graph for alert {alert_id}: {e}")
        return {"nodes": [{"id": alert_id, "type": "domain", "domain": "target.space", "score": 85}], "edges": []}


@router.get("/{alert_id}/yara", response_class=PlainTextResponse)
async def get_alert_yara_rule(alert_id: str) -> PlainTextResponse:
    """
    Download a pure, syntactically valid YARA detection rule tailored for the alert's IOCs.
    """
    client = get_supabase_client()
    alert_dict = {"id": alert_id, "domain": "suspected-domain.space", "score": 85, "sector": "Defence"}

    if client:
        try:
            res = client.table("alerts").select("*").ilike("id", f"{alert_id}%").limit(1).execute()
            if res.data:
                alert_dict = res.data[0]
        except Exception as e:
            logger.warning(f"[api.alerts] Database lookup warning for YARA export: {e}")

    yara_rule_text = generate_yara_rule(alert_dict)
    return PlainTextResponse(content=yara_rule_text, media_type="text/plain")


@router.post("/retrohunt")
async def trigger_retrohunt_replay() -> Dict[str, Any]:
    """
    Run historical APT36 IOC simulation benchmark and evaluate lead-time accuracy.
    """
    from garuda.intelligence.retrohunt import run_retrohunt
    results = await run_retrohunt()
    return results
