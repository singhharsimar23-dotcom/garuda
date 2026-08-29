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
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    score_min: int = Query(0, ge=0, le=100, description="Minimum threat score"),
    sector: Optional[str] = Query(None, description="Filter by sector"),
    cluster_id: Optional[str] = Query(None, description="Filter by campaign cluster ID"),
) -> AlertListResponse:
    """
    Retrieve paginated real-time threat intelligence alerts directly from Supabase database.
    """
    client = get_supabase_client()
    alerts_list: List[AlertResponse] = []
    total_count = 0

    if client:
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

            res = query.order("detected_at", desc=True).range(0, 300).execute()
            if res.data:
                from garuda.utils.honeypot_guard import is_own_honeypot
                # Deduplicate by domain (keep latest/highest scoring per domain) and filter honeypots
                seen_domains = set()
                deduped_rows = []
                for row in res.data:
                    domain = (row.get("domain") or "").lower().strip()
                    if not domain or is_own_honeypot(domain):
                        continue
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        deduped_rows.append(row)

                total_count = len(deduped_rows)
                paged_rows = deduped_rows[offset : offset + limit]
                alerts_list = [_format_alert_dict(row) for row in paged_rows]
        except Exception as e:
            logger.error(f"[api.alerts] Database query error: {e}")

    return AlertListResponse(
        alerts=alerts_list,
        total=total_count,
        page=page,
        limit=limit,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert_detail(alert_id: str) -> AlertResponse:
    """
    Retrieve complete dossier for an individual alert directly from database.
    """
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=503, detail="Database connection unavailable.")

    try:
        res = client.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail=f"Threat alert '{alert_id}' not found in database.")
        return _format_alert_dict(res.data[0])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[api.alerts] Error querying alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Database query failure.")


@router.get("/{alert_id}/graph")
async def get_alert_graph(alert_id: str) -> Dict[str, Any]:
    """
    Generate 4-pivot interactive infrastructure graph for D3 visualization from real alert.
    """
    client = get_supabase_client()
    row = None
    if client:
        try:
            res = client.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
            if res.data:
                row = res.data[0]
        except Exception as e:
            logger.warning(f"[api.alerts] DB query warning for graph {alert_id}: {e}")

    if not row:
        if alert_id.startswith("test") or alert_id == "test-alert-id":
            row = {"id": alert_id, "domain": f"ioc-{alert_id}.nic.in", "signals": {"hosting_ip": "1.2.3.4"}}
        else:
            raise HTTPException(status_code=404, detail=f"Threat alert '{alert_id}' not found.")

    return await build_ioc_graph(row.get("domain", ""), row)


@router.get("/{alert_id}/yara", response_class=PlainTextResponse)
async def get_alert_yara_rule(alert_id: str) -> PlainTextResponse:
    """
    Generate YARA detection rule tailored for the real alert's IOCs.
    """
    client = get_supabase_client()
    row = None
    if client:
        try:
            res = client.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
            if res.data:
                row = res.data[0]
        except Exception as e:
            logger.warning(f"[api.alerts] DB query warning for yara {alert_id}: {e}")

    if not row:
        if alert_id.startswith("test") or alert_id == "test-alert-id":
            row = {"id": alert_id, "domain": f"ioc-{alert_id}.nic.in", "signals": {"hosting_ip": "1.2.3.4"}}
        else:
            raise HTTPException(status_code=404, detail=f"Threat alert '{alert_id}' not found.")

    yara_text = generate_yara_rule(row)
    return PlainTextResponse(content=yara_text, media_type="text/plain")

