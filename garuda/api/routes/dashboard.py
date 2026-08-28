"""
GARUDA Dashboard Data API — read-only GET endpoints for frontend dashboards.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

from garuda.config import settings
from garuda.database import (
    get_monthly_registration_spend_usd,
    get_predictive_domains,
    get_supabase_client,
)
from garuda.modules.lifecycle.effectiveness import get_cached_effectiveness_metrics

logger = logging.getLogger("garuda.api.routes.dashboard")

router = APIRouter(tags=["Dashboard Data"])


def _orb_nodes() -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if client:
        try:
            res = client.table("orb_nodes").select("*").order("orb_score", desc=True).limit(500).execute()
            return res.data or []
        except Exception as exc:
            logger.warning("[dashboard] orb_nodes query failed: %s", exc)
    from garuda.database import _IN_MEMORY_ORB_NODES
    return list(_IN_MEMORY_ORB_NODES)


def _ssh_observations() -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if client:
        try:
            res = client.table("ssh_key_observations").select("*").order("last_seen", desc=True).limit(1000).execute()
            return res.data or []
        except Exception as exc:
            logger.warning("[dashboard] ssh_key_observations query failed: %s", exc)
    return []


def _sandbox_analyses() -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if client:
        try:
            res = client.table("sandbox_analyses").select("*").order("submitted_at", desc=True).limit(200).execute()
            return res.data or []
        except Exception as exc:
            logger.warning("[dashboard] sandbox_analyses query failed: %s", exc)
    from garuda.database import _IN_MEMORY_SANDBOX_ANALYSES
    return list(_IN_MEMORY_SANDBOX_ANALYSES)


def _persona_nodes(cluster: Optional[str] = None) -> List[Dict[str, Any]]:
    client = get_supabase_client()
    rows: List[Dict[str, Any]] = []
    if client:
        try:
            res = client.table("persona_nodes").select("*").limit(500).execute()
            rows = res.data or []
        except Exception as exc:
            logger.warning("[dashboard] persona_nodes query failed: %s", exc)
    else:
        from garuda.database import _IN_MEMORY_PERSONA_NODES
        rows = list(_IN_MEMORY_PERSONA_NODES)

    if cluster:
        filtered = []
        for row in rows:
            meta = row.get("metadata") or {}
            label = meta.get("cluster_label") or meta.get("cluster") or row.get("source", "")
            if cluster.lower() in str(label).lower():
                filtered.append(row)
        return filtered
    return rows


def _build_persona_graph(nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert persona_nodes rows to D3-compatible {nodes, links}."""
    d3_nodes = []
    links = []
    type_index: Dict[str, str] = {}

    for row in nodes:
        node_id = str(row.get("id", row.get("value", "")))
        node_type = (row.get("node_type") or "IP").upper()
        conf = float(row.get("confidence") or 0.5)
        d3_nodes.append({
            "id": node_id,
            "label": row.get("value", node_id),
            "type": node_type,
            "confidence": conf,
            "source": row.get("source"),
        })
        type_index[node_id] = node_type

    # Link nodes sharing the same source cluster
    by_source: Dict[str, List[str]] = defaultdict(list)
    for row in nodes:
        src = row.get("source") or "unknown"
        by_source[src].append(str(row.get("id", row.get("value", ""))))

    for src, ids in by_source.items():
        for i in range(len(ids) - 1):
            links.append({
                "source": ids[i],
                "target": ids[i + 1],
                "edge_type": f"shared_{src}",
            })

    return {"nodes": d3_nodes, "links": links}


def _lifecycle_alerts() -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if client:
        try:
            res = (
                client.table("alerts")
                .select("id,domain,cluster_id,lifecycle_state,lifecycle_updated_at,detected_at,public_disclosure_date,status")
                .eq("status", "confirmed")
                .limit(500)
                .execute()
            )
            return res.data or []
        except Exception as exc:
            logger.warning("[dashboard] lifecycle alerts query failed: %s", exc)
    from garuda.database import _IN_MEMORY_LIFECYCLE_ALERTS
    return [r for r in _IN_MEMORY_LIFECYCLE_ALERTS if r.get("status") == "confirmed"]


@router.get("/orb/nodes")
@router.get("/api/orb/nodes")
async def list_orb_nodes() -> Dict[str, Any]:
    nodes = _orb_nodes()
    probable = sum(1 for n in nodes if 60 <= int(n.get("orb_score") or 0) < 80)
    confirmed = sum(1 for n in nodes if int(n.get("orb_score") or 0) >= 80)
    targeting = sum(1 for n in nodes if n.get("targeting_indian_defence"))
    return {
        "status": "ok",
        "nodes": nodes,
        "stats": {
            "total": len(nodes),
            "probable": probable,
            "confirmed": confirmed,
            "targeting_india": targeting,
        },
    }


@router.get("/malware_hunt/ssh")
@router.get("/api/malware_hunt/ssh")
async def list_ssh_observations() -> Dict[str, Any]:
    observations = _ssh_observations()
    grouped: Dict[str, Dict[str, Any]] = {}
    for obs in observations:
        fp = obs.get("fingerprint", "")
        if fp not in grouped:
            grouped[fp] = {
                "fingerprint": fp,
                "ips": [],
                "key_type": obs.get("key_type"),
                "last_seen": obs.get("last_seen"),
                "severity": "high" if len(grouped.get(fp, {}).get("ips", [])) > 2 else "medium",
            }
        grouped[fp]["ips"].append({
            "ip": obs.get("ip"),
            "asn": obs.get("asn"),
            "org": obs.get("org"),
            "last_seen": obs.get("last_seen"),
        })
        if obs.get("last_seen") and (not grouped[fp]["last_seen"] or obs["last_seen"] > grouped[fp]["last_seen"]):
            grouped[fp]["last_seen"] = obs["last_seen"]

    for fp, entry in grouped.items():
        asns = {ip.get("asn") for ip in entry["ips"] if ip.get("asn")}
        entry["severity"] = "critical" if len(asns) > 1 else ("high" if len(entry["ips"]) > 2 else "medium")
        entry["asn_count"] = len(asns)

    return {"status": "ok", "groups": list(grouped.values())}


@router.get("/malware_hunt/sandbox")
@router.get("/api/malware_hunt/sandbox")
async def list_sandbox_analyses() -> Dict[str, Any]:
    return {"status": "ok", "analyses": _sandbox_analyses()}


@router.get("/attribution/graph")
@router.get("/api/attribution/graph")
async def get_attribution_graph(
    cluster: Optional[str] = Query(None, description="Filter by cluster label"),
) -> Dict[str, Any]:
    nodes = _persona_nodes(cluster)
    graph = _build_persona_graph(nodes)
    clusters = sorted({
        (n.get("metadata") or {}).get("cluster_label") or n.get("source", "")
        for n in _persona_nodes()
        if n.get("source")
    })
    return {
        "status": "ok",
        "cluster": cluster,
        "clusters": [c for c in clusters if c],
        **graph,
    }


@router.get("/predictive/domains")
@router.get("/api/predictive/domains")
async def list_predictive_domains() -> Dict[str, Any]:
    candidates = await get_predictive_domains(status="candidate")
    registered = await get_predictive_domains(status="registered")
    spend = await get_monthly_registration_spend_usd()
    budget = settings.DOMAIN_REGISTRATION_BUDGET_USD_MONTHLY
    return {
        "status": "ok",
        "candidates": candidates,
        "registered": registered,
        "budget": {
            "monthly_limit_usd": budget,
            "spent_usd": round(spend, 2),
            "remaining_usd": round(max(0, budget - spend), 2),
        },
    }


@router.get("/lifecycle/summary")
@router.get("/api/lifecycle/summary")
async def lifecycle_summary() -> Dict[str, Any]:
    alerts = _lifecycle_alerts()
    state_counts = defaultdict(int)
    for a in alerts:
        state = a.get("lifecycle_state") or "active"
        state_counts[state] += 1

    metrics = await get_cached_effectiveness_metrics()
    burn_by_cluster = metrics.get("mean_burn_days_by_cluster") or {}

    cluster_burn = []
    for cluster_id, median_days in burn_by_cluster.items():
        if median_days > 14:
            interpretation = "unaware"
        elif median_days < 3:
            interpretation = "aware"
        else:
            interpretation = "moderate"
        cluster_burn.append({
            "cluster_label": cluster_id,
            "median_burn_days": median_days,
            "interpretation": interpretation,
        })

    total_disclosure = metrics.get("total_with_disclosure_date") or 0
    positive = metrics.get("count_positive_lead_time") or 0
    positive_rate = round((positive / total_disclosure) * 100, 1) if total_disclosure else 0

    return {
        "status": "ok",
        "state_counts": dict(state_counts),
        "cluster_burn": cluster_burn,
        "effectiveness": {
            **metrics,
            "positive_lead_time_rate_pct": positive_rate,
        },
    }
