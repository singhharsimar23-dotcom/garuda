import logging
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from garuda.api.models import AlertResponse, CampaignListResponse, CampaignResponse
from garuda.data.seed_telemetry import DEFAULT_SEED_CAMPAIGNS, DEFAULT_SEED_ALERTS
from garuda.database import get_supabase_client
from garuda.intelligence.cluster import detect_campaigns

logger = logging.getLogger("garuda.api.routes.campaigns")

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@router.get("", response_model=CampaignListResponse)
async def list_campaign_clusters() -> CampaignListResponse:
    """
    Retrieve all correlated APT36 / Transparent Tribe campaign clusters and attack window estimates.
    """
    client = get_supabase_client()
    campaigns: List[CampaignResponse] = []

    if client:
        try:
            res = client.table("campaigns").select("*").order("created_at", desc=True).execute()
            for row in (res.data or []):
                cluster_id = row.get("cluster_id", "")
                domain_res = client.table("alerts").select("domain").eq("cluster_id", cluster_id).execute()
                domains_list = [d.get("domain") for d in (domain_res.data or []) if d.get("domain")]

                campaigns.append(
                    CampaignResponse(
                        id=str(row.get("id", "")),
                        cluster_id=cluster_id,
                        domain_count=int(row.get("domain_count", len(domains_list) or 1)),
                        registrar=row.get("registrar"),
                        hosting_asn=row.get("hosting_asn"),
                        sectors=row.get("sectors") or [],
                        estimated_attack_window_days=row.get("estimated_attack_window_days"),
                        confidence=row.get("confidence", "high"),
                        created_at=str(row.get("created_at", "")),
                        domains=domains_list,
                    )
                )
        except Exception as e:
            logger.warning(f"[api.campaigns] Database query warning: {e}")

    # Fallback to rich pre-seeded campaign clusters
    if not campaigns:
        for row in DEFAULT_SEED_CAMPAIGNS:
            cluster_id = row.get("cluster_id", "")
            member_domains = [a["domain"] for a in DEFAULT_SEED_ALERTS if a.get("cluster_id") == cluster_id]
            campaigns.append(
                CampaignResponse(
                    id=str(row.get("id", "")),
                    cluster_id=cluster_id,
                    domain_count=int(row.get("domain_count", len(member_domains) or 1)),
                    registrar=row.get("registrar"),
                    hosting_asn=row.get("hosting_asn"),
                    sectors=row.get("sectors") or [],
                    estimated_attack_window_days=row.get("estimated_attack_window_days"),
                    confidence=row.get("confidence", "high"),
                    created_at=str(row.get("created_at", "")),
                    domains=member_domains or ["modgov-secure-portal.space", "indianarmy-pension-verify.online"],
                )
            )

    return CampaignListResponse(campaigns=campaigns)


@router.get("/{cluster_id}")
async def get_campaign_detail(cluster_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed campaign profile including all correlated member threat alert records.
    """
    client = get_supabase_client()
    if client:
        try:
            camp_res = client.table("campaigns").select("*").eq("cluster_id", cluster_id).limit(1).execute()
            if camp_res.data:
                campaign_data = camp_res.data[0]
                alerts_res = client.table("alerts").select("*").eq("cluster_id", cluster_id).execute()
                return {
                    "campaign": campaign_data,
                    "member_alerts": alerts_res.data or [],
                    "total_domains": len(alerts_res.data or []),
                }
        except Exception:
            pass

    # Check seed dataset
    for camp in DEFAULT_SEED_CAMPAIGNS:
        if camp["cluster_id"] == cluster_id:
            members = [a for a in DEFAULT_SEED_ALERTS if a.get("cluster_id") == cluster_id]
            return {
                "campaign": camp,
                "member_alerts": members,
                "total_domains": len(members),
            }

    raise HTTPException(status_code=404, detail=f"Campaign cluster '{cluster_id}' not found.")
