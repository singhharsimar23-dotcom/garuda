import logging
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from garuda.api.models import AlertResponse, CampaignListResponse, CampaignResponse
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
    if not client:
        # Run ML clustering in-memory if database not configured
        mock_camps = await detect_campaigns(window_hours=72)
        c_list = [CampaignResponse(**c) for c in mock_camps]
        return CampaignListResponse(campaigns=c_list)

    try:
        res = client.table("campaigns").select("*").order("created_at", desc=True).execute()
        campaigns = []
        for row in (res.data or []):
            cluster_id = row.get("cluster_id", "")
            # Fetch member domain list
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
                    confidence=row.get("confidence", "medium"),
                    created_at=str(row.get("created_at", "")),
                    domains=domains_list,
                )
            )
        return CampaignListResponse(campaigns=campaigns)
    except Exception as e:
        logger.error(f"[api.campaigns] Error listing campaigns: {e}")
        return CampaignListResponse(campaigns=[])


@router.get("/{cluster_id}")
async def get_campaign_detail(cluster_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed campaign profile including all correlated member threat alert records.
    """
    client = get_supabase_client()
    if not client:
        return {"cluster_id": cluster_id, "members": [], "details": {}}

    try:
        camp_res = client.table("campaigns").select("*").eq("cluster_id", cluster_id).limit(1).execute()
        if not camp_res.data:
            raise HTTPException(status_code=404, detail=f"Campaign cluster '{cluster_id}' not found.")

        campaign_data = camp_res.data[0]
        alerts_res = client.table("alerts").select("*").eq("cluster_id", cluster_id).execute()

        return {
            "campaign": campaign_data,
            "member_alerts": alerts_res.data or [],
            "total_domains": len(alerts_res.data or []),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[api.campaigns] Error retrieving campaign {cluster_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed querying campaign cluster details.")
