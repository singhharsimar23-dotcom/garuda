import logging
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from garuda.api.models import AlertResponse, CampaignListResponse, CampaignResponse
from garuda.database import get_supabase_client

logger = logging.getLogger("garuda.api.routes.campaigns")

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@router.get("", response_model=CampaignListResponse)
async def list_campaign_clusters() -> CampaignListResponse:
    """
    Retrieve all correlated APT36 campaign clusters directly from database.
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
            logger.error(f"[api.campaigns] Error listing campaigns: {e}")

    return CampaignListResponse(campaigns=campaigns)


@router.get("/{cluster_id}")
async def get_campaign_detail(cluster_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed campaign profile and member threat alerts from database.
    """
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=503, detail="Database connection unavailable.")

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
        raise HTTPException(status_code=500, detail="Database query failure.")
