import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List
from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from garuda.api.models import (
    AuditLogEntry,
    ConfirmAlertRequest,
    ConfirmAlertResponse,
    RejectAlertRequest,
    WhitelistRequest,
)
from garuda.database import get_supabase_client
from garuda.intelligence.llm_enrichment import generate_threat_narrative
from garuda.response.analyst import confirm_alert, reject_alert, whitelist_domain_action
from garuda.response.blocklist_submit import submit_to_phishtank, submit_to_urlhaus
from garuda.response.certin_advisory import generate_advisory_draft
from garuda.response.screenshot import capture_screenshot
from garuda.response.stix_export import create_stix_bundle
from garuda.response.yara_generator import generate_yara_rule

logger = logging.getLogger("garuda.api.routes.analyst")

router = APIRouter(prefix="/analyst", tags=["Analyst Triage"])


async def _run_post_confirmation_tasks(alert_data: Dict[str, Any], alert_id: str) -> None:
    """Execute background blocklist submissions and visual screenshot captures."""
    domain = alert_data.get("domain", "")
    url = f"https://{domain}" if not domain.startswith("http") else domain

    # 1. URLhaus & PhishTank submission (alert is now confirmed)
    await submit_to_urlhaus(url, alert={"status": "confirmed"})
    await submit_to_phishtank(url)

    # 2. Screenshot Capture
    screenshot_url = await capture_screenshot(domain, alert_id)

    # 3. LLM Narrative Generation
    narrative = await generate_threat_narrative(alert_data)

    client = get_supabase_client()
    if client:
        try:
            update_payload: Dict[str, Any] = {"llm_narrative": narrative}
            if screenshot_url:
                update_payload["screenshot_url"] = screenshot_url
            client.table("alerts").update(update_payload).ilike("id", f"{alert_id}%").execute()
        except Exception as e:
            logger.error(f"[api.analyst] Error updating post-confirmation telemetry: {e}")


@router.post("/confirm", response_model=ConfirmAlertResponse)
async def confirm_threat_alert(
    payload: ConfirmAlertRequest,
    background_tasks: BackgroundTasks,
) -> ConfirmAlertResponse:
    """
    Analyst confirmation of malicious threat infrastructure.

    Actions:
        1. Updates alert state to 'confirmed'.
        2. Appends immutable audit entry to 'audit_log'.
        3. Generates CERT-In security advisory draft.
        4. Serializes STIX 2.1 IOC bundle.
        5. Generates endpoint YARA rule.
        6. Dispatches background blocklist submissions and screenshot capture.
    """
    client = get_supabase_client()
    alert_record: Dict[str, Any] = {
        "id": payload.alert_id,
        "domain": "target-threat.space",
        "score": 85,
        "sector": "Ministry of Defence (MoD)",
        "status": "confirmed",
    }

    if client:
        try:
            res = client.table("alerts").select("*").ilike("id", f"{payload.alert_id}%").limit(1).execute()
            if res.data:
                alert_record = res.data[0]
                alert_record["status"] = "confirmed"
        except Exception as e:
            logger.warning(f"[api.analyst] Database alert fetch warning: {e}")

    # Perform confirmation & audit logging
    res_confirm = await confirm_alert(payload.alert_id, analyst_id=payload.analyst_id)
    if res_confirm.get("status") == "error":
        raise HTTPException(status_code=500, detail="Failed to confirm alert in database.")

    # Generate response artifacts
    advisory_draft = generate_advisory_draft(alert_record)
    stix_bundle = create_stix_bundle(alert_record)
    stix_id = str(stix_bundle.id) if hasattr(stix_bundle, "id") else f"bundle--{payload.alert_id[:8]}"
    yara_rule = generate_yara_rule(alert_record)

    # Persist stix_id & yara_rule in alert record
    if client:
        try:
            client.table("alerts").update({
                "stix_id": stix_id,
                "yara_rule": yara_rule,
            }).ilike("id", f"{payload.alert_id}%").execute()
        except Exception as e:
            logger.warning(f"[api.analyst] Error saving STIX/YARA IDs: {e}")

    # Dispatch background tasks
    background_tasks.add_task(_run_post_confirmation_tasks, alert_record, payload.alert_id)

    return ConfirmAlertResponse(
        success=True,
        alert_id=payload.alert_id,
        status="confirmed",
        advisory_draft=advisory_draft,
        stix_id=stix_id,
        yara_rule=yara_rule,
    )


@router.post("/reject")
async def reject_threat_alert(payload: RejectAlertRequest) -> Dict[str, Any]:
    """
    Analyst rejection of false positive or benign domain alert.

    If reason_code == 'legitimate_domain', the target is added to the permanent whitelist.
    """
    res = await reject_alert(
        alert_id=payload.alert_id,
        reason=f"[{payload.reason_code}] {payload.justification}",
        analyst_id=payload.analyst_id,
    )

    if res.get("status") == "error":
        raise HTTPException(status_code=500, detail="Failed to reject alert in database.")

    # Whitelist if declared legitimate domain
    if payload.reason_code == "legitimate_domain":
        client = get_supabase_client()
        domain = ""
        if client:
            try:
                alert_res = client.table("alerts").select("domain").ilike("id", f"{payload.alert_id}%").limit(1).execute()
                if alert_res.data:
                    domain = alert_res.data[0].get("domain", "")
            except Exception:
                pass
        if domain:
            await whitelist_domain_action(domain, reason=f"False positive rejection: {payload.justification}", analyst_id=payload.analyst_id)

    return {"success": True, "alert_id": payload.alert_id, "status": "false_positive"}


@router.post("/whitelist")
async def add_whitelist_domain(payload: WhitelistRequest) -> Dict[str, Any]:
    """
    Explicitly add a domain to the permanent whitelist and record audit entry.
    """
    res = await whitelist_domain_action(
        domain=payload.domain,
        reason=payload.reason,
        analyst_id=payload.analyst_id,
    )
    if res.get("status") == "error":
        raise HTTPException(status_code=500, detail="Failed writing domain to whitelist table.")
    return {"success": True, "domain": payload.domain, "status": "whitelisted"}


@router.get("/audit/{alert_id}", response_model=List[AuditLogEntry])
async def get_alert_audit_trail(alert_id: str) -> List[AuditLogEntry]:
    """
    Retrieve the immutable append-only audit trail entries associated with an alert.
    """
    client = get_supabase_client()
    if not client:
        return []

    try:
        res = client.table("audit_log").select("*").ilike("alert_id", f"{alert_id}%").order("created_at", desc=True).execute()
        entries = []
        for row in (res.data or []):
            entries.append(
                AuditLogEntry(
                    id=str(row.get("id", "")),
                    alert_id=str(row.get("alert_id", "")),
                    action=row.get("action", ""),
                    analyst_id=row.get("analyst_id"),
                    justification=row.get("justification", ""),
                    created_at=str(row.get("created_at", "")),
                )
            )
        return entries
    except Exception as e:
        logger.error(f"[api.analyst] Error retrieving audit log for {alert_id}: {e}")
        return []
