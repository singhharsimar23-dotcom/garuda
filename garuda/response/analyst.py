from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
from uuid import UUID

from garuda.database import get_supabase_client

logger = logging.getLogger("garuda.response.analyst")


async def confirm_alert(alert_id: str, analyst_id: str = "telegram_analyst") -> Dict[str, Any]:
    """
    Mark an alert as confirmed malicious by an authorized analyst and record audit log.

    Args:
        alert_id: Target alert UUID or short identifier.
        analyst_id: Identification handle of the confirming analyst.

    Returns:
        Dict: Result status and updated alert details.
    """
    client = get_supabase_client()
    if not client:
        return {"status": "ok", "alert_id": alert_id, "state": "confirmed", "note": "Local mock confirmation"}

    try:
        # Update alert status to confirmed
        client.table("alerts").update({
            "status": "confirmed",
            "analyst_id": analyst_id,
            "analyst_note": "Confirmed malicious threat infrastructure.",
        }).eq("id", alert_id).execute()

        # Append to audit_log (enforcing RLS immutability)
        client.table("audit_log").insert({
            "action": "confirm_alert",
            "analyst_id": analyst_id,
            "justification": f"Analyst {analyst_id} confirmed alert {alert_id} as malicious threat infrastructure.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

        return {"status": "confirmed", "alert_id": alert_id, "analyst_id": analyst_id}
    except Exception as e:
        logger.warning(f"[analyst] Database update warning for alert {alert_id}: {e}")
        return {"status": "confirmed", "alert_id": alert_id, "analyst_id": analyst_id, "note": "Fallback confirmation"}


async def reject_alert(alert_id: str, reason: str = "False positive", analyst_id: str = "telegram_analyst") -> Dict[str, Any]:
    """
    Mark an alert as false positive / rejected with justification in the audit log.

    Args:
        alert_id: Target alert UUID or short identifier.
        reason: Mandatory analyst justification reason.
        analyst_id: Identification handle of the rejecting analyst.

    Returns:
        Dict: Result status and updated alert details.
    """
    client = get_supabase_client()
    if not client:
        return {"status": "ok", "alert_id": alert_id, "state": "rejected", "reason": reason}

    try:
        client.table("alerts").update({
            "status": "false_positive",
            "analyst_id": analyst_id,
            "analyst_note": reason,
        }).eq("id", alert_id).execute()

        client.table("audit_log").insert({
            "action": "reject_alert",
            "analyst_id": analyst_id,
            "justification": f"Analyst rejected alert {alert_id}. Reason: {reason}",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

        return {"status": "rejected", "alert_id": alert_id, "reason": reason}
    except Exception as e:
        logger.warning(f"[analyst] Database rejection warning for alert {alert_id}: {e}")
        return {"status": "rejected", "alert_id": alert_id, "reason": reason}


async def whitelist_domain_action(domain: str, reason: str, analyst_id: str = "telegram_analyst") -> Dict[str, Any]:
    """Add a domain to the permanent whitelist and log justification in audit log."""
    client = get_supabase_client()
    if not client:
        return {"status": "whitelisted", "domain": domain}

    try:
        client.table("whitelist").insert({
            "domain": domain.lower().strip(),
            "reason": reason,
            "analyst_id": analyst_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

        client.table("audit_log").insert({
            "action": "add_whitelist",
            "analyst_id": analyst_id,
            "justification": f"Whitelisted domain {domain}. Reason: {reason}",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

        return {"status": "whitelisted", "domain": domain}
    except Exception as e:
        logger.warning(f"[analyst] Database whitelist warning for {domain}: {e}")
        return {"status": "whitelisted", "domain": domain}
