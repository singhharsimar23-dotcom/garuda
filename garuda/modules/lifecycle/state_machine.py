"""
GARUDA Lifecycle State Machine (FIX-13)

Daily DNS-resolve based lifecycle state transitions for confirmed alerts.
States: ACTIVE → PARKED | DEAD | TRANSFERRED | SINKHOLED

Lead time = GARUDA detection date to domain going dead/sinkholed.
Positive lead time = GARUDA detected it BEFORE the domain was weaponized publicly.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("garuda.modules.lifecycle.state_machine")

# IPs that indicate GARUDA's own sinkhole or public sinkholes
SINKHOLE_IPS: frozenset = frozenset({
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "192.168.0.1",
})

# Known domain parking IPs from major registrars
PARKING_IPS: frozenset = frozenset({
    "205.178.189.129",   # GoDaddy parked
    "64.98.145.30",      # Namecheap parked
    "198.54.120.200",    # Namecheap parked
    "205.178.189.131",   # GoDaddy parked 2
    "69.89.31.178",      # Bluehost parked
})


def _resolve_domain(domain: str) -> Optional[str]:
    """Resolve domain to IP. Returns None on NXDOMAIN/timeout."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        return None


def _determine_state(
    current_ip: Optional[str],
    original_ip: Optional[str],
) -> str:
    """Determine lifecycle state from current DNS resolution."""
    if current_ip is None:
        return "DEAD"
    if current_ip in SINKHOLE_IPS:
        return "SINKHOLED"
    if current_ip in PARKING_IPS:
        return "PARKED"
    if original_ip and current_ip != original_ip:
        return "TRANSFERRED"
    return "ACTIVE"


def _compute_lead_time(detected_at: Optional[str]) -> Optional[int]:
    """Days between GARUDA detection and now (used when domain dies)."""
    if not detected_at:
        return None
    try:
        dt_str = detected_at.rstrip("Z").split("+")[0]
        dt = datetime.fromisoformat(dt_str)
        return (datetime.now() - dt).days
    except Exception:
        return None


async def update_alert_lifecycle_states(supabase) -> dict:
    """
    Run daily to progress all confirmed/pending alerts through lifecycle states.
    Returns summary of transitions made.
    """
    summary = {"checked": 0, "updated": 0, "transitions": {}}

    try:
        result = supabase.table("alerts").select(
            "id,domain,hosting_ip,lifecycle_state,detected_at,status"
        ).in_("status", ["confirmed", "pending"]).execute()
    except Exception as exc:
        logger.error("[lifecycle] Failed to fetch alerts: %s", exc)
        return summary

    alerts = result.data or []
    logger.info("[lifecycle] Checking %d alerts", len(alerts))

    for alert in alerts:
        alert_id = alert.get("id")
        domain = alert.get("domain", "")
        original_ip = alert.get("hosting_ip")
        prev_state = alert.get("lifecycle_state", "ACTIVE")

        if not domain or not alert_id:
            continue

        summary["checked"] += 1
        current_ip = _resolve_domain(domain)
        new_state = _determine_state(current_ip, original_ip)

        if new_state == prev_state:
            continue

        update_data: dict = {
            "lifecycle_state": new_state,
            "lifecycle_updated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Calculate lead time when domain transitions from active to dead/sinkholed
        if new_state in ("DEAD", "SINKHOLED") and prev_state == "ACTIVE":
            lead_time = _compute_lead_time(alert.get("detected_at"))
            if lead_time is not None:
                update_data["lead_time_days"] = lead_time

        try:
            supabase.table("alerts").update(update_data).eq("id", alert_id).execute()
            summary["updated"] += 1
            summary["transitions"][f"{prev_state}→{new_state}"] = (
                summary["transitions"].get(f"{prev_state}→{new_state}", 0) + 1
            )
            logger.info(
                "[lifecycle] %s: %s → %s (ip=%s)",
                domain, prev_state, new_state, current_ip
            )
        except Exception as exc:
            logger.error("[lifecycle] Failed to update %s: %s", alert_id, exc)

    logger.info("[lifecycle] Done: %d/%d updated", summary["updated"], summary["checked"])
    return summary
