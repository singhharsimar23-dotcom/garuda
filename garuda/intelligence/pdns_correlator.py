"""
GARUDA — Passive DNS Correlation & Infrastructure Overlap Engine

Correlates threat indicator domains against historical forward DNS resolutions
from zero-auth and OSINT passive DNS feeds (Robtex, VirusTotal, HackerTarget).
Identifies historical infrastructure overlap with documented Indian defence & government netblocks.

CRITICAL ANALYTICAL DISTINCTION & ALERT COPY POLICY:
---------------------------------------------------
Passive DNS resolution records indicate which IP addresses a domain historically
pointed to (domain -> resolving IPs). They DO NOT indicate internal recursive
query logs (workstation -> queried domains).

Therefore, when a C2 domain historically resolved to an IP within a defence organisation's
netblock (e.g. temporary infrastructure reuse, VPS allocation, NAT/proxy overlap),
the alert MUST state:
  "Domain {domain} (confirmed {actor_name} indicator, GARUDA confidence {confidence})
   has a historical DNS resolution to an IP ({matched_ip}) within {org_name}'s documented
   netblock, observed via {source} on {observed_at}. This does not confirm an internal host
   queried this domain — it indicates historical infrastructure overlap and warrants manual review."

Never allow alert copy to overclaim as "DRDO/Organisation is compromised".
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

from garuda.config import settings
from garuda.database import (
    find_matching_defence_ip,
    get_monitored_defence_ips,
    insert_pdns_observation,
)
from garuda.sources.robtex import query_unified_pdns

logger = logging.getLogger("garuda.intelligence.pdns_correlator")


def generate_pdns_alert_copy(
    domain: str,
    matched_ip: str,
    org_name: str,
    source: str,
    observed_at: str,
    confidence: int = 80,
    actor_name: str = "APT36",
) -> str:
    """
    Generate precisely calibrated, legally and technically accurate alert copy
    for passive DNS infrastructure overlap detections.
    """
    clean_domain = domain.strip()
    clean_org = org_name.strip()
    clean_source = source.strip()
    clean_date = observed_at.split("T")[0] if "T" in str(observed_at) else str(observed_at)

    return (
        f"historical DNS resolution overlap observed between {clean_domain} and {clean_org} netblock, via {clean_source}. "
        f"This indicates infrastructure overlap, not confirmed internal query — manual verification required. "
        f"(Matched IP: {matched_ip}, Observed: {clean_date}, Confidence: {confidence})"
    )


async def send_pdns_telegram_alert(alert_text: str) -> bool:
    """Send formatted alert to CERT / SOC Telegram channel."""
    token = settings.TELEGRAM_BOT_TOKEN
    chat_id = settings.TELEGRAM_CHAT_ID
    if not token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": f"🛡️ <b>GARUDA PASSIVE DNS CORRELATION</b>\n\n{alert_text}",
        "parse_mode": "HTML",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            return resp.status_code == 200
    except Exception as e:
        logger.warning(f"[pdns_correlator] Failed to send Telegram alert: {e}")
        return False


async def correlate_domain_pdns(
    domain: str,
    stix_indicator_id: Optional[str] = None,
    confidence: int = 80,
    actor_name: str = "APT36",
    send_alert: bool = True,
    custom_resolutions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Execute reactive passive DNS correlation for a threat domain.

    Args:
        domain: Threat indicator domain name.
        stix_indicator_id: Optional STIX Indicator object ID provenance.
        confidence: Threat confidence score (default: 80).
        actor_name: Associated threat actor label (default: 'APT36').
        send_alert: If True, dispatch alert to Telegram when overlap is found.
        custom_resolutions: Optional pre-fetched or fixture resolutions for offline testing.

    Returns:
        Dict summarizing total resolutions analyzed, matches found, and observation records.
    """
    clean_domain = domain.strip().lower().lstrip("*.")
    if not clean_domain:
        return {
            "domain": domain,
            "resolutions_checked": 0,
            "matches_found": 0,
            "observations": [],
        }

    # Fetch passive DNS resolution history (or use fixture)
    if custom_resolutions is not None:
        resolutions = custom_resolutions
    else:
        resolutions = await query_unified_pdns(clean_domain)

    matched_observations: List[Dict[str, Any]] = []
    alerts_dispatched: List[str] = []

    for record in resolutions:
        ip = record.get("rdata") or record.get("ip") or record.get("ip_address")
        if not ip or not isinstance(ip, str):
            continue

        ip = ip.strip()
        matched_defence_row = await find_matching_defence_ip(ip)
        if not matched_defence_row:
            continue

        # Infrastructure overlap confirmed!
        org_name = matched_defence_row.get("org_name", "Indian Defence Sector")
        source_provider = record.get("source") or "Passive DNS Feed"
        observed_time = record.get("time_last") or record.get("observed_at") or datetime.now(timezone.utc).isoformat()

        # Format observation record
        observation = await insert_pdns_observation(
            defence_ip_id=matched_defence_row.get("id"),
            queried_domain=clean_domain,
            resolved_via=source_provider,
            matches_known_c2=True,
            stix_indicator_id=stix_indicator_id,
            observed_at=str(observed_time),
            raw_response=record,
        )

        # Generate accurate alert copy
        alert_copy = generate_pdns_alert_copy(
            domain=clean_domain,
            matched_ip=ip,
            org_name=org_name,
            source=source_provider,
            observed_at=str(observed_time),
            confidence=confidence,
            actor_name=actor_name,
        )

        matched_observations.append({
            "observation_id": observation.get("id"),
            "matched_ip": ip,
            "org_name": org_name,
            "source": source_provider,
            "observed_at": str(observed_time),
            "alert_copy": alert_copy,
            "raw_record": record,
        })

        if send_alert:
            await send_pdns_telegram_alert(alert_copy)
            alerts_dispatched.append(alert_copy)

    return {
        "domain": clean_domain,
        "resolutions_checked": len(resolutions),
        "matches_found": len(matched_observations),
        "observations": matched_observations,
        "alerts_dispatched": alerts_dispatched,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
