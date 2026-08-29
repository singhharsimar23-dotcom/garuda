"""
GARUDA RDAP Registrar Enrichment (FIX-05)

Fetches registrar, creation date, and nameservers via IANA RDAP.
No API key required. Free, no rate limit restrictions.

Endpoint: https://rdap.org/domain/{domain}
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("garuda.modules.enrichment.rdap")


async def get_registrar_via_rdap(domain: str) -> dict:
    """
    Fetch registrar info using IANA RDAP — no API key, no rate limit.

    Returns:
        {
            registrar: str,
            creation_date: str | None,
            nameservers: list[str],
            domain_age_days: int | None
        }
    """
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code != 200:
                return _empty_result()

            data = resp.json()

            # Extract registrar from entities
            registrar = "Unknown"
            for entity in data.get("entities", []):
                if "registrar" in (entity.get("roles") or []):
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn" and len(entry) >= 4:
                                registrar = str(entry[3]).strip()
                                break
                    if registrar != "Unknown":
                        break

            # Extract creation date
            creation_date = None
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    creation_date = event.get("eventDate")
                    break

            # Extract nameservers
            nameservers = [
                ns.get("ldhName", "").lower()
                for ns in data.get("nameservers", [])
                if ns.get("ldhName")
            ]

            domain_age_days = _compute_age_days(creation_date)

            return {
                "registrar": registrar,
                "creation_date": creation_date,
                "nameservers": nameservers,
                "domain_age_days": domain_age_days,
            }

    except Exception as exc:
        logger.debug("[rdap] Failed for %s: %s", domain, exc)
        return _empty_result()


def _empty_result() -> dict:
    return {
        "registrar": "Unknown",
        "creation_date": None,
        "nameservers": [],
        "domain_age_days": None,
    }


def _compute_age_days(creation_date: Optional[str]) -> Optional[int]:
    """Compute domain age in days from ISO creation date string."""
    if not creation_date:
        return None
    try:
        dt = datetime.fromisoformat(creation_date.rstrip("Z").split("+")[0])
        return (datetime.now() - dt).days
    except Exception:
        return None


async def enrich_alert_registrar(alert_id: str, domain: str, supabase) -> None:
    """
    Fetch RDAP data and update the alert record immediately after insertion.
    Call this synchronously within the collection pass — do not defer.
    """
    rdap = await get_registrar_via_rdap(domain)
    if rdap["registrar"] != "Unknown" or rdap["domain_age_days"] is not None:
        update = {}
        if rdap["registrar"] != "Unknown":
            update["registrar"] = rdap["registrar"]
        if rdap["nameservers"]:
            update["nameservers"] = rdap["nameservers"]
        if rdap["domain_age_days"] is not None:
            update["domain_age_days"] = rdap["domain_age_days"]

        if update:
            try:
                supabase.table("alerts").update(update).eq("id", alert_id).execute()
                logger.info("[rdap] Enriched alert %s: registrar=%s", alert_id, rdap["registrar"])
            except Exception as exc:
                logger.warning("[rdap] Failed to update alert %s: %s", alert_id, exc)
