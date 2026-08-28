"""
GARUDA — CISA Known Exploited Vulnerabilities (KEV) Catalog Source

Fetches and caches the CISA KEV catalog. No authentication required.
The catalog is updated infrequently but the whole point of this pipeline
is responding fast when it does update — hence the 6-hour sync cron.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Rate limiting: no enforced limit on CISA's end, but we cap re-fetches at
once per 6 hours via _LAST_FETCH_TS to be a considerate API citizen.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from garuda.config import settings

logger = logging.getLogger("garuda.sources.cisa_kev")

# Module-level in-process cache — small enough (~2 MB) to keep in memory.
# Refreshed by the 6-hour cron or on the first call after a cold start.
_KEV_CACHE: List[Dict[str, Any]] = []
_LAST_FETCH_TS: float = 0.0
_MIN_FETCH_INTERVAL_SECONDS: int = 6 * 3600   # 6 hours

# Field mapping: KEV JSON key → normalised internal key
_KEV_FIELD_MAP = {
    "cveID": "cve_id",
    "vendorProject": "vendor_project",
    "product": "affected_product",
    "vulnerabilityName": "vulnerability_name",
    "dateAdded": "date_added",
    "shortDescription": "description",
    "requiredAction": "required_action",
    "dueDate": "due_date",
    "knownRansomwareCampaignUse": "known_ransomware_use_raw",  # "Known" | "Unknown"
    "notes": "notes",
}


def _normalise_entry(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalise a single raw KEV JSON entry into a consistent internal dict.
    known_ransomware_use is a boolean derived from knownRansomwareCampaignUse.
    """
    entry: Dict[str, Any] = {}
    for kev_key, internal_key in _KEV_FIELD_MAP.items():
        entry[internal_key] = raw.get(kev_key)

    # Canonicalise the ransomware boolean: KEV uses "Known" / "Unknown"
    raw_val = (entry.get("known_ransomware_use_raw") or "").strip().lower()
    entry["known_ransomware_use"] = raw_val == "known"

    # Parse date_added to a date object (keep as string in cache, parse on use)
    return entry


class KevSyncResult:
    """Summary returned by sync_kev_catalog()."""

    def __init__(
        self,
        total_fetched: int,
        new_entries: int,
        fetch_skipped: bool,
        fetched_at: Optional[datetime] = None,
        error: Optional[str] = None,
    ):
        self.total_fetched = total_fetched
        self.new_entries = new_entries
        self.fetch_skipped = fetch_skipped
        self.fetched_at = fetched_at or datetime.now(timezone.utc)
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_fetched": self.total_fetched,
            "new_entries": self.new_entries,
            "fetch_skipped": self.fetch_skipped,
            "fetched_at": self.fetched_at.isoformat(),
            "error": self.error,
        }


def get_cached_kev() -> List[Dict[str, Any]]:
    """Return the current in-process KEV cache. May be empty before first sync."""
    return list(_KEV_CACHE)


def get_kev_entry_by_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up a specific CVE in the cached KEV catalog.
    Returns None if not in KEV (not yet catalogued or not yet synced).
    O(n) scan — KEV is ~1200 entries, acceptable for cron frequency.
    """
    cve_upper = cve_id.upper()
    for entry in _KEV_CACHE:
        if (entry.get("cve_id") or "").upper() == cve_upper:
            return entry
    return None


async def fetch_kev_catalog(
    force_refresh: bool = False,
    timeout_seconds: int = 30,
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Fetch the CISA KEV catalog. Returns (entries, was_refreshed).

    Args:
        force_refresh: Bypass the 6-hour throttle (e.g., for tests).
        timeout_seconds: HTTP timeout in seconds.

    Returns:
        Tuple of (list of normalised KEV entries, bool indicating fresh fetch).
    """
    global _KEV_CACHE, _LAST_FETCH_TS

    now = time.monotonic()
    if not force_refresh and _KEV_CACHE and (now - _LAST_FETCH_TS) < _MIN_FETCH_INTERVAL_SECONDS:
        logger.debug("[cisa_kev] Returning cached KEV catalog (%d entries)", len(_KEV_CACHE))
        return list(_KEV_CACHE), False

    url = settings.CISA_KEV_URL
    logger.info("[cisa_kev] Fetching KEV catalog from %s", url)

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.error("[cisa_kev] HTTP error fetching KEV: %s", exc)
        # Return stale cache if available rather than crashing the cron
        return list(_KEV_CACHE), False
    except Exception as exc:
        logger.error("[cisa_kev] Unexpected error fetching KEV: %s", exc)
        return list(_KEV_CACHE), False

    raw_vulns = data.get("vulnerabilities", [])
    if not isinstance(raw_vulns, list) or len(raw_vulns) == 0:
        logger.error("[cisa_kev] KEV response missing 'vulnerabilities' list or empty — structure changed?")
        return list(_KEV_CACHE), False

    normalised = [_normalise_entry(v) for v in raw_vulns]
    _KEV_CACHE = normalised
    _LAST_FETCH_TS = now

    logger.info("[cisa_kev] KEV catalog refreshed: %d entries", len(_KEV_CACHE))
    return list(_KEV_CACHE), True


async def sync_kev_catalog(force_refresh: bool = False) -> KevSyncResult:
    """
    High-level sync entry point called by the cron job.
    Fetches the catalog and returns a KevSyncResult summarising what changed.

    In v1 the 'new_entries' count compares against the previous cache length.
    Session 5 will add CVE-usage logging that enables actor-correlation diffs.
    """
    prev_count = len(_KEV_CACHE)
    entries, was_refreshed = await fetch_kev_catalog(force_refresh=force_refresh)

    if not was_refreshed:
        return KevSyncResult(
            total_fetched=len(entries),
            new_entries=0,
            fetch_skipped=True,
        )

    new_count = max(0, len(entries) - prev_count)
    return KevSyncResult(
        total_fetched=len(entries),
        new_entries=new_count,
        fetch_skipped=False,
    )
