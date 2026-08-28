"""
EASM collector — live BGP-announced prefixes for Indian defence ASNs.

Replaces guessed /16 ranges with actual prefixes from RIPE Stat REST API.
Cache TTL=3600 (prefixes change rarely).
"""

from __future__ import annotations

import logging
from typing import Any

from garuda.modules.bgp.ripe_stat import get_announced_prefixes
from garuda.modules.easm.constants import INDIAN_DEFENCE_ASNS

logger = logging.getLogger("garuda.modules.easm.collector")


async def get_live_defence_prefixes() -> list[dict[str, Any]]:
    """
    Fetch live BGP-announced prefixes for each ASN in INDIAN_DEFENCE_ASNS.

    Returns list of dicts: {asn, prefix, org_label, source}
    Cached per-ASN via ripe_stat.get_announced_prefixes (TTL=3600).
    """
    results: list[dict[str, Any]] = []

    for asn, org_label, source in INDIAN_DEFENCE_ASNS:
        try:
            prefixes = await get_announced_prefixes(asn)
        except Exception as exc:
            logger.error("[easm/collector] Failed prefixes for AS%s: %s", asn, exc)
            continue

        for prefix in prefixes:
            results.append({
                "asn": asn,
                "prefix": prefix,
                "cidr": prefix,
                "org_label": org_label,
                "source": f"RIPE Stat announced-prefixes AS{asn} — {source}",
            })

    return results


async def get_defence_scan_targets() -> list[dict[str, Any]]:
    """
    Build scan targets for EASM: live BGP prefixes for defence ASNs.
    Used by EASM cron instead of hardcoded /16 ranges.
    """
    return await get_live_defence_prefixes()
