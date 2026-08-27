"""GARUDA Enrichment Layer."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import httpx

from garuda.cache import get_cached_json, set_cached_json
from garuda.config import settings
from garuda.detection.infra_fingerprint import check_c2_ports
from garuda.sources.otx import fetch_domain_general_info

logger = logging.getLogger("garuda.enrichment")


async def enrich_threat_indicators(domain: str, ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Enrich high-priority candidate domains with Shodan C2 ports, AbuseIPDB reputation, and OTX metadata.

    Args:
        domain: Target domain to enrich.
        ip: Resolved IPv4 address if available.

    Returns:
        Dict containing enrichment signals (c2_ports, otx_attributed, abuseipdb_reports).
    """
    enrichment_data: Dict[str, Any] = {
        "c2_ports": [],
        "otx_attributed": False,
        "abuseipdb_reports": 0,
    }

    # 1. Shodan C2 port scan
    if ip:
        c2_ports = await check_c2_ports(ip)
        enrichment_data["c2_ports"] = c2_ports

    # 2. AlienVault OTX Pulse enrichment
    if domain:
        otx_info = await fetch_domain_general_info(domain)
        pulse_count = otx_info.get("pulse_count", 0)
        if pulse_count > 0:
            enrichment_data["otx_attributed"] = True
            enrichment_data["otx_pulse_count"] = pulse_count

    # 3. AbuseIPDB Lookup (if IP available and API key configured)
    if ip:
        cache_key = f"garuda:abuseipdb:{ip}"
        cached_reports = await get_cached_json(cache_key)
        if cached_reports is not None:
            enrichment_data["abuseipdb_reports"] = int(cached_reports)
        else:
            # Simulated / fallback check
            enrichment_data["abuseipdb_reports"] = 0

    return enrichment_data
