"""GARUDA Enrichment Layer."""
import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import httpx

from garuda.cache import get_cached_json, set_cached_json
from garuda.config import settings
from garuda.detection.infra_fingerprint import check_c2_ports, check_virustotal_reputation, fetch_whois_record
from garuda.sources.otx import fetch_domain_general_info

logger = logging.getLogger("garuda.enrichment")


async def _shodan_safe(ip: str) -> Dict[str, Any]:
    try:
        ports = await check_c2_ports(ip)
        return {"c2_ports": ports}
    except Exception as e:
        logger.warning(f"Shodan safe enrichment error: {e}")
        return {"c2_ports": []}


async def _otx_safe(domain: str) -> Dict[str, Any]:
    try:
        otx_info = await fetch_domain_general_info(domain)
        pulse_count = otx_info.get("pulse_count", 0)
        return {"otx_attributed": pulse_count > 0, "otx_pulse_count": pulse_count}
    except Exception as e:
        logger.warning(f"OTX safe enrichment error: {e}")
        return {"otx_attributed": False}


async def _vt_safe(domain: str) -> Dict[str, Any]:
    try:
        verdict = await check_virustotal_reputation(domain)
        return {"virustotal": verdict}
    except Exception as e:
        logger.warning(f"VirusTotal safe enrichment error: {e}")
        return {}


async def enrich_threat_indicators(domain: str, ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Enrich high-priority candidate domains with graceful degradation on missing/failed API keys.
    """
    signals: Dict[str, Any] = {
        "c2_ports": [],
        "otx_attributed": False,
        "abuseipdb_reports": 0,
    }

    tasks = {}
    if settings.SHODAN_API_KEY and ip:
        tasks["shodan"] = _shodan_safe(ip)
    if settings.OTX_API_KEY and domain:
        tasks["otx"] = _otx_safe(domain)
    if settings.VIRUSTOTAL_API_KEY and domain:
        tasks["virustotal"] = _vt_safe(domain)

    if not tasks:
        return signals

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for (key, _), result in zip(tasks.items(), results):
        if isinstance(result, Exception):
            logger.warning(f"Enrichment {key} failed: {result} — skipping")
        elif isinstance(result, dict):
            signals.update(result)

    return signals
