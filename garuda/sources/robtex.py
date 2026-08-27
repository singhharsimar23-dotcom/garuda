import logging
from typing import Any, Dict, List, Optional
import httpx

from garuda.cache import (
    generate_cache_key,
    get_cached_json,
    set_cached_json,
)
from garuda.config import settings

logger = logging.getLogger("garuda.sources.robtex")


async def query_robtex_pdns(domain: str) -> List[Dict[str, Any]]:
    """
    Query Robtex Free API for forward passive DNS resolution data (no API key required).
    Endpoint: https://freeapi.robtex.com/pdns/forward/{domain}
    """
    domain = domain.strip().lower().lstrip("*.")
    if not domain:
        return []

    cache_key = generate_cache_key("robtex_pdns", domain)
    cached = await get_cached_json(cache_key)
    if cached is not None:
        return cached

    url = f"{settings.ROBTEX_API_URL}/pdns/forward/{domain}"
    results: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 200:
                # Robtex returns newline-delimited JSON
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        import json
                        rec = json.loads(line)
                        results.append({
                            "rrname": domain,
                            "rrtype": rec.get("rrtype", "A"),
                            "rdata": rec.get("rrdata", rec.get("rdata", "")),
                            "time_first": rec.get("time_first"),
                            "time_last": rec.get("time_last"),
                            "source": "robtex",
                        })
                    except Exception:
                        continue

            await set_cached_json(cache_key, results, ex=3600)
            return results
    except Exception as e:
        logger.warning(f"[robtex] Robtex query note for {domain}: {e}")
        return []


async def query_hackertarget_hostsearch(domain: str) -> List[Dict[str, Any]]:
    """
    Query HackerTarget HostSearch API for hostnames and IP mappings (no key required).
    Endpoint: https://api.hackertarget.com/hostsearch/?q={domain}
    """
    domain = domain.strip().lower().lstrip("*.")
    if not domain:
        return []

    cache_key = generate_cache_key("hackertarget", domain)
    cached = await get_cached_json(cache_key)
    if cached is not None:
        return cached

    url = f"{settings.HACKERTARGET_API_URL}/hostsearch/?q={domain}"
    results: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 200 and not response.text.startswith("error"):
                for line in response.text.splitlines():
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        host, ip = parts[0].strip(), parts[1].strip()
                        results.append({
                            "rrname": host,
                            "rrtype": "A",
                            "rdata": ip,
                            "source": "hackertarget",
                        })

            await set_cached_json(cache_key, results, ex=3600)
            return results
    except Exception as e:
        logger.warning(f"[hackertarget] Query note for {domain}: {e}")
        return []


async def query_virustotal_pdns(domain: str) -> List[Dict[str, Any]]:
    """
    Query VirusTotal v3 domain resolutions using configured VIRUSTOTAL_API_KEY.
    Endpoint: https://www.virustotal.com/api/v3/domains/{domain}/resolutions
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return []

    domain = domain.strip().lower().lstrip("*.")
    if not domain:
        return []

    cache_key = generate_cache_key("vt_pdns", domain)
    cached = await get_cached_json(cache_key)
    if cached is not None:
        return cached

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    results: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json().get("data", [])
                for item in data:
                    attrs = item.get("attributes", {})
                    ip = attrs.get("ip_address")
                    date_val = attrs.get("date")
                    if ip:
                        results.append({
                            "rrname": domain,
                            "rrtype": "A",
                            "rdata": ip,
                            "time_last": date_val,
                            "source": "virustotal",
                        })

            await set_cached_json(cache_key, results, ex=3600)
            return results
    except Exception as e:
        logger.warning(f"[virustotal] PDNS query note for {domain}: {e}")
        return []


async def query_unified_pdns(domain: str) -> List[Dict[str, Any]]:
    """
    Unified zero-auth and OSINT Passive DNS engine combining Robtex, VirusTotal, and HackerTarget.
    """
    import asyncio
    res_robtex, res_vt, res_ht = await asyncio.gather(
        query_robtex_pdns(domain),
        query_virustotal_pdns(domain),
        query_hackertarget_hostsearch(domain),
        return_exceptions=True,
    )

    combined: List[Dict[str, Any]] = []
    if isinstance(res_robtex, list):
        combined.extend(res_robtex)
    if isinstance(res_vt, list):
        combined.extend(res_vt)
    if isinstance(res_ht, list):
        combined.extend(res_ht)

    # Deduplicate by (rrname, rdata)
    seen = set()
    deduped = []
    for item in combined:
        key = (item.get("rrname"), item.get("rdata"))
        if key not in seen and item.get("rdata"):
            seen.add(key)
            deduped.append(item)

    return deduped
