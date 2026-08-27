import json
import logging
from typing import Any, Dict, List, Optional
import httpx

from garuda.cache import (
    generate_cache_key,
    get_cached_json,
    set_cached_json,
)
from garuda.config import settings

logger = logging.getLogger("garuda.sources.circl_pdns")


async def query_pdns(domain: str) -> List[Dict[str, Any]]:
    """
    Query CIRCL Passive DNS service for historical DNS resolution records of a domain.

    Queries https://www.circl.lu/pdns/query/{domain}. The endpoint returns newline-delimited
    JSON (NDJSON) containing historical DNS entries (A, AAAA, NS, MX, CNAME, TXT).
    These records enable nameserver account fingerprinting and infrastructure clustering.

    Args:
        domain: Domain name to query (e.g., 'example.com').

    Returns:
        List of dictionaries with keys:
            - rrname (str): Resource record name.
            - rrtype (str): DNS record type (e.g. 'A', 'NS', 'MX').
            - rdata (str or list): Target IP or hostname pointed to.
            - time_first (int/str): Epoch or ISO timestamp first observed.
            - time_last (int/str): Epoch or ISO timestamp last observed.
    """
    domain = domain.strip().lower().lstrip("*.")
    if not domain:
        return []

    cache_key = generate_cache_key("circl_pdns", domain)
    cached = await get_cached_json(cache_key)
    if cached is not None:
        logger.debug(f"[circl_pdns] Returning cached PDNS records for '{domain}'")
        return cached

    url = f"https://www.circl.lu/pdns/query/{domain}"
    auth: Optional[httpx.BasicAuth] = None
    if settings.CIRCL_API_USER and settings.CIRCL_API_PASSWORD:
        auth = httpx.BasicAuth(settings.CIRCL_API_USER, settings.CIRCL_API_PASSWORD)

    results: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, auth=auth) as client:
            response = await client.get(url)
            if response.status_code == 404:
                # No passive DNS records found for domain
                await set_cached_json(cache_key, [], ex=1800)
                return []

            response.raise_for_status()

            # Parse NDJSON line by line
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        results.append({
                            "rrname": record.get("rrname", domain),
                            "rrtype": record.get("rrtype", ""),
                            "rdata": record.get("rdata", ""),
                            "time_first": record.get("time_first", record.get("time_first_ms")),
                            "time_last": record.get("time_last", record.get("time_last_ms")),
                        })
                except json.JSONDecodeError:
                    continue

            await set_cached_json(cache_key, results, ex=1800)
            return results
    except httpx.HTTPError as err:
        logger.error(f"[circl_pdns] HTTP error querying CIRCL PDNS for '{domain}': {err}")
        return []
    except Exception as e:
        logger.error(f"[circl_pdns] Unexpected error parsing CIRCL PDNS for '{domain}': {e}")
        return []
