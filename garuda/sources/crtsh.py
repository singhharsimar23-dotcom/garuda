import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

from garuda.cache import (
    check_and_add_set,
    generate_cache_key,
    get_cached_json,
    set_cached_json,
)

logger = logging.getLogger("garuda.sources.crtsh")
SEEN_SERIALS_SET = "garuda:seen_serials"


async def _fetch_single_keyword(
    client: httpx.AsyncClient,
    keyword: str,
    semaphore: asyncio.Semaphore,
) -> List[Dict[str, Any]]:
    """
    Fetch certificates for a single keyword query from crt.sh with rate limit retries and caching.

    Args:
        client: Shared httpx.AsyncClient instance.
        keyword: Target keyword to match (%keyword%).
        semaphore: Asyncio semaphore to bound concurrency.

    Returns:
        List of raw certificate dictionaries from crt.sh or empty list on error.
    """
    cache_key = generate_cache_key("crtsh", keyword)
    cached_data = await get_cached_json(cache_key)
    if cached_data is not None:
        logger.debug(f"[crtsh] Using cached certificate results for keyword: '{keyword}'")
        return cached_data

    url = f"https://crt.sh/?q=%.{keyword}%&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    retried_429 = False

    async with semaphore:
        while True:
            try:
                response = await client.get(url, headers=headers, timeout=12.0)
                if response.status_code == 429 and not retried_429:
                    logger.warning(f"[crtsh] Rate limit hit (429) for keyword '{keyword}'. Sleeping 5s...")
                    retried_429 = True
                    await asyncio.sleep(5)
                    continue
                elif response.status_code in (404, 502, 503, 504):
                    return []

                response.raise_for_status()
                data = response.json()
                if isinstance(data, list):
                    await set_cached_json(cache_key, data, ex=1800)
                    return data
                return []
            except (httpx.HTTPError, httpx.TimeoutException):
                return []
            except Exception as e:
                logger.debug(f"[crtsh] Error parsing response for '{keyword}': {e}")
                return []


async def fetch_new_certs(keywords: List[str]) -> List[Dict[str, Any]]:
    """
    Query crt.sh Certificate Transparency logs for new certificates matching input keywords.

    Performs concurrent searches across keywords bounded by asyncio.Semaphore(5), deduplicates
    certificates by serial_number via Redis SET ('garuda:seen_serials'), splits multi-SAN domains,
    and returns standardized certificate threat records.

    Args:
        keywords: List of target keyword strings (e.g. TIER_1_PATTERNS).

    Returns:
        List of dictionaries with keys:
            - domain (str): The SAN domain string.
            - cert_issued_at (str): Certificate issuance timestamp (not_before).
            - serial (str): Certificate serial number.
            - source (str): Static string "crtsh".
    """
    if not keywords:
        return []

    semaphore = asyncio.Semaphore(5)
    results: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        tasks = [_fetch_single_keyword(client, kw, semaphore) for kw in keywords]
        keyword_results = await asyncio.gather(*tasks, return_exceptions=False)

    for cert_list in keyword_results:
        for cert in cert_list:
            if not isinstance(cert, dict):
                continue

            serial_number = str(cert.get("serial_number", "")).strip()
            if not serial_number:
                continue

            # Deduplicate by serial_number in Redis SET
            is_new = await check_and_add_set(SEEN_SERIALS_SET, serial_number)
            if not is_new:
                continue

            name_value = cert.get("name_value", "")
            not_before = cert.get("not_before", "")

            # name_value may contain \n-separated multiple domains (SANs)
            raw_domains = [d.strip() for d in str(name_value).split("\n") if d.strip()]
            for raw_domain in raw_domains:
                domain = raw_domain.lower().lstrip("*.")
                if not domain:
                    continue

                results.append({
                    "domain": domain,
                    "cert_issued_at": not_before,
                    "serial": serial_number,
                    "source": "crtsh",
                })

    return results
