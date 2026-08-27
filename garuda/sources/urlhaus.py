import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx

from garuda.cache import (
    generate_cache_key,
    get_cached_json,
    set_cached_json,
)
from garuda.config import settings

logger = logging.getLogger("garuda.sources.urlhaus")


def _extract_domain(url_str: str, host_str: Optional[str] = None) -> str:
    """Extract and normalize domain name from URL or host string."""
    if host_str and "." in host_str:
        return host_str.strip().lower().split(":")[0].lstrip("*.")
    try:
        parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
        netloc = (parsed.hostname or parsed.netloc).split(":")[0].strip().lower().lstrip("*.")
        return netloc
    except Exception:
        return url_str.split("/")[0].split(":")[0].strip().lower()


async def fetch_recent_malware_urls() -> List[Dict[str, Any]]:
    """
    Fetch recent malware URLs from URLhaus and filter by APT36 tags or TIER_1_PATTERNS.

    Queries https://urlhaus-api.abuse.ch/v1/urls/recent/ without authentication,
    filters the latest 1,000 URLs for APT36 activity or Indian critical infrastructure
    pattern matches, and caches the results in Redis.

    Returns:
        List of dictionaries with keys:
            - domain (str): Extracted target domain or hostname.
            - url (str): The full malware payload URL.
            - status (str): Online/offline status from URLhaus.
            - threat (str): Type of threat (e.g. malware_download).
            - source (str): Static string "urlhaus".
    """
    cache_key = generate_cache_key("urlhaus", "recent_malware_urls")
    cached = await get_cached_json(cache_key)
    if cached is not None:
        logger.debug("[urlhaus] Returning cached URLhaus feed data")
        return cached

    endpoint = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    results: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(endpoint, json={})
            response.raise_for_status()
            data = response.json()
            urls = data.get("urls", [])

            tier_1_lower = [p.lower() for p in settings.TIER_1_PATTERNS]

            for entry in urls:
                if not isinstance(entry, dict):
                    continue

                raw_url = entry.get("url", "")
                host = entry.get("host", "")
                url_status = entry.get("url_status", "")
                threat = entry.get("threat", "")
                tags = [str(t).lower() for t in entry.get("tags") or []]

                # Filter: tags contains "apt36" OR host matches TIER_1_PATTERNS
                matches_apt36 = any("apt36" in t or "transparent" in t for t in tags)
                host_lower = str(host).lower()
                matches_tier1 = any(pattern in host_lower for pattern in tier_1_lower)

                if matches_apt36 or matches_tier1:
                    domain = _extract_domain(raw_url, host)
                    if domain:
                        results.append({
                            "domain": domain,
                            "url": raw_url,
                            "status": url_status,
                            "threat": threat,
                            "source": "urlhaus",
                        })

            await set_cached_json(cache_key, results, ex=1800)
            return results
    except httpx.HTTPError as err:
        logger.error(f"[urlhaus] HTTP error querying recent malware URLs: {err}")
        return []
    except Exception as e:
        logger.error(f"[urlhaus] Unexpected error processing URLhaus feed: {e}")
        return []


async def submit_ioc(url: str, threat: str) -> bool:
    """
    Submit a malicious URL indicator to URLhaus.

    Queries POST https://urlhaus-api.abuse.ch/v1/url/ with API authentication.

    Args:
        url: The malicious payload URL.
        threat: Threat category (e.g., 'malware_download', 'apt36_c2').

    Returns:
        bool: True if submission succeeded (urlhaus_submit_status == 'ok'), False otherwise.
    """
    token = settings.URLHAUS_API_KEY
    if not token:
        logger.warning("[urlhaus] Cannot submit IOC: URLHAUS_API_KEY is not configured.")
        return False

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    payload = {
        "token": token,
        "url": url,
        "threat": threat,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(endpoint, data=payload)
            response.raise_for_status()
            data = response.json()
            submit_status = data.get("query_status") or data.get("urlhaus_submit_status")
            return submit_status == "ok"
    except httpx.HTTPError as err:
        logger.error(f"[urlhaus] HTTP error submitting IOC '{url}': {err}")
        return False
    except Exception as e:
        logger.error(f"[urlhaus] Unexpected error submitting IOC '{url}': {e}")
        return False
