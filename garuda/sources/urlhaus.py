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
    Fetch recent malware URLs from URLhaus open public feed.
    """
    cache_key = generate_cache_key("urlhaus", "recent_malware_urls")
    cached = await get_cached_json(cache_key)
    if cached is not None:
        logger.debug("[urlhaus] Returning cached URLhaus feed data")
        return cached

    results: List[Dict[str, Any]] = []
    headers = {}
    if settings.URLHAUS_TOKEN:
        headers["Auth-Key"] = settings.URLHAUS_TOKEN

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=headers) as client:
            # Try public export feed first
            response = await client.get("https://urlhaus.abuse.ch/downloads/json_recent/")
            if response.status_code == 200:
                data = response.json()
                urls = []
                for _, entries in data.items():
                    if isinstance(entries, list):
                        urls.extend(entries)

                tier_1_lower = [p.lower() for p in settings.TIER_1_PATTERNS]

                for entry in urls:
                    if not isinstance(entry, dict):
                        continue

                    raw_url = entry.get("url", "")
                    host = entry.get("host", "")
                    url_status = entry.get("url_status", "")
                    threat = entry.get("threat", "")
                    tags = [str(t).lower() for t in entry.get("tags") or []]

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
    except Exception as e:
        logger.warning(f"[urlhaus] Public feed lookup note: {e}")

    return []


async def submit_ioc(url: str, threat: str) -> bool:
    """Submit IOC to URLhaus."""
    token = settings.URLHAUS_TOKEN
    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0, headers={"Auth-Key": token}) as client:
            res = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url, "threat": threat})
            return res.status_code == 200
    except Exception:
        return False

