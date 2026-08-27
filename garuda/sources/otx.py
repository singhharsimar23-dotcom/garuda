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

logger = logging.getLogger("garuda.sources.otx")
TARGET_TAG_KEYWORDS = ["apt36", "transparent tribe", "sidewinder"]
INDICATOR_TYPES = {"domain", "hostname", "url", "URL", "Domain", "Hostname"}


def _extract_domain_from_indicator(indicator_value: str, indicator_type: str) -> Optional[str]:
    """Extract clean domain name from indicator value."""
    val = indicator_value.strip().lower()
    if not val:
        return None
    if "://" in val:
        parsed = urlparse(val)
        val = parsed.hostname or val
    val = val.split("/")[0].split(":")[0].lstrip("*.")
    return val if "." in val else None


async def fetch_domain_general_info(domain: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """
    Fetch indicator summary metadata for a domain from AlienVault OTX.

    Queries https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general
    and caches the result per domain with TTL=86400 seconds (24 hours).

    Args:
        domain: Target domain to inspect.
        client: Optional existing httpx.AsyncClient instance.

    Returns:
        Dict containing pulse_count, first_seen, last_seen, or empty dict on error.
    """
    cache_key = f"garuda:otx:domain_general:{domain}"
    cached = await get_cached_json(cache_key)
    if cached is not None:
        return cached

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {}
    if settings.OTX_API_KEY:
        headers["X-OTX-API-KEY"] = settings.OTX_API_KEY

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        close_client = True

    try:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        general = data.get("general", {})
        result = {
            "pulse_count": general.get("pulse_info", {}).get("count", 0),
            "first_seen": general.get("first_seen"),
            "last_seen": general.get("last_seen"),
        }
        await set_cached_json(cache_key, result, ex=86400)
        return result
    except httpx.HTTPError as err:
        logger.error(f"[otx] HTTP error fetching general info for domain '{domain}': {err}")
        return {}
    except Exception as e:
        logger.error(f"[otx] Error parsing OTX domain general response for '{domain}': {e}")
        return {}
    finally:
        if close_client:
            await client.aclose()


async def fetch_apt36_iocs() -> List[Dict[str, Any]]:
    """
    Fetch and extract APT36, Transparent Tribe, and SideWinder pulse IOCs from AlienVault OTX.

    Queries subscribed pulses from AlienVault OTX, filters by actor tags, extracts
    indicators matching domain/hostname/URL types, and enriches them with general
    pulse metadata.

    Returns:
        List of dictionaries with keys:
            - domain (str): Target domain name.
            - source (str): Static string "otx".
            - pulse_id (str): Associated OTX pulse identifier.
            - pulse_name (str): Associated OTX pulse title.
    """
    cache_key = generate_cache_key("otx", "subscribed_apt36_pulses")
    cached = await get_cached_json(cache_key)
    if cached is not None:
        logger.debug("[otx] Returning cached OTX pulse IOCs")
        return cached

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"
    headers = {}
    if settings.OTX_API_KEY:
        headers["X-OTX-API-KEY"] = settings.OTX_API_KEY

    results: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            pulses = data.get("results", [])

            for pulse in pulses:
                if not isinstance(pulse, dict):
                    continue

                pulse_id = str(pulse.get("id", ""))
                pulse_name = str(pulse.get("name", ""))
                tags = [str(t).lower() for t in pulse.get("tags", [])]

                # Filter pulses where tags contain target actor tags
                matches_tag = any(
                    any(target_tag in t for target_tag in TARGET_TAG_KEYWORDS)
                    for t in tags
                ) or any(target_tag in pulse_name.lower() for target_tag in TARGET_TAG_KEYWORDS)

                if not matches_tag:
                    continue

                indicators = pulse.get("indicators", [])
                for ind in indicators:
                    if not isinstance(ind, dict):
                        continue

                    ind_type = str(ind.get("type", ""))
                    ind_val = str(ind.get("indicator", ""))

                    if ind_type in INDICATOR_TYPES:
                        domain = _extract_domain_from_indicator(ind_val, ind_type)
                        if domain:
                            results.append({
                                "domain": domain,
                                "source": "otx",
                                "pulse_id": pulse_id,
                                "pulse_name": pulse_name,
                            })

            # Cache the parsed results
            await set_cached_json(cache_key, results, ex=1800)
            return results
    except httpx.HTTPError as err:
        logger.error(f"[otx] HTTP error fetching OTX subscribed pulses: {err}")
        return []
    except Exception as e:
        logger.error(f"[otx] Unexpected error processing OTX feed: {e}")
        return []
