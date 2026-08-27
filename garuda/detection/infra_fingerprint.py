import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

from garuda.cache import (
    generate_cache_key,
    get_cached_json,
    set_cached_json,
)
from garuda.config import settings

logger = logging.getLogger("garuda.detection.infra_fingerprint")

APT36_KNOWN_REGISTRARS = {
    "namecheap": 25.0,
    "pdr ltd": 10.0,
    "publicdomainregistry": 10.0,
    "enom": 10.0,
    "epik": 10.0,
}


async def fetch_whois_record(domain: str) -> Dict[str, Any]:
    """
    Retrieve WHOIS metadata for a target domain via WhoisXML API.

    Queries https://www.whoisxmlapi.com/whoisserver/WhoisService and caches results
    in Redis for 24 hours.

    Args:
        domain: Domain name to look up.

    Returns:
        Dict[str, Any]: Parsed WHOIS record or empty dict on failure.
    """
    if not domain or not settings.WHOISXML_API_KEY:
        return {}

    clean_domain = domain.strip().lower().lstrip("*.")
    cache_key = f"garuda:whois:{clean_domain}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, dict):
        return cached

    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "apiKey": settings.WHOISXML_API_KEY,
        "domainName": clean_domain,
        "outputFormat": "JSON",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                whois_rec = data.get("WhoisRecord", {})
                parsed = {
                    "domain": clean_domain,
                    "registrar": whois_rec.get("registrarName") or whois_rec.get("registrar"),
                    "created_date": whois_rec.get("createdDate") or whois_rec.get("registryData", {}).get("createdDate"),
                    "expires_date": whois_rec.get("expiresDate"),
                    "raw_text": whois_rec.get("rawText"),
                }
                await set_cached_json(cache_key, parsed, ex=86400)
                return parsed
            else:
                logger.warning(f"[infra_fingerprint] WhoisXML API returned status {response.status_code} for {clean_domain}")
                return {}
    except Exception as e:
        logger.error(f"[infra_fingerprint] Error querying WhoisXML API for {clean_domain}: {e}")
        return {}


async def check_registrar_fingerprint(domain: str, whois_data: Dict[str, Any]) -> Tuple[bool, float]:
    """
    Evaluate registrar against known APT36 / Transparent Tribe infrastructure preferences.

    Checks WHOIS registrar field against high-frequency threat actor registrars
    (Namecheap yields +25 score, PDR Ltd / eNom / Epik yield +10 score).

    Args:
        domain: Domain name being analyzed.
        whois_data: Parsed WHOIS dictionary.

    Returns:
        Tuple of:
            - bool: True if registrar matches known APT36 registrar profile, False otherwise.
            - float: Score contribution from registrar fingerprint (0.0, 10.0, or 25.0).
    """
    if not whois_data:
        return False, 0.0

    raw_registrar = str(whois_data.get("registrar") or whois_data.get("registrar_name") or "")
    registrar_lower = raw_registrar.lower().strip()

    if not registrar_lower:
        return False, 0.0

    if "namecheap" in registrar_lower:
        return True, 25.0

    for reg_key, score_weight in APT36_KNOWN_REGISTRARS.items():
        if reg_key in registrar_lower:
            return True, score_weight

    return False, 0.0


async def check_hosting_asn(ip: str) -> Tuple[bool, int]:
    """
    Query IP geolocation/ASN data and detect if hosting ASN matches APT36 hosting infrastructure.

    Queries http://ip-api.com/json/{ip}?fields=as,org,country, extracts ASN number, and compares
    against settings.APT36_HOSTING_ASNS (OVH, Hetzner, Linode, DigitalOcean, Vultr).
    Results are cached in Redis with TTL=86400 seconds.

    Args:
        ip: Target IPv4 address.

    Returns:
        Tuple of:
            - bool: True if hosted on known APT36 infrastructure ASN, False otherwise.
            - int: Extracted ASN integer (e.g. 16276) or 0 if unresolvable.
    """
    if not ip or ip in {"127.0.0.1", "0.0.0.0", "localhost"}:
        return False, 0

    cache_key = f"garuda:asn:{ip}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, dict):
        return cached.get("is_apt36", False), cached.get("asn", 0)

    url = f"http://ip-api.com/json/{ip}?fields=as,org,country"
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            as_field = data.get("as", "")
            asn_int = 0

            # Parse "AS16276 OVH SAS" -> 16276
            match = re.search(r"AS(\d+)", as_field, re.IGNORECASE)
            if match:
                asn_int = int(match.group(1))

            is_apt36_asn = asn_int in settings.APT36_HOSTING_ASNS

            result_payload = {"is_apt36": is_apt36_asn, "asn": asn_int}
            await set_cached_json(cache_key, result_payload, ex=86400)
            return is_apt36_asn, asn_int
    except httpx.HTTPError as err:
        logger.error(f"[infra_fingerprint] HTTP error querying ASN for IP '{ip}': {err}")
        return False, 0
    except Exception as e:
        logger.error(f"[infra_fingerprint] Error parsing ASN for IP '{ip}': {e}")
        return False, 0


async def check_c2_ports(ip: str) -> List[int]:
    """
    Query Shodan for open ports on an IP address and detect known APT36 C2 listening ports.

    Queries https://api.shodan.io/shodan/host/{ip} using SHODAN_API_KEY and filters open ports
    against settings.APT36_C2_PORTS ([4000, 8443, 9001]).

    Args:
        ip: Target IPv4 address.

    Returns:
        List[int]: List of matching open C2 ports observed on target host.
    """
    if not ip or not settings.SHODAN_API_KEY:
        return []

    cache_key = f"garuda:shodan:ports:{ip}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, list):
        return cached

    url = f"https://api.shodan.io/shodan/host/{ip}?key={settings.SHODAN_API_KEY}"
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 404:
                # Host not indexed in Shodan
                await set_cached_json(cache_key, [], ex=86400)
                return []

            response.raise_for_status()
            data = response.json()
            open_ports = data.get("ports", [])

            # Filter against APT36 C2 ports
            matching_c2_ports = [
                p for p in open_ports if isinstance(p, int) and p in settings.APT36_C2_PORTS
            ]

            await set_cached_json(cache_key, matching_c2_ports, ex=86400)
            return matching_c2_ports
    except httpx.HTTPError as err:
        logger.error(f"[infra_fingerprint] HTTP error querying Shodan for IP '{ip}': {err}")
        return []
    except Exception as e:
        logger.error(f"[infra_fingerprint] Error querying Shodan for IP '{ip}': {e}")
        return []


async def check_virustotal_reputation(domain: str) -> Dict[str, Any]:
    """
    Query VirusTotal v3 API for community threat verdict, malicious votes, and categories.

    Queries https://www.virustotal.com/api/v3/domains/{domain} and caches results
    in Redis for 24 hours.

    Args:
        domain: Domain name to inspect.

    Returns:
        Dict[str, Any]: Verdict dictionary with 'malicious_count', 'suspicious_count', 'reputation'.
    """
    if not domain or not settings.VIRUSTOTAL_API_KEY:
        return {}

    clean_domain = domain.strip().lower().lstrip("*.")
    cache_key = f"garuda:vt:{clean_domain}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, dict):
        return cached

    url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                verdict = {
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                }
                await set_cached_json(cache_key, verdict, ex=86400)
                return verdict
            elif response.status_code == 404:
                # Domain unobserved in VT database
                res_empty = {"malicious_count": 0, "suspicious_count": 0, "harmless_count": 0, "reputation": 0}
                await set_cached_json(cache_key, res_empty, ex=86400)
                return res_empty
            else:
                logger.warning(f"[infra_fingerprint] VirusTotal API returned status {response.status_code} for {clean_domain}")
                return {}
    except Exception as e:
        logger.error(f"[infra_fingerprint] Error querying VirusTotal API for {clean_domain}: {e}")
        return {}

