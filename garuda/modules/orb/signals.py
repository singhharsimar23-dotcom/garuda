"""
ORB signal scoring — probability-based, not definitive attribution.

What we CAN observe externally: device fingerprint, CVE exposure, BGP path
anomalies, IOC feed presence. What we CANNOT: which APT controls the node.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from garuda.modules.easm.constants import INDIAN_DEFENCE_ASN_NUMBERS
from garuda.modules.bgp.ripe_stat import get_announced_prefixes

# Source: Black Lotus Labs KV-botnet research (public, December 2023)
SOHO_KEYWORDS = [
    "cisco rv", "draytek", "netgear prosafe", "mikrotik",
    "tp-link", "asus rt", "zyxel", "d-link", "fortinet soho",
]

# Chinese/HK transit ASNs used as ORB anchor/egress points
# VERIFY each against current RIPE ASN records before production use
ANCHOR_CHINESE_ASNS = [
    37963,  # Alibaba Cloud (Hangzhou)
    45090,  # Tencent Cloud
    4134,   # China Telecom (ChinaNet)
    9269,   # HKT Limited (Hong Kong)
    3491,   # PCCW Global (Hong Kong)
    4837,   # China Unicom
]

ORB_SUSPECT_PORTS = {8443, 4443, 9443, 7443}

# Cached defence prefix ranges for targeting check (populated lazily)
_defence_prefixes_cache: Optional[list] = None


def _product_matches_soho(internetdb_data: dict) -> bool:
    """Check if InternetDB/Shodan product data matches SOHO keywords."""
    cpes = internetdb_data.get("cpes") or []
    for cpe in cpes:
        cpe_lower = cpe.lower()
        if any(kw in cpe_lower for kw in SOHO_KEYWORDS):
            return True
    product = (internetdb_data.get("product") or "").lower()
    return any(kw in product for kw in SOHO_KEYWORDS)


def _ports_include_orb_suspect(internetdb_data: dict) -> bool:
    ports = set(internetdb_data.get("ports") or [])
    return bool(ports & ORB_SUSPECT_PORTS)


def _ip_in_defence_prefixes(ip: str, defence_prefixes: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for prefix in defence_prefixes:
            if addr in ipaddress.ip_network(prefix, strict=False):
                return True
    except ValueError:
        pass
    return False


async def get_defence_prefixes_cached() -> list[str]:
    """Load and cache Indian defence BGP prefixes for targeting checks."""
    global _defence_prefixes_cache
    if _defence_prefixes_cache is not None:
        return _defence_prefixes_cache

    prefixes: list[str] = []
    for asn in INDIAN_DEFENCE_ASN_NUMBERS:
        try:
            prefixes.extend(await get_announced_prefixes(asn))
        except Exception:
            continue
    _defence_prefixes_cache = prefixes
    return prefixes


def score_orb_probability(
    ip: str,
    internetdb_data: dict,
    bgp_path_asns: list[int],
    is_in_otx_iocs: bool,
    kev_cves: Optional[set[str]] = None,
    defence_prefixes: Optional[list[str]] = None,
) -> tuple[int, list[str], bool]:
    """
    Score probability that an IP is an ORB relay node.
    Returns (score, triggered_signals, targeting_indian_defence)

    Threshold 60+: flag as probable ORB node
    Threshold 80+: CRITICAL alert (if also targeting_indian_defence)
    """
    triggered: list[str] = []
    score = 0
    kev_cves = kev_cves or set()

    soho_match = _product_matches_soho(internetdb_data)
    orb_port = _ports_include_orb_suspect(internetdb_data)
    if soho_match and orb_port:
        score += 25
        triggered.append("soho_device_with_suspect_port")

    vulns = set(internetdb_data.get("vulns") or [])
    kev_hits = vulns & kev_cves
    if kev_hits:
        score += 20
        triggered.append(f"kev_cve_exposure:{','.join(sorted(kev_hits))}")

    anchor_hits = [a for a in bgp_path_asns if a in ANCHOR_CHINESE_ASNS]
    if anchor_hits:
        score += 35
        triggered.append(f"chinese_anchor_asn:{','.join(str(a) for a in anchor_hits)}")

    targeting = False
    if defence_prefixes and _ip_in_defence_prefixes(ip, defence_prefixes):
        score += 30
        targeting = True
        triggered.append("targeting_indian_defence_prefix")

    if is_in_otx_iocs:
        score += 20
        triggered.append("otx_apt_ioc_match")

    return score, triggered, targeting


def confidence_label_from_score(score: int) -> str:
    """Map score to confidence label."""
    if score >= 80:
        return "CONFIRMED_ORB"
    if score >= 60:
        return "PROBABLE_ORB"
    return "BELOW_THRESHOLD"
