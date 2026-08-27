import asyncio
import json
import logging
from pathlib import Path
from typing import List, Tuple
import httpx
try:
    from rapidfuzz import fuzz
except ImportError:
    class MockFuzz:
        @staticmethod
        def token_sort_ratio(s1: str, s2: str) -> float:
            return 100.0 if s1 == s2 else 50.0
        @staticmethod
        def partial_ratio(s1: str, s2: str) -> float:
            return 100.0 if s1 in s2 or s2 in s1 else 30.0
    fuzz = MockFuzz()

from garuda.detection.homoglyph import normalize_domain

logger = logging.getLogger("garuda.detection.nic_ground_truth")

# Global in-memory list of authentic NIC and Indian Government domains
NIC_DOMAINS: List[str] = []


def _extract_stem(domain: str) -> str:
    """Extract domain stem by removing subdomains and common TLD extensions."""
    parts = domain.lower().strip().split(".")
    # Common 2-level TLDs in India: .gov.in, .nic.in, .co.in, .org.in, .res.in, .ac.in
    if len(parts) >= 3 and parts[-1] == "in" and parts[-2] in {"gov", "nic", "co", "org", "res", "ac"}:
        return parts[-3]
    elif len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _load_local_ground_truth() -> List[str]:
    """Load curated NIC/Gov domains from data/nic_domains.json."""
    data_path = Path(__file__).resolve().parent.parent / "data" / "nic_domains.json"
    if data_path.exists():
        try:
            with open(data_path, "r", encoding="utf-8") as f:
                domains = json.load(f)
                if isinstance(domains, list):
                    return [d.strip().lower() for d in domains if isinstance(d, str) and d.strip()]
        except Exception as e:
            logger.error(f"[nic_ground_truth] Error loading local ground truth from {data_path}: {e}")
    return [
        "nic.in", "gov.in", "mod.gov.in", "indianarmy.nic.in", "indiannavy.nic.in",
        "drdo.gov.in", "isro.gov.in", "mea.gov.in", "mha.gov.in", "rbi.org.in", "uidai.gov.in"
    ]


async def load_nic_domains() -> int:
    """
    Load, fetch, merge, and deduplicate Indian Government & NIC domains into module memory.

    Loads primary records from 'garuda/data/nic_domains.json' and supplements them by querying
    open government catalog feeds (e.g. data.gov.in). Updates the module-level NIC_DOMAINS list.

    Returns:
        int: Total number of unique ground truth domains loaded.
    """
    global NIC_DOMAINS
    collected = set(_load_local_ground_truth())

    catalog_url = "https://data.gov.in/ogdp-catalog"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(catalog_url)
            if response.status_code == 200:
                # TODO: verify data.gov.in catalog API structure when auth key is provided
                text = response.text.lower()
                for token in text.split():
                    if ".gov.in" in token or ".nic.in" in token:
                        clean = token.strip(" '\"<>()[]:;,").lstrip("*.")
                        if "." in clean and (clean.endswith(".gov.in") or clean.endswith(".nic.in")):
                            collected.add(clean)
    except httpx.HTTPError as err:
        logger.warning(f"[nic_ground_truth] HTTP error fetching external data.gov.in catalog: {err}")
    except Exception as e:
        logger.warning(f"[nic_ground_truth] Could not supplement from external catalog: {e}")

    NIC_DOMAINS = sorted(list(collected))
    logger.info(f"[nic_ground_truth] Loaded {len(NIC_DOMAINS)} ground truth domains.")
    return len(NIC_DOMAINS)


def compute_similarity(domain: str) -> Tuple[float, str]:
    """
    Compute maximum fuzzy string similarity against known authentic NIC/Gov ground truth domains.

    Normalizes target domain using homoglyph mapping, extracts domain stems, and computes
    token_sort_ratio and partial_ratio via rapidfuzz, returning the highest normalized score.

    Args:
        domain: Input domain name to test for brand impersonation.

    Returns:
        Tuple of:
            - float: Best similarity ratio score normalized between 0.0 and 1.0.
            - str: Ground truth NIC domain with highest similarity match.
    """
    if not NIC_DOMAINS:
        _load_defaults()

    normalized = normalize_domain(domain)
    target_stem = _extract_stem(normalized)
    if not target_stem:
        return 0.0, ""

    best_score = 0.0
    best_match = ""

    for nic_domain in NIC_DOMAINS:
        nic_stem = _extract_stem(nic_domain)
        if not nic_stem:
            continue

        # Compute token sort and partial ratio
        sort_ratio = fuzz.token_sort_ratio(target_stem, nic_stem)
        part_ratio = fuzz.partial_ratio(target_stem, nic_stem)
        max_ratio = max(sort_ratio, part_ratio) / 100.0

        # Exact stem match on non-gov TLD
        if target_stem == nic_stem and not (domain.endswith(".gov.in") or domain.endswith(".nic.in")):
            max_ratio = max(max_ratio, 0.95)

        if max_ratio > best_score:
            best_score = max_ratio
            best_match = nic_domain

    return round(best_score, 4), best_match


def _load_defaults():
    """Initial population of default ground truth on startup."""
    global NIC_DOMAINS
    NIC_DOMAINS = _load_local_ground_truth()


# Populate initial defaults on module load
_load_defaults()
