"""
GARUDA Honeypot Self-Detection Guard (FIX-01)

Prevents GARUDA's own registered honeypot domains from being scored,
alerted, blocked via RPZ, or flagged in passive DNS.

Usage:
    from garuda.utils.honeypot_guard import is_own_honeypot

    if is_own_honeypot(domain):
        logger.info("Skipping own honeypot: %s", domain)
        return
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger("garuda.utils.honeypot_guard")


@lru_cache(maxsize=1)
def get_honeypot_domains() -> frozenset:
    """
    Load honeypot domain whitelist from garuda/data/honeypot_domains.json.
    LRU-cached — reads file once per process lifetime.
    """
    path = Path(__file__).parent.parent / "data" / "honeypot_domains.json"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        domains = frozenset(d.lower().strip() for d in data.get("honeypot_domains", []))
        logger.info("[honeypot_guard] Loaded %d honeypot domains", len(domains))
        return domains
    except Exception as exc:
        logger.error("[honeypot_guard] Failed to load honeypot_domains.json: %s", exc)
        return frozenset()


def is_own_honeypot(domain: str) -> bool:
    """
    Returns True if domain is a GARUDA-registered honeypot lure.

    Must be checked BEFORE:
      - Inserting into alerts table
      - Adding to rpz_entries (DNS sinkhole blocklist)
      - Flagging in passive_dns_observations
      - Scoring in the threat scoring pipeline

    Case-insensitive. Strips whitespace.
    """
    if not domain:
        return False
    return domain.lower().strip() in get_honeypot_domains()
