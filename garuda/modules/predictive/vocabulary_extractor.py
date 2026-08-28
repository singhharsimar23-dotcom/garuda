"""
ISPR narrative vocabulary extraction for APT36 domain prediction.

Two free sources: ISPR RSS feed (primary) and GDELT Doc API (fallback).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List

import feedparser
import httpx

logger = logging.getLogger("garuda.modules.predictive.vocabulary_extractor")

ISPR_RSS_URL = "http://ispr.gov.pk/feed/"
GDELT_DOC_BASE = "https://api.gdeltproject.org/api/v2/doc/doc"

# Narrative terms commonly appearing in ISPR releases → likely APT36 spoof targets.
NARRATIVE_KEYWORD_MAP: dict[str, list[str]] = {
    "army": ["indianarmy", "modgov", "crpf-gov", "indianairforce"],
    "crpf": ["crpf-gov", "modgov", "indianarmy"],
    "pahalgam": ["modgov", "indianarmy", "crpf-gov", "mha-gov"],
    "kashmir": ["modgov", "indianarmy", "crpf-gov", "bsf-gov"],
    "loc": ["indianarmy", "bsf-gov", "crpf-gov"],
    "mod": ["modgov", "modindia", "mod-india", "defenceindia"],
    "defence": ["modgov", "defenceindia", "drdo", "raksha"],
    "security": ["modgov", "cert-in", "crpf-gov", "mha-gov"],
    "drdo": ["drdo", "drdoin", "drdogov"],
    "isro": ["isro", "isroin", "isrogov"],
    "navy": ["indiannavy", "modgov"],
    "air force": ["indianairforce", "iaf-gov", "iafgov"],
    "iaf": ["indianairforce", "iaf-gov", "iafgov"],
    "terror": ["modgov", "mha-gov", "cert-in"],
    "infiltration": ["indianarmy", "bsf-gov", "crpf-gov"],
    "operation": ["modgov", "indianarmy", "crpf-gov"],
    "border": ["bsf-gov", "indianarmy", "itbp-gov"],
    "ceasefire": ["indianarmy", "modgov"],
    "missile": ["drdo", "modgov"],
    "nuclear": ["npcil", "drdo", "barc-gov"],
}


def _tokenize_narrative(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


async def _fetch_ispr_rss(hours_back: int) -> list[str]:
    """Parse ISPR press-release RSS feed titles and summaries."""
    loop = asyncio.get_running_loop()
    try:
        feed = await loop.run_in_executor(None, feedparser.parse, ISPR_RSS_URL)
    except Exception as exc:
        logger.warning("[vocabulary_extractor] ISPR RSS parse failed: %s", exc)
        return []

    if not getattr(feed, "entries", None):
        return []

    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    snippets: list[str] = []

    for entry in feed.entries:
        published = getattr(entry, "published_parsed", None)
        if published:
            try:
                entry_dt = datetime(*published[:6], tzinfo=timezone.utc)
                if entry_dt < cutoff:
                    continue
            except Exception:
                pass

        title = str(getattr(entry, "title", "")).strip()
        summary = str(getattr(entry, "summary", "")).strip()
        if title:
            snippets.append(title)
        if summary:
            snippets.append(summary)

    return snippets


async def _fetch_gdelt_ispr(hours_back: int) -> list[str]:
    """GDELT fallback when ISPR RSS is unavailable."""
    params = {
        "query": "ISPR pakistan military statement",
        "mode": "artlist",
        "format": "json",
        "maxrecords": "20",
        "timespan": f"{hours_back}H",
    }
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            res = await client.get(GDELT_DOC_BASE, params=params)
            if res.status_code != 200:
                return []
            data = res.json()
    except Exception as exc:
        logger.warning("[vocabulary_extractor] GDELT fallback failed: %s", exc)
        return []

    articles = data.get("articles") or data.get("data") or []
    return [
        str(item.get("title", "")).strip()
        for item in articles
        if isinstance(item, dict) and item.get("title")
    ]


async def get_ispr_narrative(hours_back: int = 72) -> list[str]:
    """
    Fetch ISPR recent article titles and summaries.

    Primary: http://ispr.gov.pk/feed/
    Fallback: GDELT Doc API when RSS is down or empty.
    """
    snippets = await _fetch_ispr_rss(hours_back)
    if snippets:
        logger.info("[vocabulary_extractor] ISPR RSS returned %d snippets", len(snippets))
        return snippets

    logger.info("[vocabulary_extractor] ISPR RSS empty — using GDELT fallback")
    gdelt = await _fetch_gdelt_ispr(hours_back)
    return gdelt


async def extract_target_keywords_from_narrative(
    narrative_text: list[str],
    tier1_patterns: list[str],
) -> list[str]:
    """
    Map narrative vocabulary to GARUDA TIER_1 patterns APT36 would spoof.

    Pure string matching — no LLM.
    """
    if not narrative_text:
        return []

    combined = _tokenize_narrative(" ".join(narrative_text))
    matched: set[str] = set()

    tier1_lower = [p.lower() for p in tier1_patterns]

    # Direct tier-1 substring hits in narrative text.
    for pattern in tier1_lower:
        stem = pattern.replace("-", "").replace("_", "")
        if pattern in combined or stem in combined.replace("-", ""):
            matched.add(pattern)

    # Narrative keyword → tier-1 mapping.
    for narrative_kw, targets in NARRATIVE_KEYWORD_MAP.items():
        if narrative_kw in combined:
            for target in targets:
                if target in tier1_lower:
                    matched.add(target)

    # Partial stem overlap (e.g. "army" in "indianarmy").
    for pattern in tier1_lower:
        stem = pattern.replace("-", "")
        if len(stem) >= 4 and stem in combined.replace("-", "").replace(" ", ""):
            matched.add(pattern)

    return sorted(matched)
