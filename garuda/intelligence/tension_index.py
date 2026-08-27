import asyncio
from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
import feedparser
import httpx

from garuda.cache import get_cached_json, set_cached_json
from garuda.config import settings
from garuda.database import get_supabase_client

logger = logging.getLogger("garuda.intelligence.tension_index")

RSS_FEEDS = {
    "ndtv": "https://feeds.feedburner.com/ndtvnews-india-news",
    "mea": "https://mea.gov.in/rss/latest-releases.htm",
    "pakistan_today": "https://www.pakistantoday.com.pk/category/national/feed/",
    "geo_tv": "https://www.geo.tv/rss/1/1",
}

GDELT_DOC_API_URL = "https://api.gdeltproject.org/api/v2/doc/doc?query=(pakistan+OR+kashmir+OR+loc+OR+drdo+OR+iaf)&mode=artlist&format=json&maxrecords=100"

# Geopolitical Conflict & Tension Keywords and Severity Multipliers
TENSION_KEYWORDS: Dict[str, float] = {
    "loc ceasefire violation": 0.95,
    "line of control": 0.85,
    "cross-border firing": 0.85,
    "infiltration bid": 0.80,
    "terror attack": 0.85,
    "surgical strike": 0.95,
    "balakot": 0.90,
    "abrogation": 0.80,
    "drone attack": 0.85,
    "military standoff": 0.80,
    "isi": 0.75,
    "jaish": 0.80,
    "lashkar": 0.80,
    "transparent tribe": 0.90,
    "apt36": 0.90,
    "sidewinder": 0.85,
    "cyber espionage": 0.80,
    "malware attack": 0.75,
    "defence alert": 0.80,
    "iaf scrambled": 0.90,
}


def _parse_entry_datetime(entry: Any) -> datetime:
    """Convert feedparser published_parsed struct_time to aware datetime object."""
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            return datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


async def _fetch_gdelt_articles() -> List[Dict[str, Any]]:
    """Fetch recent Indo-Pak military/geopolitical articles from GDELT 2.0 Doc API (No auth required)."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            res = await client.get(GDELT_DOC_API_URL)
            if res.status_code == 200:
                data = res.json()
                return data.get("articles", [])
    except Exception as e:
        logger.debug(f"[tension_index] GDELT Doc API note: {e}")
    return []


async def compute_tension_index(window_days: int = 7) -> float:
    """
    Compute real-time Indo-Pak geopolitical tension score using GDELT 2.0 and multi-feed RSS keyword velocity.
    """
    cache_key = f"garuda:intelligence:tension_index_{window_days}d"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, (int, float)):
        return float(cached)

    loop = asyncio.get_running_loop()
    all_entries: list[Any] = []

    # 1. Fetch RSS feeds
    for source_name, feed_url in RSS_FEEDS.items():
        try:
            feed_obj = await loop.run_in_executor(None, feedparser.parse, feed_url)
            if hasattr(feed_obj, "entries"):
                all_entries.extend(feed_obj.entries)
        except Exception as e:
            logger.warning(f"[tension_index] Failed parsing RSS feed '{source_name}': {e}")

    # 2. Fetch GDELT 2.0 articles
    gdelt_articles = await _fetch_gdelt_articles()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)

    total_weighted_score = 0.0
    matching_articles_count = 0

    # Process RSS
    for entry in all_entries:
        published_dt = _parse_entry_datetime(entry)
        if published_dt < cutoff:
            continue

        title = str(getattr(entry, "title", "")).lower()
        summary = str(getattr(entry, "summary", "")).lower()
        combined_text = f"{title} {summary}"

        age_days = max(0.0, (now - published_dt).total_seconds() / 86400.0)
        age_weight = max(0.2, 1.0 - (age_days / float(window_days)) * 0.8)

        article_max_score = 0.0
        for kw, weight in TENSION_KEYWORDS.items():
            if kw in combined_text:
                if weight > article_max_score:
                    article_max_score = weight

        if article_max_score > 0:
            total_weighted_score += article_max_score * age_weight
            matching_articles_count += 1

    # Process GDELT articles
    for g_art in gdelt_articles:
        title = str(g_art.get("title", "")).lower()
        for kw, weight in TENSION_KEYWORDS.items():
            if kw in title:
                total_weighted_score += weight * 0.8
                matching_articles_count += 1
                break

    if matching_articles_count == 0:
        tension_index = 0.45
    else:
        scaled = 0.45 + (total_weighted_score / (total_weighted_score + 5.0)) * 0.55
        tension_index = round(min(1.0, max(0.0, scaled)), 3)

    conflict_mode = tension_index >= settings.TENSION_THRESHOLD
    settings.CONFLICT_MODE = conflict_mode

    # Persist to Supabase
    client = get_supabase_client()
    if client:
        try:
            client.table("tension_log").insert({
                "tension_index": tension_index,
                "conflict_mode": conflict_mode,
                "computed_at": now.isoformat(),
            }).execute()
        except Exception as e:
            logger.warning(f"[tension_index] Failed logging tension score to Supabase: {e}")

    await set_cached_json(cache_key, tension_index, ex=900)
    logger.info(f"[tension_index] Computed tension index: {tension_index} (Conflict Mode: {conflict_mode})")
    return tension_index


async def fetch_tension_index() -> float:
    """Wrapper function returning the current geopolitical tension index."""
    return await compute_tension_index(window_days=7)
