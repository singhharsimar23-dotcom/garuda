import asyncio
from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, Optional
import feedparser

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


async def compute_tension_index(window_days: int = 7) -> float:
    """
    Compute real-time Indo-Pak geopolitical tension score using multi-feed RSS keyword velocity.

    Parses national and diplomatic news releases (MEA, NDTV) using feedparser in an async thread pool.
    Applies exponential recency decay weights and severity multipliers across military, territorial,
    and cyber escalation keywords.

    Persists result to the 'tension_log' Supabase table and dynamically updates CONFLICT_MODE.

    Args:
        window_days: Lookback window in days (default: 7).

    Returns:
        float: Normalized tension index score between 0.0 and 1.0.
    """
    cache_key = f"garuda:intelligence:tension_index_{window_days}d"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, (int, float)):
        return float(cached)

    loop = asyncio.get_running_loop()
    all_entries: list[Any] = []

    # Fetch and parse RSS feeds concurrently in executor
    for source_name, feed_url in RSS_FEEDS.items():
        try:
            feed_obj = await loop.run_in_executor(None, feedparser.parse, feed_url)
            if hasattr(feed_obj, "entries"):
                all_entries.extend(feed_obj.entries)
        except Exception as e:
            logger.warning(f"[tension_index] Failed parsing RSS feed '{source_name}': {e}")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)

    total_weighted_score = 0.0
    matching_articles_count = 0

    for entry in all_entries:
        published_dt = _parse_entry_datetime(entry)
        if published_dt < cutoff:
            continue

        title = str(getattr(entry, "title", "")).lower()
        summary = str(getattr(entry, "summary", "")).lower()
        combined_text = f"{title} {summary}"

        # Calculate time-decay weight (1.0 for today -> 0.2 for window_days ago)
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

    # Base baseline is 0.40; escalation pushes towards 1.0
    if matching_articles_count == 0:
        tension_index = 0.45
    else:
        # Logistic / asymptotic scaling
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

    # Cache for 15 minutes
    await set_cached_json(cache_key, tension_index, ex=900)
    logger.info(f"[tension_index] Computed tension index: {tension_index} (Conflict Mode: {conflict_mode})")
    return tension_index


async def fetch_tension_index() -> float:
    """Wrapper function returning the current geopolitical tension index."""
    return await compute_tension_index(window_days=7)
