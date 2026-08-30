"""
Groq & Gemini Rate Limiter & Budget Tracker
Tracks daily and hourly token/request consumption across UTNE, MAYA, and KALI.
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("network.utne.limiter")

# Default daily allocations
BUDGET_LIMITS: Dict[str, int] = {
    "utne_sitrep": 24,       # 24 sitreps / day (hourly)
    "utne_qa": 50,           # 50 operator Q&A / day
    "maya_doc": 20,          # 20 ghost documents / day
    "kali_batch": 1000,      # 1000 requests on Sunday batch
}


def _get_current_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class BudgetLimiter:
    """
    Tracks and enforces API quotas using Upstash Redis or local memory counter.
    """

    def __init__(self, redis_url: Optional[str] = None, redis_token: Optional[str] = None):
        self.redis_url = redis_url or os.environ.get("UPSTASH_REDIS_REST_URL")
        self.redis_token = redis_token or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        self._memory_counts: Dict[str, int] = {}

    def check_and_increment(self, purpose: str) -> Tuple[bool, int, int]:
        """
        Checks if the request is within daily budget.
        Returns: (is_allowed, current_count, max_limit)
        """
        limit = BUDGET_LIMITS.get(purpose, 50)
        day_str = _get_current_day()
        key = f"groq:daily:{day_str}:{purpose}"

        current_count = self._memory_counts.get(key, 0)
        if current_count >= limit:
            logger.warning(f"Daily budget exceeded for {purpose} ({current_count}/{limit}).")
            return (False, current_count, limit)

        self._memory_counts[key] = current_count + 1
        return (True, current_count + 1, limit)

    def get_status(self) -> Dict[str, Any]:
        """Returns current daily usage summary."""
        day_str = _get_current_day()
        status = {}
        for purpose, limit in BUDGET_LIMITS.items():
            key = f"groq:daily:{day_str}:{purpose}"
            status[purpose] = {
                "used": self._memory_counts.get(key, 0),
                "limit": limit,
                "remaining": max(0, limit - self._memory_counts.get(key, 0)),
            }
        return status
