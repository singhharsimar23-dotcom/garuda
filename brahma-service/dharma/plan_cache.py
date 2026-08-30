"""
Upstash Redis Plan Cache & State Manager
Caches pre-computed containment plans, pending Tier 1 authorizations, and intensification timers.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("brahma.dharma.cache")


class PlanCache:
    """
    Manages in-memory and Redis-backed containment plan caching and pending authorization queues.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        redis_token: Optional[str] = None,
    ):
        self.redis_url = redis_url or os.environ.get("UPSTASH_REDIS_REST_URL")
        self.redis_token = redis_token or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        # In-memory fallback dictionary with TTL tracking
        self._memory_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}

    def set_plan(self, key: str, value: Dict[str, Any], ttl_seconds: int = 900) -> bool:
        """Sets a key-value record with TTL."""
        expiry = time.time() + ttl_seconds
        self._memory_cache[key] = (value, expiry)

        if not self.redis_url or not self.redis_token:
            return True

        try:
            # If using Upstash REST API
            import urllib.request
            url = f"{self.redis_url.rstrip('/')}/setex/{key}/{ttl_seconds}"
            data = json.dumps(value).encode("utf-8")
            headers = {"Authorization": f"Bearer {self.redis_token}"}
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            logger.debug(f"Redis cache set failed: {e}")
            return True

    def get_plan(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieves a cached plan if not expired."""
        if key in self._memory_cache:
            val, expiry = self._memory_cache[key]
            if time.time() <= expiry:
                return val
            else:
                del self._memory_cache[key]

        if not self.redis_url or not self.redis_token:
            return None

        try:
            import urllib.request
            url = f"{self.redis_url.rstrip('/')}/get/{key}"
            headers = {"Authorization": f"Bearer {self.redis_token}"}
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if 200 <= resp.status < 300:
                    data = json.loads(resp.read().decode("utf-8"))
                    res_str = data.get("result")
                    if res_str:
                        return json.loads(res_str)
        except Exception as e:
            logger.debug(f"Redis cache get failed: {e}")

        return None

    def delete_plan(self, key: str) -> bool:
        """Removes a key from cache."""
        if key in self._memory_cache:
            del self._memory_cache[key]
        return True

    def get_all_pending_actions(self) -> List[Dict[str, Any]]:
        """Lists all active non-expired pending actions."""
        pending = []
        now = time.time()
        for k, (val, exp) in list(self._memory_cache.items()):
            if k.startswith("dharma:pending:") and now <= exp:
                pending.append(val)
        return pending
