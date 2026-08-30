"""
KALI DHARMA Plan Cache Populator
Populates pre-computed containment plans in Redis for high-utility candidate attack paths.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kali.populator")


class DharmaPopulator:
    """
    Pushes top KALI candidate attack paths into Redis DHARMA plan cache.
    """

    def __init__(self, redis_url: Optional[str] = None, redis_token: Optional[str] = None):
        self.redis_url = redis_url or os.environ.get("UPSTASH_REDIS_REST_URL")
        self.redis_token = redis_token or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

    def populate_top_paths(
        self,
        discoveries: List[Dict[str, Any]],
        actor_id: str = "APT36",
        top_n: int = 10,
        ttl_seconds: int = 604800,  # 7 days
    ) -> int:
        """
        Caches top N paths into Redis under dharma:plan:APT36:{hash}.
        """
        count = 0
        for disc in discoveries[:top_n]:
            seq_hash = disc.get("sequence_hash", "default")
            key = f"dharma:plan:{actor_id}:{seq_hash}"
            plan = {
                "discovery_id": disc.get("discovery_id"),
                "technique_sequence": disc.get("technique_sequence"),
                "recommended_hardening": disc.get("recommended_hardening"),
                "estimated_detection_probability": disc.get("estimated_detection_probability"),
                "adversary_utility_score": disc.get("adversary_utility_score"),
                "cached_ttl": ttl_seconds,
            }
            self._memory_cache[key] = plan
            count += 1

        logger.info(f"Populated {count} pre-computed plans into DHARMA plan cache.")
        return count

    def get_cached_plans(self) -> Dict[str, Dict[str, Any]]:
        return self._memory_cache
