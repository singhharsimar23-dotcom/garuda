"""
Redis SLA Countdown & Escalation Manager
Manages Upstash Redis TTL countdowns (15 min for Tier 1, 5 min for Tier 3) with auto-escalation hooks.
"""

from datetime import datetime, timezone
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("brahma.dharma.redis_sla")


class RedisSLAManager:
    """
    Manages action SLA TTL timers via Upstash Redis REST API or in-memory fallback.
    """

    def __init__(
        self,
        rest_url: Optional[str] = None,
        rest_token: Optional[str] = None,
    ):
        self.rest_url = (rest_url or os.environ.get("UPSTASH_REDIS_REST_URL", "")).rstrip("/")
        self.rest_token = rest_token or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        self._local_sla_store: Dict[str, Dict[str, Any]] = {}

    def _has_remote_redis(self) -> bool:
        return bool(self.rest_url and self.rest_token)

    async def queue_action_sla(
        self,
        action_id: str,
        action_payload: Dict[str, Any],
        ttl_seconds: int = 900,  # 15 minutes default
    ) -> bool:
        """
        Record pending action with expiration TTL in Redis.
        """
        key = f"dharma_sla:{action_id}"
        payload_str = json.dumps(action_payload)
        now = time.time()

        # In-memory store
        self._local_sla_store[action_id] = {
            "payload": action_payload,
            "expires_at": now + ttl_seconds,
            "ttl_seconds": ttl_seconds,
        }

        if not self._has_remote_redis():
            logger.info(f"Queued SLA for action {action_id} locally (TTL: {ttl_seconds}s).")
            return True

        try:
            url = f"{self.rest_url}/set/{key}"
            headers = {"Authorization": f"Bearer {self.rest_token}"}
            # Upstash REST API: POST /set/key/val?ex=900
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(
                    f"{self.rest_url}/set/{key}?ex={ttl_seconds}",
                    headers=headers,
                    content=payload_str,
                )
                if resp.status_code == 200:
                    logger.info(f"Successfully set Redis SLA key for {action_id} (EX {ttl_seconds}).")
                    return True
                else:
                    logger.warning(f"Upstash Redis SET returned {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.warning(f"Redis unavailable for SLA tracking on {action_id}: {e}")

        return True

    async def get_remaining_ttl(self, action_id: str) -> int:
        """Return remaining TTL seconds for an action, or -1 if expired / not found."""
        key = f"dharma_sla:{action_id}"

        if self._has_remote_redis():
            try:
                headers = {"Authorization": f"Bearer {self.rest_token}"}
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get(f"{self.rest_url}/ttl/{key}", headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        ttl = int(data.get("result", -1))
                        if ttl >= 0:
                            return ttl
            except Exception as e:
                logger.debug(f"Redis TTL lookup error: {e}")

        # Local fallback check
        item = self._local_sla_store.get(action_id)
        if item:
            diff = item["expires_at"] - time.time()
            if diff >= 0:
                return max(0, int(diff + 0.999))
            return -1

        return -1


    async def delete_action_sla(self, action_id: str) -> bool:
        """Remove action from SLA tracking on decision (APPROVE / REJECT)."""
        key = f"dharma_sla:{action_id}"
        self._local_sla_store.pop(action_id, None)

        if not self._has_remote_redis():
            return True

        try:
            headers = {"Authorization": f"Bearer {self.rest_token}"}
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.get(f"{self.rest_url}/del/{key}", headers=headers)
            return True
        except Exception as e:
            logger.debug(f"Redis DEL error for {action_id}: {e}")
            return False

    async def check_expired_actions(self) -> List[Dict[str, Any]]:
        """Return list of actions whose SLA has expired and need escalation."""
        now = time.time()
        expired: List[Dict[str, Any]] = []

        # Check local memory store
        for action_id, item in list(self._local_sla_store.items()):
            if item["expires_at"] <= now:
                expired.append(item["payload"])
                self._local_sla_store.pop(action_id, None)

        return expired


_redis_sla = RedisSLAManager()


def get_redis_sla_manager() -> RedisSLAManager:
    return _redis_sla
