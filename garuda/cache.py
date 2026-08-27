import hashlib
import json
import logging
from typing import Any, Optional, Set
try:
    from upstash_redis.asyncio import Redis
except ImportError:
    Redis = None  # type: ignore

from garuda.config import settings

logger = logging.getLogger("garuda.cache")

_redis_client: Optional[Redis] = None
_in_memory_cache: dict[str, Any] = {}
_in_memory_sets: dict[str, Set[str]] = {}


def get_redis_client() -> Optional[Redis]:
    """Retrieve or initialize the Upstash Async Redis client."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    if settings.UPSTASH_REDIS_REST_URL and settings.UPSTASH_REDIS_REST_TOKEN:
        try:
            _redis_client = Redis(
                url=settings.UPSTASH_REDIS_REST_URL,
                token=settings.UPSTASH_REDIS_REST_TOKEN,
            )
            return _redis_client
        except Exception as e:
            logger.warning(f"Failed to initialize Upstash Redis: {e}. Falling back to memory.")
            return None
    return None


def generate_cache_key(source: str, query: Any) -> str:
    """Generate a cache key using the standard pattern 'garuda:{source}:{query_hash}'."""
    if isinstance(query, (dict, list)):
        raw_str = json.dumps(query, sort_keys=True)
    else:
        raw_str = str(query)
    query_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
    return f"garuda:{source}:{query_hash}"


async def get_cached_json(key: str) -> Optional[Any]:
    """Retrieve cached JSON data by key."""
    client = get_redis_client()
    if client:
        try:
            data = await client.get(key)
            if data:
                if isinstance(data, (dict, list)):
                    return data
                return json.loads(data)
        except Exception as e:
            logger.error(f"Redis get error on {key}: {e}")

    # In-memory fallback
    return _in_memory_cache.get(key)


async def set_cached_json(key: str, data: Any, ex: int = 1800) -> bool:
    """Store data in cache as JSON with a specified TTL in seconds (default: 1800)."""
    payload = json.dumps(data)
    client = get_redis_client()
    if client:
        try:
            await client.set(key, payload, ex=ex)
            return True
        except Exception as e:
            logger.error(f"Redis set error on {key}: {e}")

    _in_memory_cache[key] = data
    return True


async def check_and_add_set(set_name: str, member: str, ttl: Optional[int] = None) -> bool:
    """
    Check if a member exists in a Redis set. If not present, add it.
    Returns True if the member was newly added, False if it was already present.
    """
    client = get_redis_client()
    if client:
        try:
            is_member = await client.sismember(set_name, member)
            if is_member:
                return False
            await client.sadd(set_name, member)
            if ttl:
                await client.expire(set_name, ttl)
            return True
        except Exception as e:
            logger.error(f"Redis set operation error on {set_name}: {e}")

    # In-memory fallback
    if set_name not in _in_memory_sets:
        _in_memory_sets[set_name] = set()

    if member in _in_memory_sets[set_name]:
        return False

    _in_memory_sets[set_name].add(member)
    return True
