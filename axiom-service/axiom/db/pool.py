"""
Asyncpg Database Connection Pool Management
Enforces connection pooling (min=2, max=10) with retry and exponential backoff.
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("axiom.db.pool")

_pool: Optional[object] = None


async def init_db_pool(
    db_url: Optional[str],
    min_size: int = 2,
    max_size: int = 10,
    retries: int = 3,
    initial_backoff: float = 1.0,
) -> Optional[object]:
    """
    Initializes asyncpg connection pool with exponential backoff retry logic.
    """
    global _pool
    if not db_url:
        logger.warning("No DATABASE_URL configured. Database pool initialized in disabled/mock state.")
        return None

    try:
        import asyncpg
    except ImportError:
        logger.warning("asyncpg is not installed. Database persistence will be disabled.")
        return None

    for attempt in range(1, retries + 1):
        try:
            logger.info(f"Connecting to database pool (attempt {attempt}/{retries}, min={min_size}, max={max_size})...")
            _pool = await asyncpg.create_pool(
                dsn=db_url,
                min_size=min_size,
                max_size=max_size,
                command_timeout=15.0,
            )
            logger.info("Database connection pool established successfully.")
            return _pool
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt} failed: {e}")
            if attempt < retries:
                sleep_time = initial_backoff * (2 ** (attempt - 1))
                await asyncio.sleep(sleep_time)

    logger.error("Failed to establish database connection pool after retries. Continuing in degraded mode.")
    return None


async def get_db_pool() -> Optional[object]:
    """Returns the active asyncpg connection pool or None."""
    global _pool
    return _pool


async def close_db_pool() -> None:
    """Gracefully terminates all pool connections."""
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
            logger.info("Database connection pool closed.")
        except Exception as e:
            logger.warning(f"Error closing database pool: {e}")
        finally:
            _pool = None
