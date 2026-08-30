"""
BRAHMA Database Pool Module
Asyncpg connection pool with exponential backoff retry logic.
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("brahma.db.pool")

_pool: Optional[object] = None


async def init_db_pool(
    db_url: Optional[str],
    min_size: int = 2,
    max_size: int = 10,
    retries: int = 3,
    initial_backoff: float = 1.0,
) -> Optional[object]:
    """Initializes asyncpg connection pool."""
    global _pool
    if not db_url:
        logger.warning("No DATABASE_URL configured for BRAHMA. Database pool initialized in disabled/mock state.")
        return None

    try:
        import asyncpg
    except ImportError:
        logger.warning("asyncpg is not installed. Database persistence will be disabled.")
        return None

    for attempt in range(1, retries + 1):
        try:
            logger.info(f"Connecting BRAHMA to database pool (attempt {attempt}/{retries})...")
            _pool = await asyncpg.create_pool(
                dsn=db_url,
                min_size=min_size,
                max_size=max_size,
                command_timeout=15.0,
            )
            logger.info("BRAHMA Database connection pool established successfully.")
            return _pool
        except Exception as e:
            logger.warning(f"BRAHMA Database connection attempt {attempt} failed: {e}")
            if attempt < retries:
                await asyncio.sleep(initial_backoff * (2 ** (attempt - 1)))

    logger.error("Failed to establish BRAHMA database connection pool after retries.")
    return None


async def get_db_pool() -> Optional[object]:
    """Returns the active asyncpg connection pool."""
    global _pool
    return _pool


async def close_db_pool() -> None:
    """Closes all database pool connections."""
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
            logger.info("BRAHMA database connection pool closed.")
        except Exception as e:
            logger.warning(f"Error closing BRAHMA database pool: {e}")
        finally:
            _pool = None
