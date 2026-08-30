"""
Database Retention & Vacuum Cleanup Maintenance Script (Cron Job 1)
Prunes physics_observations older than 90 days to maintain database size under the 512MB threshold.
"""

import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("garuda.maintenance.cleanup")


def run_cleanup(database_url: str = None) -> bool:
    """Executes retention cleanup on PostgreSQL."""
    db_url = database_url or os.environ.get("NORTHFLANK_DB_URL") or os.environ.get("DATABASE_URL")
    if not db_url:
        logger.warning("No NORTHFLANK_DB_URL configured. Cleanup skipped.")
        return True

    logger.info("Starting automated 90-day retention cleanup...")

    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cursor = conn.cursor()

        # 1. Prune physics observations older than 90 days
        delete_query = """
            DELETE FROM physics_observations
            WHERE observed_at < NOW() - INTERVAL '90 days';
        """
        cursor.execute(delete_query)
        deleted_count = cursor.rowcount
        logger.info(f"Purged {deleted_count} stale physics observation rows (> 90 days).")

        # 2. Check current database size
        size_query = "SELECT pg_size_pretty(pg_database_size(current_database()));"
        cursor.execute(size_query)
        db_size = cursor.fetchone()[0]
        logger.info(f"Current PostgreSQL Database Size: {db_size} (Target: < 400MB).")

        cursor.close()
        conn.close()
        return True

    except Exception as e:
        logger.error(f"Cleanup maintenance failed: {e}")
        return False


if __name__ == "__main__":
    success = run_cleanup()
    sys.exit(0 if success else 1)
