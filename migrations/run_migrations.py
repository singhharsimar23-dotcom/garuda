"""
Idempotent Migration Runner for GARUDA Northflank & Supabase PostgreSQL
Executes SQL migration files in numerical order.
"""

import glob
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.migrations")


def run_migrations(database_url: str = None, migrations_dir: str = None) -> bool:
    """
    Executes all .sql files in migrations directory against the target database.
    """
    db_url = database_url or os.environ.get("NORTHFLANK_DB_URL") or os.environ.get("DATABASE_URL")
    if not db_url:
        logger.error("No database URL provided (NORTHFLANK_DB_URL or DATABASE_URL not set).")
        return False

    script_dir = migrations_dir or os.path.dirname(os.path.abspath(__file__))
    migration_files = sorted(glob.glob(os.path.join(script_dir, "[0-9]*.sql")))

    if not migration_files:
        logger.warning(f"No migration SQL files found in {script_dir}")
        return True

    logger.info(f"Found {len(migration_files)} migration files to execute.")

    # Try asyncpg or psycopg2 / psycopg
    try:
        import psycopg2
        logger.info("Using psycopg2 for migration execution...")
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cursor = conn.cursor()

        for sql_path in migration_files:
            file_name = os.path.basename(sql_path)
            logger.info(f"Executing migration: {file_name}...")
            with open(sql_path, "r", encoding="utf-8") as f:
                sql_content = f.read()
            cursor.execute(sql_content)
            logger.info(f"Successfully applied {file_name}")

        cursor.close()
        conn.close()
        logger.info("All migrations completed successfully.")
        return True
    except ImportError:
        pass

    try:
        import asyncio
        import asyncpg

        async def _run_async():
            logger.info("Using asyncpg for migration execution...")
            conn = await asyncpg.connect(db_url)
            for sql_path in migration_files:
                file_name = os.path.basename(sql_path)
                logger.info(f"Executing migration: {file_name}...")
                with open(sql_path, "r", encoding="utf-8") as f:
                    sql_content = f.read()
                await conn.execute(sql_content)
                logger.info(f"Successfully applied {file_name}")
            await conn.close()

        asyncio.run(_run_async())
        logger.info("All migrations completed successfully via asyncpg.")
        return True
    except ImportError:
        logger.error("Neither psycopg2 nor asyncpg is installed. Please install one to run migrations.")
        return False
    except Exception as e:
        logger.error(f"Migration execution failed: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run GARUDA SQL migrations")
    parser.add_argument("--url", help="Database connection URL", default=None)
    parser.add_argument("--dir", help="Directory containing migration SQL files", default=None)
    args = parser.parse_args()

    success = run_migrations(database_url=args.url, migrations_dir=args.dir)
    sys.exit(0 if success else 1)
