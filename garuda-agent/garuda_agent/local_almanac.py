"""
Local Almanac Storage & Offline Telemetry Buffer
Stores offline telemetry records and local baselines in SQLite with 30-day retention.
"""

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("garuda_agent.local_almanac")


class LocalAlmanac:
    """
    Manages local SQLite database for buffering telemetry during network partitions
    and caching local baseline values.
    """

    def __init__(self, db_path: str = "./garuda_almanac.db"):
        self.db_path = db_path
        # Ensure parent directory exists
        parent = os.path.dirname(db_path)
        if parent and not os.path.exists(parent):
            try:
                os.makedirs(parent, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create directory for local database {parent}: {e}")

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize required SQLite tables."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS offline_telemetry (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        sent INTEGER DEFAULT 0,
                        sent_at REAL
                    )
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_offline_sent 
                    ON offline_telemetry (sent, created_at)
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS local_baseline (
                        workload_class TEXT PRIMARY KEY,
                        baseline_json TEXT NOT NULL,
                        observation_count INTEGER DEFAULT 0,
                        updated_at REAL NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize local SQLite almanac at {self.db_path}: {e}")

    def store_offline_batch(self, agent_id: str, batch: List[Dict[str, Any]]) -> bool:
        """Buffer unsent telemetry batch to SQLite."""
        try:
            payload_str = json.dumps(batch)
            now = time.time()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO offline_telemetry (agent_id, payload_json, created_at, sent) VALUES (?, ?, ?, 0)",
                    (agent_id, payload_str, now),
                )
                conn.commit()
            logger.info(f"Buffered {len(batch)} readings to offline storage.")
            return True
        except Exception as e:
            logger.error(f"Failed to store offline telemetry batch: {e}")
            return False

    def get_unsent_batches(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve pending unsent telemetry batches."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, agent_id, payload_json, created_at FROM offline_telemetry WHERE sent = 0 ORDER BY created_at ASC LIMIT ?",
                    (limit,),
                )
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    results.append({
                        "id": row["id"],
                        "agent_id": row["agent_id"],
                        "batch": json.loads(row["payload_json"]),
                        "created_at": row["created_at"],
                    })
                return results
        except Exception as e:
            logger.error(f"Failed to fetch unsent batches: {e}")
            return []

    def mark_batch_sent(self, batch_id: int) -> bool:
        """Mark a buffered batch as successfully synchronized."""
        try:
            now = time.time()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE offline_telemetry SET sent = 1, sent_at = ? WHERE id = ?",
                    (now, batch_id),
                )
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to mark batch {batch_id} as sent: {e}")
            return False

    def purge_old_records(self, max_age_days: int = 30) -> int:
        """Purge synchronized or expired records older than max_age_days."""
        cutoff = time.time() - (max_age_days * 86400)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM offline_telemetry WHERE created_at < ?", (cutoff,))
                deleted = cursor.rowcount
                conn.commit()
            logger.info(f"Purged {deleted} expired telemetry records from local almanac.")
            return deleted
        except Exception as e:
            logger.error(f"Failed to purge old records: {e}")
            return 0
