"""
Local Telemetry Buffer (SQLite FIFO)
Buffers telemetry payloads during network isolation or upstream AXIOM-II downtime.
Capped at 10,000 records with FIFO eviction.
"""

import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("garuda_agent.buffer")

DEFAULT_BUFFER_PATH = "/var/lib/garuda/buffer.db"
MAX_BUFFER_ROWS = 10000


class LocalBuffer:
    """
    Persistent SQLite FIFO queue for telemetry payloads.
    """

    def __init__(self, db_path: str = DEFAULT_BUFFER_PATH, max_rows: int = MAX_BUFFER_ROWS):
        self.db_path = db_path
        self.max_rows = max_rows
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema and parent directory."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except OSError as e:
                logger.warning(f"Could not create buffer directory {db_dir}: {e}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS telemetry_buffer (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_telemetry_created ON telemetry_buffer(id)"
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize SQLite buffer at {self.db_path}: {e}")

    def push(self, payload: Dict[str, Any]) -> bool:
        """
        Push a telemetry payload to the buffer.
        Enforces MAX_BUFFER_ROWS FIFO eviction.
        """
        try:
            payload_str = json.dumps(payload)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO telemetry_buffer (payload) VALUES (?)", (payload_str,))
                
                # Check row count and prune if exceeding max_rows
                cursor.execute("SELECT COUNT(*) FROM telemetry_buffer")
                count = cursor.fetchone()[0]
                if count > self.max_rows:
                    excess = count - self.max_rows
                    cursor.execute(
                        "DELETE FROM telemetry_buffer WHERE id IN (SELECT id FROM telemetry_buffer ORDER BY id ASC LIMIT ?)",
                        (excess,),
                    )
                conn.commit()
            return True
        except (sqlite3.Error, TypeError, ValueError) as e:
            logger.error(f"Failed to push payload to buffer: {e}")
            return False

    def fetch_batch(self, limit: int = 100) -> List[Tuple[int, Dict[str, Any]]]:
        """Fetch up to `limit` oldest un-sent payloads with their row IDs."""
        results: List[Tuple[int, Dict[str, Any]]] = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, payload FROM telemetry_buffer ORDER BY id ASC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                for row_id, payload_str in rows:
                    try:
                        results.append((row_id, json.loads(payload_str)))
                    except json.JSONDecodeError:
                        # Corrupt row, mark for deletion
                        results.append((row_id, {}))
        except sqlite3.Error as e:
            logger.error(f"Failed to fetch batch from buffer: {e}")
        return results

    def delete_batch(self, row_ids: List[int]) -> None:
        """Remove successfully streamed rows by their IDs."""
        if not row_ids:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                placeholders = ",".join("?" for _ in row_ids)
                cursor.execute(f"DELETE FROM telemetry_buffer WHERE id IN ({placeholders})", row_ids)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to delete rows from buffer: {e}")

    def count(self) -> int:
        """Return total buffered records."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM telemetry_buffer")
                return int(cursor.fetchone()[0])
        except sqlite3.Error as e:
            logger.error(f"Failed to count buffer rows: {e}")
            return 0

    def clear(self) -> None:
        """Clear all buffer records."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM telemetry_buffer")
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to clear buffer: {e}")
