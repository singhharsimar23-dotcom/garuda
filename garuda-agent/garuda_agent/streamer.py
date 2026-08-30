"""
AXIOM-II Telemetry Streamer
Transmits real-time host physics telemetry to AXIOM-II ingestion API with exponential backoff,
local SQLite buffering upon disconnect, and strict HTTP 401/429 status handling.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import httpx

from garuda_agent.buffer import LocalBuffer

logger = logging.getLogger("garuda_agent.streamer")

BACKOFF_DELAYS = [1, 2, 4, 8, 16]
RATE_LIMIT_BACKOFF_SECONDS = 60.0


def alert_syslog(message: str) -> None:
    """Alert local syslog on critical security conditions (Unix)."""
    try:
        import syslog
        syslog.openlog(ident="garuda-agent", logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_ERR, message)
        syslog.closelog()
    except (ImportError, AttributeError):
        logger.error(f"[SYSLOG ALERT] {message}")


class TelemetryStreamer:
    """
    HTTP POST streamer to AXIOM-II backend with queue flushing and backoff.
    """

    def __init__(
        self,
        axiom_host: str,
        agent_api_key: str,
        buffer: Optional[LocalBuffer] = None,
        timeout: float = 5.0,
    ):
        self.axiom_host = axiom_host.rstrip("/")
        if not self.axiom_host.startswith("http://") and not self.axiom_host.startswith("https://"):
            self.endpoint = f"https://{self.axiom_host}/api/v1/telemetry"
        else:
            self.endpoint = f"{self.axiom_host}/api/v1/telemetry"

        self.agent_api_key = agent_api_key
        self.buffer = buffer or LocalBuffer()
        self.timeout = timeout
        
        # State tracking
        self.key_rejected: bool = False
        self.rate_limited_until: float = 0.0
        self.consecutive_failures: int = 0

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.agent_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "garuda-agent/0.1.0",
        }

    def _post_payload(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[int]]:
        """
        Execute single synchronous HTTP POST.
        Returns: (success: bool, status_code: Optional[int])
        """
        if self.key_rejected:
            logger.warning("Telemetry transmission skipped: AGENT_KEY_REJECTED")
            return False, 401

        now = time.monotonic()
        if now < self.rate_limited_until:
            logger.warning(f"Telemetry transmission skipped: Rate-limited for {int(self.rate_limited_until - now)}s")
            return False, 429

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.endpoint, headers=self._get_headers(), json=payload)
                
                if response.status_code in (200, 201, 202, 204):
                    self.consecutive_failures = 0
                    return True, response.status_code

                if response.status_code == 401:
                    self.key_rejected = True
                    logger.error("AGENT_KEY_REJECTED: Received 401 Unauthorized from AXIOM-II.")
                    alert_syslog("AGENT_KEY_REJECTED: API key invalid on AXIOM-II.")
                    return False, 401

                if response.status_code == 429:
                    self.rate_limited_until = time.monotonic() + RATE_LIMIT_BACKOFF_SECONDS
                    logger.warning(f"Received 429 Too Many Requests from AXIOM-II. Backing off for {RATE_LIMIT_BACKOFF_SECONDS}s.")
                    return False, 429

                # 5xx or other status codes
                logger.warning(f"AXIOM-II returned HTTP {response.status_code}: {response.text[:200]}")
                return False, response.status_code

        except (httpx.RequestError, httpx.TimeoutException, OSError) as e:
            logger.warning(f"Network error communicating with AXIOM-II ({self.endpoint}): {e}")
            return False, None

    def flush_buffer(self, max_records: int = 500) -> int:
        """
        Flush queued records in FIFO order.
        Returns number of successfully sent rows.
        """
        if self.key_rejected or time.monotonic() < self.rate_limited_until:
            return 0

        flushed = 0
        batch = self.buffer.fetch_batch(limit=min(max_records, 100))
        while batch and not self.key_rejected:
            success_ids = []
            for row_id, payload in batch:
                if not payload:
                    success_ids.append(row_id)
                    continue

                success, status_code = self._post_payload(payload)
                if success:
                    success_ids.append(row_id)
                    flushed += 1
                else:
                    # If failed on buffer flush, stop flushing and resume later
                    break

            if success_ids:
                self.buffer.delete_batch(success_ids)

            if len(success_ids) < len(batch):
                # An error occurred; don't loop endlessly
                break

            batch = self.buffer.fetch_batch(limit=100)

        return flushed

    def send(self, payload: Dict[str, Any], retry_synchronously: bool = False) -> bool:
        """
        Send telemetry payload to AXIOM-II.
        Flushes buffer if reconnecting, retries with backoff on failure, or buffers locally.
        """
        if self.key_rejected:
            logger.warning("Not sending telemetry: AGENT_KEY_REJECTED")
            return False

        # If buffer has rows, attempt to flush buffer first
        if self.buffer.count() > 0:
            self.flush_buffer()

        # Send current payload
        success, status_code = self._post_payload(payload)
        if success:
            return True

        if status_code == 401:
            # Fatal key rejection - do NOT retry, do NOT buffer
            return False

        # Attempt exponential backoff retries if requested or buffer locally
        if retry_synchronously:
            for delay in BACKOFF_DELAYS:
                time.sleep(delay)
                success, status_code = self._post_payload(payload)
                if success:
                    return True
                if status_code == 401:
                    return False

        # Offline / Upstream Down: Enqueue to local SQLite buffer
        logger.info("Upstream unavailable; buffering telemetry payload locally in SQLite.")
        self.buffer.push(payload)
        return False
