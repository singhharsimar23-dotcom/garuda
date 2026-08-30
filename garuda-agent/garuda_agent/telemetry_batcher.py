"""
Telemetry Batcher & Transport Layer
Aggregates telemetry observations, manages HTTP transport to AXIOM, and coordinates offline queue fallback.
"""

import logging
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
import json

from .config import AgentConfig
from .local_almanac import LocalAlmanac

logger = logging.getLogger("garuda_agent.batcher")


class TelemetryBatcher:
    """
    Batches telemetry observations and handles resilient transmission to AXIOM service.
    """

    def __init__(self, config: AgentConfig, almanac: LocalAlmanac):
        self.config = config
        self.almanac = almanac
        self.buffer: List[Dict[str, Any]] = []

    def add_reading(self, reading: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Appends a reading to the in-memory buffer.
        If buffer size >= batch_size, dispatches the batch and returns the response from AXIOM.
        """
        self.buffer.append(reading)
        if len(self.buffer) >= self.config.batch_size:
            return self.flush()
        return None

    def flush(self) -> Optional[Dict[str, Any]]:
        """
        Dispatches all buffered readings to AXIOM service.
        """
        if not self.buffer:
            return None

        batch = list(self.buffer)
        self.buffer.clear()

        response = self.send_batch(batch)
        if response is not None:
            # Successfully sent current batch; try draining offline buffer if any
            self._drain_offline_queue()
            return response
        else:
            # Network failed; buffer to local SQLite
            self.almanac.store_offline_batch(self.config.agent_id, batch)
            return None

    def send_batch(self, batch: List[Dict[str, Any]], retries: int = 2) -> Optional[Dict[str, Any]]:
        """
        Sends a single batch payload to AXIOM endpoint with retry logic.
        Uses standard library urllib to avoid mandatory third-party network dependencies.
        """
        url = f"{self.config.axiom_url.rstrip('/')}/api/v1/telemetry"
        payload = {
            "agent_id": self.config.agent_id,
            "hostname": self.config.hostname,
            "readings": batch,
            "timestamp": time.time(),
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.agent_api_key}",
            "User-Agent": "garuda-agent/0.1.0",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if 200 <= resp.status < 300:
                        resp_data = json.loads(resp.read().decode("utf-8"))
                        logger.debug(f"Telemetry batch ({len(batch)} items) accepted by AXIOM.")
                        return resp_data
            except urllib.error.HTTPError as e:
                logger.warning(f"AXIOM HTTP Error {e.code} on attempt {attempt + 1}: {e.reason}")
                if e.code in (401, 403):
                    # Authentication failure, do not retry blindly
                    return None
            except urllib.error.URLError as e:
                logger.warning(f"Connection failed to AXIOM ({url}) on attempt {attempt + 1}: {e.reason}")
            except Exception as e:
                logger.warning(f"Unexpected transport error on attempt {attempt + 1}: {e}")

            if attempt < retries:
                time.sleep(1.0 * (attempt + 1))

        return None

    def _drain_offline_queue(self) -> None:
        """
        Attempts to synchronize cached offline batches when connectivity is available.
        """
        pending = self.almanac.get_unsent_batches(limit=10)
        for item in pending:
            resp = self.send_batch(item["batch"], retries=1)
            if resp is not None:
                self.almanac.mark_batch_sent(item["id"])
            else:
                break
