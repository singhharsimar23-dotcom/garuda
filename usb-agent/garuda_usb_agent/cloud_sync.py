"""
GARUDA USB Cloud Synchronization Engine
Syncs offline observations and alerts with AXIOM cloud backend when network/WireGuard is available.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("garuda.usb.sync")


class CloudSynchronizer:
    """
    Manages synchronization between local SQLite / alert files and remote AXIOM service.
    """

    def __init__(self, axiom_url: Optional[str] = None, agent_api_key: Optional[str] = None):
        self.axiom_url = axiom_url
        self.agent_api_key = agent_api_key

    def sync_pending_alerts(self, alert_queue_dir: str) -> int:
        """
        Uploads local alert JSON files to cloud and deletes synced files.
        """
        if not self.axiom_url or not self.agent_api_key:
            logger.info("Cloud sync skipped (no AXIOM URL or API key configured).")
            return 0

        if not os.path.exists(alert_queue_dir):
            return 0

        synced_count = 0
        alert_files = [f for f in os.listdir(alert_queue_dir) if f.startswith("alert_") and f.endswith(".json")]

        for fname in alert_files:
            fpath = os.path.join(alert_queue_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    alert_data = json.load(f)

                url = f"{self.axiom_url.rstrip('/')}/api/v1/telemetry"
                req = urllib.request.Request(
                    url,
                    data=json.dumps(alert_data).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.agent_api_key}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if 200 <= resp.status < 300:
                        os.remove(fpath)
                        synced_count += 1
            except Exception as e:
                logger.debug(f"Could not sync alert {fname}: {e}")

        logger.info(f"Synced {synced_count} pending offline alerts to AXIOM.")
        return synced_count
