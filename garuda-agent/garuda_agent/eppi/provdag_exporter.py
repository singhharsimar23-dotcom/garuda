"""
PROVDAG Exporter Module
Batches and streams process provenance graph events to the AXIOM provenance endpoint.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("garuda_agent.eppi.exporter")


class PROVDAGExporter:
    """
    Streams local EPPI events to AXIOM /api/v1/provenance.
    """

    def __init__(self, axiom_url: str, agent_id: str, agent_api_key: str):
        self.axiom_url = axiom_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_api_key = agent_api_key

    def export_events(self, events: List[Dict[str, Any]]) -> bool:
        """
        Transmits EPPI events to AXIOM provenance endpoint.
        """
        if not events:
            return True

        url = f"{self.axiom_url}/api/v1/provenance"
        payload = {
            "agent_id": self.agent_id,
            "events": events,
            "events_count": len(events),
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.agent_api_key}",
            "User-Agent": "garuda-agent-eppi/0.1.0",
        }

        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            logger.debug(f"Failed to export EPPI events: {e}")
            return False
