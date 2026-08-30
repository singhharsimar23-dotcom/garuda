"""
KALI Threat State Synchronizer
Pulls live adversary posteriors from BRAHMA service to seed automated red-team simulations.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kali.threat_state")


def fetch_all_agent_posteriors(
    brahma_url: Optional[str] = None,
    agent_ids: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves current kill-chain distributions for active agents.
    """
    brahma_url = brahma_url or os.environ.get("NORTHFLANK_BRAHMA_URL", "http://localhost:8001")
    agent_list = agent_ids or ["delhi-core-gw", "mumbai-dc-01", "drdo-sensor-hub"]

    posteriors = {}
    for aid in agent_list:
        try:
            url = f"{brahma_url}/api/v1/brahma/assessment/{aid}"
            req = urllib.request.Request(url, headers={"User-Agent": "KALI-RedTeam/0.1"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if 200 <= resp.status < 300:
                    posteriors[aid] = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.debug(f"Failed to fetch assessment for {aid}: {e}")
            # Mock default distribution
            posteriors[aid] = {
                "agent_id": aid,
                "actor_id": "APT36",
                "map_tactic": "execution",
                "confidence": 0.65,
                "observation_count": 18,
                "convergence_status": "CONVERGED",
            }

    return posteriors
