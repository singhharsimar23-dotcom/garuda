"""
DHARMA Subsystem Trigger Service
Dispatches automated containment & deception triggers to Service 2 on CRITICAL physical anomalies.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from ..config import AxiomSettings, get_settings
from ..models.telemetry import IASResult

logger = logging.getLogger("axiom.services.dharma")


async def trigger_dharma(
    agent_id: str,
    hostname: str,
    ias_result: IASResult,
    settings: Optional[AxiomSettings] = None,
) -> bool:
    """
    Sends inter-service HTTP POST to DHARMA trigger endpoint on Service 2.
    """
    settings = settings or get_settings()

    if not settings.feature_flag_dharma or not settings.brahma_service_url:
        logger.info(f"DHARMA trigger disabled or URL not set. (Agent: {agent_id}, IAS: {ias_result.score})")
        return False

    url = f"{settings.brahma_service_url.rstrip('/')}/api/v1/dharma/trigger"
    payload = {
        "source": "AXIOM_II_PHYSICS",
        "agent_id": agent_id,
        "hostname": hostname,
        "ias_score": ias_result.score,
        "top_channels": ias_result.top_divergent_channels,
        "trigger_level": ias_result.level.value,
    }

    headers = {
        "Content-Type": "application/json",
        "X-Inter-Service-Secret": settings.inter_service_secret,
        "User-Agent": "GARUDA-AXIOM/0.1.0",
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            success = 200 <= resp.status < 300
            if success:
                logger.info(f"Successfully triggered DHARMA response for agent {agent_id}.")
            return success
    except urllib.error.URLError as e:
        logger.warning(f"Failed to connect to DHARMA Service at {url}: {e.reason}")
        return False
    except Exception as e:
        logger.warning(f"Error triggering DHARMA: {e}")
        return False
