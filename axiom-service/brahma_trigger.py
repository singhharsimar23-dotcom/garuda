"""
BRAHMA Adversary & Prediction Service Trigger
Asynchronously notifies BRAHMA engine upon elevated IAS physics telemetry (IAS >= LOG).
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import httpx

from config import get_settings

logger = logging.getLogger("axiom.brahma_trigger")


async def trigger_brahma_observe(
    hostname: str,
    ias_score: float,
    channel_sigmas: Dict[str, float],
    workload_class: str,
    observed_at: Optional[str] = None,
) -> bool:
    """
    POST physics evidence to BRAHMA /internal/observe asynchronously.
    Fire-and-forget; never blocks or fails parent telemetry ingestion.
    """
    settings = get_settings()
    endpoint = f"{settings.brahma_service_url.rstrip('/')}/internal/observe"

    payload = {
        "hostname": hostname,
        "ias_score": ias_score,
        "channel_sigmas": channel_sigmas,
        "workload_class": workload_class,
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
        "source": "AXIOM_II_PHYSICS_ENGINE",
    }

    headers = {
        "X-Inter-Service-Secret": settings.inter_service_secret,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(endpoint, headers=headers, json=payload)
            if resp.status_code in (200, 201, 202, 204):
                logger.info(f"[BRAHMA TRIGGERED] Successfully forwarded IAS={ias_score} for {hostname}")
                return True
            else:
                logger.warning(
                    f"BRAHMA service returned status {resp.status_code} for {hostname}: {resp.text[:150]}"
                )
                return False
    except Exception as e:
        logger.warning(f"Failed to connect to BRAHMA service ({endpoint}): {e}")
        return False
