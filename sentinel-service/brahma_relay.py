"""
BRAHMA Relay — HTTP relay from SENTINEL to BRAHMA observe endpoint.
Sends CT convergence hits as physical observations for BRAHMA Dirichlet updates.

Endpoint: POST {BRAHMA_URL}/brahma/observe
Body format mirrors existing BRAHMA observe router in brahma-service/brahma/routers/observe.py.

Called by EnrichmentPipeline when convergence_score >= 7.0.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# BRAHMA service URL — set in .env for sentinel-service
BRAHMA_URL = os.getenv("BRAHMA_SERVICE_URL", "https://garuda-brahma-service.onrender.com")


async def notify_brahma_observe(
    domain: str,
    convergence_score: float,
    tactic: str,
    evidence_type: str,
    hostname: str = "ct-hunt-external",
) -> None:
    """
    Notify BRAHMA of a high-confidence CT convergence hit.
    Maps to initial_access tactic alpha update in the Dirichlet model.

    convergence_score >= 7.0 is the minimum threshold for BRAHMA notification
    (checked by caller — EnrichmentPipeline.process()).

    Failure is non-fatal: BRAHMA is a complementary signal, not required for
    CT hunt operations. Log and continue.
    """
    payload = {
        "hostname": hostname,
        "tactic": tactic,
        "evidence_type": evidence_type,
        "domain": domain,
        "convergence_score": convergence_score,
        "source": "CT_HUNT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                f"{BRAHMA_URL}/brahma/observe",
                json=payload,
            )
            if resp.status_code in (200, 201, 204):
                logger.info(
                    f"[BRAHMA-RELAY] Notified BRAHMA: domain={domain} "
                    f"convergence={convergence_score:.2f} tactic={tactic}"
                )
            else:
                logger.warning(
                    f"[BRAHMA-RELAY] BRAHMA returned {resp.status_code} "
                    f"for domain={domain}"
                )
    except Exception as exc:
        # Non-fatal — log and continue
        logger.warning(f"[BRAHMA-RELAY] Failed to notify BRAHMA for {domain}: {exc}")
