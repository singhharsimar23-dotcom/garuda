from datetime import datetime, timezone
import logging
from typing import Any, Dict
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status

from garuda.collector import run_collection
from garuda.config import settings

logger = logging.getLogger("garuda.api.routes.collect")

router = APIRouter(prefix="/collect", tags=["Collector Trigger"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
@router.get("", status_code=status.HTTP_202_ACCEPTED)
async def trigger_background_collection(
    background_tasks: BackgroundTasks,
    request: Request,
    authorization: str = Header(None),
) -> Dict[str, Any]:
    """
    Vercel Cron and multi-feed trigger target.

    Dispatches full intelligence ingestion (crt.sh, OTX, URLhaus, CIRCL PDNS, MalwareBazaar)
    as an asynchronous background task and immediately responds with 202 Accepted.
    """
    if settings.CRON_SECRET:
        expected = f"Bearer {settings.CRON_SECRET}"
        if authorization != expected:
            logger.warning("[api.collect] Unauthorized cron collection trigger attempt.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing cron authorization header.",
            )

    now_iso = datetime.now(timezone.utc).isoformat()
    logger.info("[api.collect] Enqueueing asynchronous intelligence collection run...")

    # Enqueue in background tasks — non-blocking HTTP response
    background_tasks.add_task(run_collection)

    return {
        "status": "collection_started",
        "timestamp": now_iso,
        "environment": settings.ENVIRONMENT,
    }


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def receive_edge_candidate(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
) -> Dict[str, Any]:
    """
    Ingest a real-time domain candidate from the Cloudflare Edge Worker.
    """
    if settings.CRON_SECRET:
        expected = f"Bearer {settings.CRON_SECRET}"
        if authorization != expected:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization token.",
            )

    try:
        body = await request.json()
    except Exception:
        body = {}

    domain = str(body.get("domain", "")).strip().lower()
    if not domain:
        return {"status": "ignored", "reason": "empty_domain"}

    from garuda.detection.engine import process_domain
    background_tasks.add_task(process_domain, domain, "cf_worker")

    return {"status": "enqueued", "domain": domain}

