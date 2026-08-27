from datetime import datetime, timezone
import logging
from typing import Any, Dict
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status

from garuda.collector import run_collection
from garuda.config import settings

logger = logging.getLogger("garuda.api.routes.collect")

router = APIRouter(prefix="/collect", tags=["Collector Trigger"])


@router.post("", status_code=status.HTTP_200_OK)
@router.get("", status_code=status.HTTP_200_OK)
async def trigger_background_collection(
    background_tasks: BackgroundTasks,
    request: Request,
    authorization: str = Header(None),
) -> Dict[str, Any]:
    """
    Vercel Cron target. Returns 200 immediately and dispatches collection run to GitHub Actions.
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
    logger.info("[api.collect] Triggering collection run...")

    if settings.GH_TOKEN and settings.GH_REPO:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"https://api.github.com/repos/{settings.GH_REPO}/dispatches",
                    headers={
                        "Authorization": f"Bearer {settings.GH_TOKEN}",
                        "Accept": "application/vnd.github+json",
                    },
                    json={
                        "event_type": "collect",
                        "client_payload": {"triggered_by": "vercel_cron"},
                    },
                )
            return {"status": "dispatched", "target": "github_actions", "timestamp": now_iso}
        except Exception as e:
            logger.warning(f"[api.collect] Failed dispatching to GitHub Actions: {e}")

    # Fallback to local async background task
    background_tasks.add_task(run_collection)
    return {"status": "dispatched", "target": "background_task", "timestamp": now_iso}


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

