"""Canary webhook endpoint — thin FastAPI wrapper."""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, status

from garuda.modules.canary.webhook import CanaryWebhookError, process_canary_webhook

logger = logging.getLogger("garuda.api.routes.canary")

router = APIRouter(tags=["Canary Documents"])


def _get_supabase_client():
    from garuda.database import get_supabase_client
    return get_supabase_client()


@router.post("/canary/webhook")
@router.post("/api/canary/webhook")
async def canary_webhook_endpoint(request: Request) -> Dict[str, Any]:
    """Public webhook for canarytokens.org document fires."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload")

    from garuda.cache import get_redis_client

    try:
        return await process_canary_webhook(
            payload,
            _get_supabase_client(),
            redis_client=get_redis_client(),
        )
    except CanaryWebhookError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
