import logging
from typing import Any, Dict
from fastapi import APIRouter, BackgroundTasks, Request, Response, status

from garuda.response.telegram_bot import handle_telegram_update

logger = logging.getLogger("garuda.api.routes.telegram")

router = APIRouter(tags=["Telegram Webhook"])


@router.post("/telegram_webhook", status_code=status.HTTP_200_OK)
async def receive_telegram_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """
    Handle incoming Telegram Bot webhook updates.

    Responds with HTTP 200 OK immediately to satisfy Telegram's webhook latency requirements
    and routes command execution asynchronously.
    """
    try:
        update_data = await request.json()
    except Exception as e:
        logger.warning(f"[api.telegram] Invalid JSON payload received: {e}")
        return {"ok": True}

    # Process command in background task
    background_tasks.add_task(handle_telegram_update, update_data)
    return {"ok": True}
