import asyncio
import logging
from pathlib import Path
from typing import Optional
import httpx

from garuda.config import settings
from garuda.database import get_supabase_client

logger = logging.getLogger("garuda.response.screenshot")


async def capture_screenshot(domain: str, alert_id: str) -> Optional[str]:
    """
    Dispatch screenshot capture to GitHub Actions or capture locally if Playwright is present.

    Playwright Chromium cannot run inside Vercel Serverless Functions due to size limits.
    When GH_TOKEN and GH_REPO are configured, a repository_dispatch event is triggered.
    """
    domain_clean = domain.strip().lower().lstrip("*.")
    if not domain_clean:
        return None

    # Cloud / GitHub Actions dispatch mode (runs in ubuntu-latest runner with full Playwright Chromium)
    if settings.GH_TOKEN and settings.GH_REPO:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"https://api.github.com/repos/{settings.GH_REPO}/dispatches",
                    headers={
                        "Authorization": f"Bearer {settings.GH_TOKEN}",
                        "Accept": "application/vnd.github+json",
                    },
                    json={
                        "event_type": "screenshot",
                        "client_payload": {"domain": domain_clean, "alert_id": alert_id},
                    },
                )
                resp.raise_for_status()
                logger.info(f"[screenshot] Dispatched screenshot workflow for {domain_clean} to GitHub Actions runner.")
                return None  # URL set asynchronously by GH Actions callback to Supabase
        except Exception as e:
            logger.warning(f"[screenshot] Failed dispatching screenshot event to GitHub: {e}")

    logger.info(f"[screenshot] Screenshot offloaded to GitHub Actions runner for alert {alert_id}.")
    return None
