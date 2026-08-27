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

    # Cloud / GitHub Actions dispatch mode
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
                logger.info(f"[screenshot] Dispatched screenshot workflow for {domain_clean} to GH Actions.")
                return None  # URL set later by GH Actions callback
        except Exception as e:
            logger.warning(f"[screenshot] Failed dispatching screenshot event to GitHub: {e}")

    # Local development mode with Playwright
    screenshot_bytes: Optional[bytes] = None
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            )
            page = await context.new_page()
            try:
                target_url = f"https://{domain_clean}" if not domain_clean.startswith("http") else domain_clean
                await page.goto(target_url, timeout=15000, wait_until="load")
                screenshot_bytes = await page.screenshot(type="png", full_page=False)
            except Exception:
                try:
                    target_url = f"http://{domain_clean}"
                    await page.goto(target_url, timeout=10000, wait_until="load")
                    screenshot_bytes = await page.screenshot(type="png", full_page=False)
                except Exception:
                    screenshot_bytes = None
            finally:
                await browser.close()
    except (ImportError, ModuleNotFoundError):
        logger.info("[screenshot] Playwright not installed locally. Offloading to GitHub Actions.")
        return None
    except Exception as e:
        logger.error(f"[screenshot] Local screenshot capture error: {e}")
        return None

    if not screenshot_bytes:
        return None

    # Upload to Supabase Storage bucket 'screenshots'
    file_path = f"{alert_id}.png"
    client = get_supabase_client()
    if client is not None:
        try:
            client.storage.from_("screenshots").upload(
                path=file_path,
                file=screenshot_bytes,
                file_options={"content-type": "image/png", "upsert": "true"},
            )
            return client.storage.from_("screenshots").get_public_url(file_path)
        except Exception as upload_err:
            logger.warning(f"[screenshot] Supabase storage upload failed: {upload_err}")

    # Local fallback
    local_dir = Path(__file__).resolve().parent.parent / "data" / "screenshots"
    local_dir.mkdir(parents=True, exist_ok=True)
    local_file = local_dir / file_path
    with open(local_file, "wb") as f:
        f.write(screenshot_bytes)
    return str(local_file)
