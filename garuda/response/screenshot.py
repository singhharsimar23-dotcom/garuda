import asyncio
import logging
from pathlib import Path
from typing import Optional

from garuda.database import get_supabase_client

logger = logging.getLogger("garuda.response.screenshot")


async def capture_screenshot(domain: str, alert_id: str) -> Optional[str]:
    """
    Safely capture a visual snapshot of a target threat domain using headless Playwright Chromium.

    Uploads the captured PNG to the Supabase Storage 'screenshots' bucket and returns
    its public accessibility URL.

    Args:
        domain: Domain name or URL to render.
        alert_id: Associated alert UUID string.

    Returns:
        Optional[str]: Public URL or storage path of the captured screenshot, or None on failure.
    """
    domain_clean = domain.strip().lower().lstrip("*.")
    if not domain_clean:
        return None

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
            except Exception as nav_err:
                logger.warning(f"[screenshot] Navigation failed for {domain_clean}: {nav_err}")
                # Try HTTP fallback
                try:
                    target_url = f"http://{domain_clean}"
                    await page.goto(target_url, timeout=10000, wait_until="load")
                    screenshot_bytes = await page.screenshot(type="png", full_page=False)
                except Exception:
                    screenshot_bytes = None
            finally:
                await browser.close()
    except ImportError:
        logger.warning("[screenshot] Playwright is not installed or available.")
        return None
    except Exception as e:
        logger.error(f"[screenshot] Error capturing screenshot for {domain_clean}: {e}")
        return None

    if not screenshot_bytes:
        return None

    # Upload to Supabase Storage bucket 'screenshots'
    file_path = f"{alert_id}.png"
    client = get_supabase_client()

    if client is not None:
        try:
            # TODO: verify Supabase storage bucket upload API
            client.storage.from_("screenshots").upload(
                path=file_path,
                file=screenshot_bytes,
                file_options={"content-type": "image/png", "upsert": "true"},
            )
            public_url = client.storage.from_("screenshots").get_public_url(file_path)
            return public_url
        except Exception as upload_err:
            logger.warning(f"[screenshot] Supabase storage upload failed: {upload_err}")

    # Local storage fallback
    local_dir = Path(__file__).resolve().parent.parent / "data" / "screenshots"
    local_dir.mkdir(parents=True, exist_ok=True)
    local_file = local_dir / file_path
    with open(local_file, "wb") as f:
        f.write(screenshot_bytes)

    return str(local_file)
