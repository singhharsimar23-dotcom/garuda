"""
Sandbox submission trigger — gates high-score alerts with downloadable content.

Background task via asyncio.create_task — never blocks main alert pipeline.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from garuda.config import settings
from garuda.modules.sandbox.anyrun_client import (
    MAX_SUBMISSIONS_PER_DAY,
    extract_iocs,
    poll_results,
    submit_url,
)

logger = logging.getLogger("garuda.modules.sandbox.trigger")

DAILY_SUBMISSION_CACHE_KEY = "garuda:sandbox:submissions:{date}"
DOMAIN_SUBMISSION_KEY = "garuda:sandbox:domain:{domain}"
DOMAIN_SUBMISSION_TTL = 86400  # 24h

DOWNLOADABLE_CONTENT_TYPES = frozenset({
    "application/octet-stream",
    "application/zip",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable",
})


async def _domain_resolves(domain: str) -> bool:
    """Check if domain currently resolves via DNS."""
    try:
        import dns.resolver
    except ImportError:
        return True  # permissive if dnspython unavailable in test env

    def _sync() -> bool:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            resolver.resolve(domain, "A")
            return True
        except Exception:
            return False

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync)


async def _has_downloadable_content(domain: str) -> bool:
    """HTTP HEAD — returns True if response looks like a downloadable payload."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.head(url)
                content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
                disposition = (resp.headers.get("content-disposition") or "").lower()
                if content_type in DOWNLOADABLE_CONTENT_TYPES:
                    return True
                if "attachment" in disposition:
                    return True
        except Exception:
            continue
    return False


async def _get_daily_submission_count(redis_client) -> int:
    if redis_client is None:
        return 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = DAILY_SUBMISSION_CACHE_KEY.format(date=today)
    try:
        val = await redis_client.get(key)
        return int(val or 0)
    except Exception:
        return 0


async def _increment_daily_submission(redis_client) -> None:
    if redis_client is None:
        return
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = DAILY_SUBMISSION_CACHE_KEY.format(date=today)
    try:
        await redis_client.incr(key)
        await redis_client.expire(key, 86400)
    except Exception as exc:
        logger.warning("[sandbox] Redis INCR failed: %s", exc)


async def _was_domain_submitted_recently(domain: str, redis_client) -> bool:
    if redis_client is None:
        return False
    key = DOMAIN_SUBMISSION_KEY.format(domain=domain.lower())
    try:
        val = await redis_client.get(key)
        return val is not None
    except Exception:
        return False


async def _mark_domain_submitted(domain: str, redis_client) -> None:
    if redis_client is None:
        return
    key = DOMAIN_SUBMISSION_KEY.format(domain=domain.lower())
    try:
        await redis_client.set(key, "1", ex=DOMAIN_SUBMISSION_TTL)
    except Exception as exc:
        logger.warning("[sandbox] Redis SET domain key failed: %s", exc)


async def should_submit(alert: dict, redis_client) -> bool:
    """
    Returns True only if ALL conditions met:
    1. alert.score >= 60
    2. Domain resolves
    3. HTTP HEAD returns downloadable content type or attachment disposition
    4. Daily submission count < MAX_SUBMISSIONS_PER_DAY
    5. Domain not submitted in last 24h
    """
    score = alert.get("score", 0)
    if score < 60:
        return False

    domain = (alert.get("domain") or "").strip().lower().lstrip("*.")
    if not domain:
        return False

    if not await _domain_resolves(domain):
        return False

    if not await _has_downloadable_content(domain):
        return False

    daily_count = await _get_daily_submission_count(redis_client)
    if daily_count >= MAX_SUBMISSIONS_PER_DAY:
        return False

    if await _was_domain_submitted_recently(domain, redis_client):
        return False

    return True


async def _send_sandbox_telegram_addendum(alert: dict, ioc_dict: dict) -> None:
    """Telegram addendum when sandbox verdict is malicious."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return

    from garuda.response.alerts import escape_md2

    domain = alert.get("domain", "unknown")
    msg = (
        f"🧪 *Sandbox Verdict: MALICIOUS*\n"
        f"Domain: `{escape_md2(domain)}`\n"
        f"Verdict: `{escape_md2(ioc_dict.get('verdict', 'malicious'))}`\n"
        f"C2 domains: `{escape_md2(', '.join(ioc_dict.get('c2_domains', [])[:5]) or 'none')}`\n"
        f"Report: {escape_md2(ioc_dict.get('report_url', ''))}"
    )
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.post(
                url,
                json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "MarkdownV2"},
            )
    except Exception as exc:
        logger.error("[sandbox] Telegram addendum failed: %s", exc)


async def _trigger_boss_linux_analysis(alert: dict, ioc_dict: dict) -> None:
    """Module 7 enhanced analysis stub for BOSS Linux .desktop payloads."""
    logger.info(
        "[sandbox] BOSS Linux .desktop detected for %s — triggering enhanced analysis",
        alert.get("domain"),
    )
    try:
        from garuda.sources.malwarebazaar import fetch_boss_samples
        samples = await fetch_boss_samples()
        logger.info("[sandbox] BOSS Linux correlation: %d known samples available", len(samples))
    except Exception as exc:
        logger.warning("[sandbox] BOSS Linux analysis stub failed: %s", exc)


async def _enqueue_c2_domain(c2_domain: str, parent_alert_id: Optional[str]) -> None:
    """Seed C2 domain into detection pipeline with score=70."""
    from garuda.database import seed_sandbox_ioc_alert

    await seed_sandbox_ioc_alert(c2_domain, score=70, parent_alert_id=parent_alert_id)


async def run_sandbox_pipeline(
    alert: dict,
    api_key: str,
    redis_client,
    supabase_client,
) -> None:
    """
    Background sandbox analysis pipeline.

    1. should_submit() → if False, return silently
    2. submit_url() → task_id
    3. poll_results() → results
    4. extract_iocs() → ioc_dict
    5. Seed C2 domains into detection queue (score=70)
    6. Insert dropped hashes into compiler_fingerprints
    7. Upsert sandbox_analyses
    8. Update alert sandbox_verdict
    9. Telegram addendum if malicious
    10. BOSS Linux enhanced analysis if .desktop dropped
    """
    if not await should_submit(alert, redis_client):
        return

    domain = alert["domain"].strip().lower()
    url = f"https://{domain}/"
    await _increment_daily_submission(redis_client)
    await _mark_domain_submitted(domain, redis_client)

    task_id = await submit_url(url, api_key)
    if not task_id:
        return

    alert_id = alert.get("id")
    from garuda.database import upsert_sandbox_analysis

    await upsert_sandbox_analysis(
        supabase_client,
        {
            "alert_id": alert_id,
            "domain": domain,
            "task_id": task_id,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "report_url": f"https://app.any.run/tasks/{task_id}",
            "raw_result_url": f"https://app.any.run/tasks/{task_id}",
        },
    )

    results = await poll_results(task_id, api_key)
    if not results:
        return

    ioc_dict = extract_iocs(results, task_id=task_id)
    completed_at = datetime.now(timezone.utc).isoformat()

    for c2_domain in ioc_dict.get("c2_domains", []):
        if c2_domain != domain:
            await _enqueue_c2_domain(c2_domain, str(alert_id) if alert_id else None)

    from garuda.database import insert_compiler_fingerprint

    for idx, sha in enumerate(ioc_dict.get("dropped_hashes", [])):
        filename = (
            ioc_dict.get("dropped_filenames", [None] * len(ioc_dict.get("dropped_hashes", [])))[idx]
            if idx < len(ioc_dict.get("dropped_filenames", []))
            else None
        )
        await insert_compiler_fingerprint(sha, filename=filename, alert_id=alert_id, source="anyrun_sandbox")

    await upsert_sandbox_analysis(
        supabase_client,
        {
            "alert_id": alert_id,
            "domain": domain,
            "task_id": task_id,
            "completed_at": completed_at,
            "verdict": ioc_dict.get("verdict"),
            "c2_domains": ioc_dict.get("c2_domains"),
            "c2_ips": ioc_dict.get("c2_ips"),
            "mitre_techniques": ioc_dict.get("mitre_techniques"),
            "dropped_hashes": ioc_dict.get("dropped_hashes"),
            "report_url": ioc_dict.get("report_url"),
            "is_boss_linux": ioc_dict.get("is_boss_linux", False),
            "raw_result_url": ioc_dict.get("report_url"),
        },
    )

    if supabase_client and alert_id:
        try:
            existing = supabase_client.table("alerts").select("signals").eq("id", alert_id).limit(1).execute()
            signals = {}
            if existing.data:
                signals = existing.data[0].get("signals") or {}
            signals["sandbox_verdict"] = ioc_dict.get("verdict")
            signals["sandbox_report_url"] = ioc_dict.get("report_url")
            supabase_client.table("alerts").update({"signals": signals}).eq("id", alert_id).execute()
        except Exception as exc:
            logger.warning("[sandbox] Failed to update alert sandbox_verdict: %s", exc)

    if ioc_dict.get("verdict") == "malicious":
        await _send_sandbox_telegram_addendum(alert, ioc_dict)

    if ioc_dict.get("is_boss_linux"):
        await _trigger_boss_linux_analysis(alert, ioc_dict)


def schedule_sandbox_analysis(alert: dict) -> None:
    """Fire-and-forget sandbox pipeline from detection engine."""
    if not getattr(settings, "ENABLE_SANDBOX", True):
        return
    api_key = getattr(settings, "ANYRUN_API_KEY", None)
    if not api_key:
        return

    from garuda.cache import get_redis_client
    from garuda.database import get_supabase_client

    redis_client = get_redis_client()
    supabase_client = get_supabase_client()

    try:
        asyncio.get_running_loop().create_task(
            run_sandbox_pipeline(alert, api_key, redis_client, supabase_client)
        )
    except RuntimeError:
        asyncio.run(run_sandbox_pipeline(alert, api_key, redis_client, supabase_client))
