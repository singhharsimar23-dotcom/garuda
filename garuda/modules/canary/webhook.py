"""
Canary webhook processing — scoring, alerting, persona graph updates.

Separated from API routes so unit tests avoid loading the full FastAPI router graph.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

import httpx

from garuda.config import settings

logger = logging.getLogger("garuda.modules.canary.webhook")

PAKISTANI_ISP_ASNS: dict[int, str] = {
    17557: "PTCL",
    63948: "StormFiber",
    45595: "Transworld",
    56096: "Nayatel",
    24499: "Cybernet",
}

IST = ZoneInfo("Asia/Kolkata")
GREYNOISE_MONTHLY_BUDGET = 50
GREYNOISE_BUDGET_KEY = "garuda:greynoise:queries:{month}"


class CanaryWebhookError(Exception):
    """Base error for canary webhook processing."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class CanaryTokenNotFoundError(CanaryWebhookError):
    def __init__(self):
        super().__init__("Unknown canary token", status_code=404)


def _parse_asn(as_field: Optional[str]) -> tuple[Optional[int], str]:
    if not as_field:
        return None, ""
    match = re.search(r"AS(\d+)", str(as_field), re.IGNORECASE)
    asn_num = int(match.group(1)) if match else None
    org = re.sub(r"^AS\d+\s*", "", str(as_field)).strip()
    return asn_num, org


async def lookup_ip_asn(src_ip: str) -> dict:
    """Classify src_ip ASN via ip-api.com (free, no auth)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{src_ip}",
                params={"fields": "as,org,country,isp,status"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
    except Exception as exc:
        logger.warning("[canary] ip-api lookup failed for %s: %s", src_ip, exc)
    return {}


async def greynoise_targeted(src_ip: str, redis_client) -> bool:
    if not getattr(settings, "GREYNOISE_API_KEY", None):
        return False

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    budget_key = GREYNOISE_BUDGET_KEY.format(month=month)

    if redis_client:
        try:
            count = int(await redis_client.get(budget_key) or 0)
            if count >= GREYNOISE_MONTHLY_BUDGET:
                return False
            await redis_client.incr(budget_key)
            await redis_client.expire(budget_key, 31 * 86400)
        except Exception:
            pass

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{src_ip}",
                headers={"key": settings.GREYNOISE_API_KEY},
            )
            if resp.status_code == 200:
                return resp.json().get("noise") is False
    except Exception as exc:
        logger.debug("[canary] GreyNoise lookup failed: %s", exc)
    return False


async def score_canary_fire(
    src_ip: str,
    supabase_client,
    redis_client=None,
) -> tuple[int, dict]:
    score = 0
    context: dict[str, Any] = {"src_ip": src_ip}

    asn_data = await lookup_ip_asn(src_ip)
    asn_num, asn_org = _parse_asn(asn_data.get("as"))
    context["asn"] = asn_num
    context["asn_org"] = asn_org or asn_data.get("org") or asn_data.get("isp") or "unknown"
    context["country"] = asn_data.get("country")

    if asn_num in PAKISTANI_ISP_ASNS:
        score += 40
        context["pakistani_isp"] = PAKISTANI_ISP_ASNS[asn_num]

    from garuda.database import ip_in_passive_dns, ip_matches_confirmed_alert

    if await ip_matches_confirmed_alert(src_ip, supabase_client):
        score += 60
        context["infra_match"] = True

    if await ip_in_passive_dns(src_ip, supabase_client):
        score += 35
        context["pdns_match"] = True

    if await greynoise_targeted(src_ip, redis_client):
        score += 20
        context["greynoise_targeted"] = True

    return score, context


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    return "LOG"


def build_canary_alert_text(
    token_record: dict,
    payload: dict,
    score: int,
    context: dict,
) -> str:
    src_ip = context.get("src_ip", "unknown")
    useragent = payload.get("useragent") or payload.get("user_agent") or "unknown"
    token_type = payload.get("token_type") or token_record.get("token_type", "unknown")
    document_theme = token_record.get("document_theme") or token_record.get("memo", "unknown")
    token_id = token_record.get("id", "unknown")

    fired_at = payload.get("time") or datetime.now(timezone.utc).isoformat()
    try:
        dt = datetime.fromisoformat(str(fired_at).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ist_time = dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ist_time = str(fired_at)

    asn = context.get("asn")
    asn_org = context.get("asn_org", "unknown")
    pakistani_isp = context.get("pakistani_isp")
    asn_classification = pakistani_isp if pakistani_isp else "unknown"

    return (
        "🔴 CANARY DOCUMENT FIRED — ATTRIBUTION SIGNAL\n"
        f"Document: {document_theme} (type: {token_type})\n"
        f"Egress IP: {src_ip} — {asn_org} (AS{asn})\n"
        "Note: Egress IP is where the opener's traffic exited — likely VPN/proxy, not physical location.\n"
        f"User-Agent: {useragent}\n"
        f"Time: {ist_time} IST\n"
        f"ASN classification: {asn_classification}\n"
        f"Score: {score}/130\n"
        f"/canary_correlate_{token_id} — correlate with passive DNS and infra records\n"
        "⚠️ Egress IP ≠ operator location. Requires correlation analysis."
    )


async def process_canary_webhook(
    payload: dict,
    supabase_client,
    telegram_client=None,
    redis_client=None,
) -> dict:
    token_value = (
        payload.get("token")
        or payload.get("canarytoken")
        or payload.get("manage_url", "").rsplit("/", 1)[-1]
    )
    src_ip = payload.get("src_ip") or payload.get("ip") or payload.get("src")

    if not token_value:
        raise CanaryWebhookError("Missing token in payload")
    if not src_ip:
        raise CanaryWebhookError("Missing src_ip in payload")

    from garuda.database import (
        get_canary_token_by_value,
        increment_canary_fire_count,
        insert_canary_fire,
        upsert_persona_node,
    )

    token_record = await get_canary_token_by_value(str(token_value), supabase_client)
    if not token_record:
        raise CanaryTokenNotFoundError()

    score, context = await score_canary_fire(src_ip, supabase_client, redis_client)
    severity = "CRITICAL" if context.get("infra_match") else severity_from_score(score)

    fire_record = await insert_canary_fire(
        supabase_client,
        {
            "token_id": token_record["id"],
            "src_ip": src_ip,
            "src_asn": context.get("asn"),
            "src_org": context.get("asn_org"),
            "useragent": payload.get("useragent") or payload.get("user_agent"),
            "score": score,
            "alert_dispatched": severity in {"CRITICAL", "HIGH"},
        },
    )

    await increment_canary_fire_count(token_record["id"], supabase_client)

    if severity == "CRITICAL":
        alert_text = build_canary_alert_text(token_record, payload, score, context)
        if telegram_client:
            await telegram_client(alert_text)
        elif settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    await client.post(
                        url,
                        json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": alert_text},
                    )
            except Exception as exc:
                logger.error("[canary] Telegram dispatch failed: %s", exc)

        await upsert_persona_node(
            node_type="IP",
            value=src_ip,
            confidence=min(1.0, score / 130.0),
            source="CANARY_FIRE",
            metadata={"token_id": token_record["id"], "score": score},
        )
    elif severity == "HIGH":
        logger.warning("[canary] HIGH severity fire (score=%d) from %s", score, src_ip)
    else:
        logger.info("[canary] LOG-only fire (score=%d) from %s", score, src_ip)

    return {
        "status": "processed",
        "severity": severity,
        "score": score,
        "fire_id": fire_record.get("id"),
    }
