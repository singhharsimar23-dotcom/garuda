import logging
import re
from typing import Any, Dict, Optional
import httpx

from garuda.config import settings

logger = logging.getLogger("garuda.response.alerts")

TELEGRAM_API_BASE = "https://api.telegram.org/bot{TOKEN}"

# Characters requiring backslash escaping in Telegram MarkdownV2
MARKDOWN_V2_SPECIAL_CHARS = r"_*[]()~`>#+-=|{}.!"


def escape_md2(text: Any) -> str:
    """Escape all MarkdownV2 special chars. Missing one -> Telegram 400."""
    return re.sub(r'([_*\[\]()~`>#\+\-=|{}\.!])', r'\\\1', str(text))


# Maintain alias for compatibility
escape_markdown_v2 = escape_md2


async def dispatch_alert(alert: Dict[str, Any], level: Optional[str] = None) -> bool:
    """
    Dispatch multi-channel threat intelligence alerts (Telegram MarkdownV2, Slack, Teams).

    Args:
        alert: Alert dictionary containing domain, score, sector, signals, etc.
        level: Optional severity string ('CRITICAL', 'MEDIUM', 'INFO').

    Returns:
        bool: True if at least one alert destination was notified successfully.
    """
    domain = alert.get("domain", "unknown-domain")
    score = alert.get("score", 0)
    sector = alert.get("sector", "Critical Infrastructure")
    signals = alert.get("signals", {})
    alert_id = str(alert.get("id", "pending"))[:8]

    if not level:
        if score >= settings.SCORE_THRESHOLD_CRITICAL:
            level = "CRITICAL"
        elif score >= settings.SCORE_THRESHOLD_MEDIUM:
            level = "MEDIUM"
        else:
            level = "LOG"

    registrar = alert.get("registrar") or signals.get("registrar") or "Unknown"
    age_days = signals.get("domain_age_days")
    age_str = f"{age_days}" if age_days is not None else "N/A"

    nic_match = signals.get("nic_match") or "None"
    nic_similarity = float(signals.get("nic_similarity", 0.0))
    similarity_pct_str = f"{nic_similarity:.0%}"

    dispatched = False

    # --------------------------------------------------------------------------
    # 1. Telegram Dispatch with MarkdownV2 and Inline Buttons
    # --------------------------------------------------------------------------
    if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
        telegram_text = (
            f"🚨 *GARUDA ALERT* \\- {escape_md2(level)}\n"
            f"Domain: `{escape_md2(domain)}`\n"
            f"Score: {escape_md2(score)}/100 \\| Sector: {escape_md2(sector)}\n"
            f"Registrar: {escape_md2(registrar)} \\| Age: {escape_md2(age_str)}d\n"
            f"Similarity to: {escape_md2(nic_match)} \\({escape_md2(similarity_pct_str)}\\)"
        )

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Confirm", "callback_data": f"confirm:{alert_id}"},
                    {"text": "❌ Reject", "callback_data": f"reject:{alert_id}"},
                    {"text": "🔍 Investigate", "callback_data": f"investigate:{alert_id}"},
                ]
            ]
        }

        tg_url = TELEGRAM_API_BASE.format(TOKEN=settings.TELEGRAM_BOT_TOKEN) + "/sendMessage"
        tg_payload = {
            "chat_id": settings.TELEGRAM_CHAT_ID,
            "text": telegram_text,
            "parse_mode": "MarkdownV2",
            "reply_markup": keyboard,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(tg_url, json=tg_payload)
                if res.status_code == 200:
                    dispatched = True
                else:
                    logger.error(f"[alerts] Telegram dispatch failed ({res.status_code}): {res.text}")
        except Exception as e:
            logger.error(f"[alerts] Telegram dispatch error: {e}")

    # --------------------------------------------------------------------------
    # 2. Slack Webhook Dispatch
    # --------------------------------------------------------------------------
    if settings.SLACK_WEBHOOK_URL:
        slack_payload = {
            "text": (
                f":rotating_light: *GARUDA ALERT — {level}*\n"
                f"*Domain:* `{domain}` | *Score:* {score}/100\n"
                f"*Sector:* {sector} | *Registrar:* {registrar} (Age: {age_str}d)\n"
                f"*Similarity:* {nic_match} ({similarity_pct_str})"
            )
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(settings.SLACK_WEBHOOK_URL, json=slack_payload)
                if res.status_code == 200:
                    dispatched = True
        except Exception as e:
            logger.error(f"[alerts] Slack webhook error: {e}")

    # --------------------------------------------------------------------------
    # 3. Microsoft Teams Webhook Dispatch
    # --------------------------------------------------------------------------
    if settings.TEAMS_WEBHOOK_URL:
        teams_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": f"GARUDA {level} Alert: {domain}",
            "themeColor": "D9534F" if level == "CRITICAL" else "F0AD4E",
            "title": f"🚨 GARUDA {level} Alert: {domain} (Score: {score})",
            "text": f"Targeting {sector}. Registrar: {registrar}, Age: {age_str} days, Match: {nic_match} ({similarity_pct_str}).",
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(settings.TEAMS_WEBHOOK_URL, json=teams_payload)
                if res.status_code == 200:
                    dispatched = True
        except Exception as e:
            logger.error(f"[alerts] Teams webhook error: {e}")

    return dispatched
