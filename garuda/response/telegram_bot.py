import logging
import re
from typing import Any, Dict, Optional
from fastapi import APIRouter, Request
import httpx

from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.response.alerts import TELEGRAM_API_BASE, escape_markdown_v2
from garuda.response.analyst import confirm_alert, reject_alert, whitelist_domain_action

logger = logging.getLogger("garuda.response.telegram_bot")

router = APIRouter(prefix="/api", tags=["Telegram Bot"])


async def send_telegram_reply(chat_id: Any, text: str) -> bool:
    """Send MarkdownV2 formatted reply back to Telegram chat."""
    if not settings.TELEGRAM_BOT_TOKEN:
        return False

    url = TELEGRAM_API_BASE.format(TOKEN=settings.TELEGRAM_BOT_TOKEN) + "/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            return resp.status_code == 200
    except Exception as e:
        logger.error(f"[telegram_bot] Error sending reply: {e}")
        return False


async def handle_telegram_update(update: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process incoming Telegram Bot update payloads and route command interactions.

    Supported Commands:
        - /confirm_{id}: Mark alert as confirmed malicious.
        - /reject_{id} [reason]: Mark alert as false positive.
        - /investigate_{id}: Retrieve deep OSINT and graph telemetry for alert.
        - /status: Retrieve active tension and platform operational status.
        - /cluster_{id}: Inspect multi-domain campaign cluster members.
        - /whitelist_{id}: Whitelist target domain.
        - /stats: Aggregated SOC operational statistics.
    """
    message = update.get("message", {})
    text = str(message.get("text", "")).strip()
    chat_id = message.get("chat", {}).get("id", settings.TELEGRAM_CHAT_ID)
    user_id = message.get("from", {}).get("username") or message.get("from", {}).get("id")
    analyst_tag = f"telegram:{user_id}"

    if not text.startswith("/"):
        return {"status": "ignored"}

    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    reply_text = ""

    # 1. /confirm_{id}
    if cmd.startswith("/confirm_"):
        alert_id = cmd.replace("/confirm_", "")
        res = await confirm_alert(alert_id, analyst_id=analyst_tag)
        reply_text = f"✅ *Alert Confirmed Malicious*\nAlert ID: `{escape_markdown_v2(alert_id)}`\nAnalyst: `{escape_markdown_v2(analyst_tag)}`"

    # 2. /reject_{id}
    elif cmd.startswith("/reject_"):
        alert_id = cmd.replace("/reject_", "")
        reason = arg if arg else "False positive / benign infrastructure"
        res = await reject_alert(alert_id, reason=reason, analyst_id=analyst_tag)
        reply_text = f"❌ *Alert Rejected as False Positive*\nAlert ID: `{escape_markdown_v2(alert_id)}`\nReason: {escape_markdown_v2(reason)}"

    # 3. /investigate_{id}
    elif cmd.startswith("/investigate_"):
        alert_id = cmd.replace("/investigate_", "")
        client = get_supabase_client()
        alert_record = None
        if client:
            try:
                res = client.table("alerts").select("*").ilike("id", f"{alert_id}%").limit(1).execute()
                if res.data:
                    alert_record = res.data[0]
            except Exception:
                pass

        if alert_record:
            domain = alert_record.get("domain", "unknown")
            score = alert_record.get("score", 0)
            sector = alert_record.get("sector", "Unknown")
            ip = alert_record.get("hosting_ip", "N/A")
            reply_text = (
                f"🔍 *Investigation Dossier*\n"
                f"Domain: `{escape_markdown_v2(domain)}`\n"
                f"Threat Score: `{escape_markdown_v2(score)}/100`\n"
                f"Sector: {escape_markdown_v2(sector)}\n"
                f"Resolved IP: `{escape_markdown_v2(ip)}`\n"
                f"Action: /confirm_{escape_markdown_v2(alert_id)} /reject_{escape_markdown_v2(alert_id)}"
            )
        else:
            reply_text = f"🔍 *Investigation*: Alert `{escape_markdown_v2(alert_id)}` queued for deep telemetry retrieval."
            reply_text = escape_markdown_v2(reply_text)

    # 4. /status
    elif cmd == "/status":
        conflict_status = "ENABLED 🔴" if settings.CONFLICT_MODE else "STANDBY 🟢"
        reply_text = (
            f"🛡️ *GARUDA CTI Engine Status*\n"
            f"Environment: `{escape_markdown_v2(settings.ENVIRONMENT)}`\n"
            f"Conflict Mode: {escape_markdown_v2(conflict_status)}\n"
            f"Tension Threshold: `{escape_markdown_v2(settings.TENSION_THRESHOLD)}`"
        )

    # 5. /stats
    elif cmd == "/stats":
        reply_text = (
            f"📊 *SOC Operations Summary (24h)*\n"
            f"• Tier 1 Signatures Monitored: `{escape_markdown_v2(len(settings.TIER_1_PATTERNS))}`\n"
            f"• Critical Score Threshold: `{escape_markdown_v2(settings.SCORE_THRESHOLD_CRITICAL)}`\n"
            f"• Honeypot Decoys Active: `4`\n"
            f"• Platform Engine: `GARUDA v0.1.0`"
        )

    # 6. /whitelist_{id} or /whitelist [domain]
    elif cmd.startswith("/whitelist"):
        target = cmd.replace("/whitelist_", "") if "_" in cmd else arg
        reason = "Analyst authorized exception"
        await whitelist_domain_action(target, reason=reason, analyst_id=analyst_tag)
        reply_text = f"⚪ *Domain Whitelisted*\nTarget: `{escape_markdown_v2(target)}`"

    else:
        reply_text = (
            "ℹ️ *Unknown Command*\n"
            "Available commands: /status, /stats, /investigate_<id>, /confirm_<id>, /reject_<id>"
        )

    if chat_id and reply_text:
        await send_telegram_reply(chat_id, reply_text)

    return {"status": "ok", "command": cmd}


@router.post("/telegram_webhook")
async def telegram_webhook_endpoint(request: Request) -> Dict[str, Any]:
    """FastAPI webhook endpoint for receiving Telegram updates."""
    try:
        update_data = await request.json()
        return await handle_telegram_update(update_data)
    except Exception as e:
        logger.error(f"[telegram_bot] Error handling webhook POST: {e}")
        return {"status": "error", "message": str(e)}
