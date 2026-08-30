"""
Telegram Security Notification & Operator Alerting
Dispatches real-time containment alerts and interactive inline authorization keyboards to operators.
"""

import logging
import os
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("brahma.dharma.telegram")


class TelegramNotifier:
    """
    Sends structured security notifications to Telegram channels with actionable inline buttons.
    """

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
    ):
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")

    async def send_alert(
        self,
        text: str,
        action_id: Optional[str] = None,
        include_buttons: bool = False,
    ) -> bool:
        """Send formatted alert message via Telegram Bot API."""
        if not self.bot_token or not self.chat_id:
            logger.info(f"[TELEGRAM SIMULATION]: {text}")
            return True

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload: Dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        if include_buttons and action_id:
            payload["reply_markup"] = {
                "inline_keyboard": [
                    [
                        {"text": "✅ APPROVE (SIGSTOP)", "callback_data": f"/dharma_approve_{action_id}"},
                        {"text": "❌ REJECT", "callback_data": f"/dharma_reject_{action_id}"},
                    ]
                ]
            }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    logger.info("Successfully sent Telegram alert.")
                    return True
                else:
                    logger.warning(f"Telegram API returned status {resp.status_code}: {resp.text}")
                    return False
        except Exception as e:
            logger.warning(f"Failed sending Telegram alert: {e}")
            return False

    async def notify_tier2_auto_execute(
        self,
        action_id: str,
        action_type: str,
        hostname: str,
        target: str,
        ias_score: float,
        evidence_count: int,
    ) -> bool:
        """Notify operator immediately after Tier 2 autonomous execution."""
        msg = (
            f"🚨 *[DHARMA TIER 2 AUTO-EXECUTION]* 🚨\n\n"
            f"*Action ID:* `{action_id}`\n"
            f"*Type:* `{action_type}`\n"
            f"*Host:* `{hostname}`\n"
            f"*Target:* `{target}`\n"
            f"*Trigger IAS:* `{ias_score:.2f}`\n"
            f"*Attribution Evidence:* `{evidence_count}` correlated events\n"
            f"*Status:* `EXECUTED`\n\n"
            f"_Autonomous containment executed under Rule 8 Attribution._"
        )
        return await self.send_alert(msg, action_id=action_id, include_buttons=False)

    async def notify_tier1_sla_expired(
        self,
        action_id: str,
        hostname: str,
        target: str,
        ias_score: float,
    ) -> bool:
        """Alert operator when Tier 1 15-minute SLA countdown has expired."""
        msg = (
            f"⏰ *[DHARMA TIER 1 SLA EXPIRED — ESCALATING]*\n\n"
            f"*Action ID:* `{action_id}`\n"
            f"*Host:* `{hostname}`\n"
            f"*Target:* `{target}`\n"
            f"*Trigger IAS:* `{ias_score:.2f}`\n\n"
            f"_15-minute operator approval countdown expired. Auto-escalating to Tier 2 decision engine._"
        )
        return await self.send_alert(msg, action_id=action_id, include_buttons=True)

    async def notify_execution_failed(
        self,
        action_id: str,
        action_type: str,
        hostname: str,
        target: str,
        error_detail: str,
    ) -> bool:
        """Immediate alert on any containment action failure."""
        msg = (
            f"⚠️ *[DHARMA EXECUTION FAILED]*\n\n"
            f"*Action ID:* `{action_id}`\n"
            f"*Type:* `{action_type}`\n"
            f"*Host:* `{hostname}`\n"
            f"*Target:* `{target}`\n"
            f"*Error:* `{error_detail}`\n\n"
            f"_Manual operator intervention required._"
        )
        return await self.send_alert(msg, action_id=action_id, include_buttons=True)


_notifier = TelegramNotifier()


def get_telegram_notifier() -> TelegramNotifier:
    return _notifier
