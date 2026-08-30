"""
Daily Health Check & Alerting Script (Cron Job 2)
Probes all 3 microservices (AXIOM, BRAHMA, UTNE) and dispatches Telegram notification on failure.
"""

import json
import logging
import os
import sys
import urllib.error
import urllib.request
from typing import Dict, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("garuda.maintenance.health")


def check_service(url: str, name: str) -> Tuple[bool, str]:
    """Pings a service health endpoint."""
    if not url:
        return (True, "URL_NOT_CONFIGURED")

    target = f"{url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "GARUDA-Cron-Health/0.1"})
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            if 200 <= resp.status < 300:
                return (True, f"HTTP {resp.status}")
            return (False, f"HTTP {resp.status}")
    except Exception as e:
        return (False, str(e))


def send_telegram_alert(bot_token: str, chat_id: str, message: str) -> None:
    """Dispatches Telegram alert to operator chat."""
    if not bot_token or not chat_id:
        logger.warning("Telegram credentials not set. Alert logged to stdout only.")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            logger.info("Telegram alert sent successfully.")
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")


def run_health_check() -> bool:
    """Runs health check over all 3 services."""
    services = {
        "AXIOM (Service 1)": os.environ.get("NORTHFLANK_AXIOM_URL"),
        "BRAHMA+DHARMA (Service 2)": os.environ.get("NORTHFLANK_BRAHMA_URL"),
        "UTNE (Narrative Service)": os.environ.get("RENDER_UTNE_URL") or os.environ.get("KOYEB_UTNE_URL"),
    }

    all_healthy = True
    failed_services = []

    for name, url in services.items():
        if url:
            healthy, detail = check_service(url, name)
            if not healthy:
                all_healthy = False
                failed_services.append(f"❌ <b>{name}</b>: {detail}")
                logger.error(f"Health check failed for {name}: {detail}")
            else:
                logger.info(f"✅ {name}: {detail}")

    if not all_healthy:
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        msg = "🚨 <b>GARUDA PRODUCTION HEALTH ALERT</b>\n\n" + "\n".join(failed_services)
        send_telegram_alert(bot_token, chat_id, msg)

    return all_healthy


if __name__ == "__main__":
    success = run_health_check()
    sys.exit(0 if success else 1)
