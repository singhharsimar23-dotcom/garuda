"""
Anomaly Alert Publisher
Broadcasts detected anomalies to Supabase Realtime, generates rate-limited LLM narratives via Groq,
and dispatches formatted Telegram defense alerts.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import urllib.request
import urllib.parse
from typing import Any, Dict, List, Optional

from ..config import AxiomSettings, get_settings
from ..models.telemetry import AnomalyLevel, IASResult

logger = logging.getLogger("axiom.services.publisher")

# In-memory daily Groq counter (resets daily)
_daily_groq_counter: Dict[str, int] = {"date": "", "count": 0}


def _get_ist_timestamp() -> str:
    """Returns formatted current Indian Standard Time (IST = UTC+5:30)."""
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    now_ist = datetime.now(ist_tz)
    return now_ist.strftime("%Y-%m-%d %H:%M:%S IST")


async def generate_ai_narrative(
    settings: AxiomSettings,
    agent_id: str,
    hostname: str,
    ias_result: IASResult,
) -> Optional[str]:
    """
    Generates a concise physics anomaly narrative via Gemini API or Groq LLM under strict rate-limit budget.
    """
    prompt = (
        f"Analyze physical anomaly on host {hostname} (Agent ID: {agent_id}).\n"
        f"IAS Score: {ias_result.score} (Level: {ias_result.level.value}, Calibrated: {ias_result.calibrated})\n"
        f"Top Divergent Channels: {ias_result.top_divergent_channels}\n"
        f"Write a 2-sentence physics-informed explanation of what microarchitectural invariant was violated."
    )

    # 1. Prefer Gemini API if GEMINI_API_KEY is configured
    if settings.gemini_api_key:
        try:
            # Use google.genai or standard Gemini REST endpoint
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 150}
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                if 200 <= resp.status < 300:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                    text = resp_json["candidates"][0]["content"]["parts"][0]["text"].strip()
                    logger.info("Generated anomaly narrative via Google Gemini API.")
                    return text
        except Exception as e:
            logger.warning(f"Gemini API narrative generation failed: {e}")

    # 2. Fallback to Groq if configured
    if not settings.feature_flag_groq or not settings.groq_api_key:
        return "Microarchitectural side-channel deviation detected across physical execution channels."

    # Check daily budget
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if _daily_groq_counter["date"] != today_str:
        _daily_groq_counter["date"] = today_str
        _daily_groq_counter["count"] = 0

    if _daily_groq_counter["count"] >= settings.groq_daily_limit:
        logger.warning(f"Groq daily rate limit budget reached ({_daily_groq_counter['count']}/{settings.groq_daily_limit}). Skipping narrative generation.")
        return "Microarchitectural side-channel deviation detected. (AI narrative budget reached for today)."

    try:
        from groq import AsyncGroq
        client = AsyncGroq(api_key=settings.groq_api_key)

        response = await client.chat.completions.create(
            model=settings.groq_preferred_model,
            messages=[
                {"role": "system", "content": "You are GARUDA AXIOM Physics Intelligence Engine. Be precise, technical, and concise."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=150,
            temperature=0.2,
        )

        _daily_groq_counter["count"] += 1
        narrative = response.choices[0].message.content.strip()
        logger.info(f"Generated Groq anomaly narrative (Budget used: {_daily_groq_counter['count']}/{settings.groq_daily_limit})")
        return narrative
    except Exception as e:
        logger.warning(f"Groq narrative generation failed: {e}")
        return "Anomalous execution pattern exceeding calibrated Gaussian energy invariants."


def send_telegram_alert(settings: AxiomSettings, message: str) -> bool:
    """Dispatches markdown formatted message to configured Telegram channel."""
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        logger.debug("Telegram credentials not configured. Skipping alert dispatch.")
        return False

    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    payload = {
        "chat_id": settings.telegram_chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        logger.warning(f"Failed to send Telegram alert: {e}")
        return False


async def publish_anomaly_alert(
    agent_id: str,
    hostname: str,
    ias_result: IASResult,
    settings: Optional[AxiomSettings] = None,
) -> Dict[str, Any]:
    """
    Coordinates anomaly alerting across Supabase Realtime and Telegram.
    """
    settings = settings or get_settings()
    timestamp_ist = _get_ist_timestamp()
    alert_id = f"alert-{agent_id}-{int(datetime.now(timezone.utc).timestamp())}"

    # Generate LLM narrative if MEDIUM/CRITICAL
    narrative = None
    if ias_result.level in (AnomalyLevel.MEDIUM, AnomalyLevel.CRITICAL):
        narrative = await generate_ai_narrative(settings, agent_id, hostname, ias_result)

    # Format Telegram Message
    telegram_sent = False
    calibrated_str = "CALIBRATED" if ias_result.calibrated else "UNCALIBRATED"
    threshold_val = ias_result.threshold_used.get(ias_result.level.value, 3.0)

    if ias_result.level == AnomalyLevel.MEDIUM:
        top_ch = ias_result.top_divergent_channels[0] if ias_result.top_divergent_channels else {"channel": "rapl_pkg", "delta_from_baseline": 0}
        ch_name = top_ch.get("channel", "rapl_pkg")
        delta_mw = abs(float(top_ch.get("delta_from_baseline", 0.0))) / 1000.0

        telegram_msg = (
            f"⚠️ *GARUDA MEDIUM ALERT* — `{timestamp_ist}`\n"
            f"*Asset:* `{hostname}` (`{agent_id}`)\n"
            f"*IAS Score:* `{ias_result.score:.2f}` ({calibrated_str} → `{threshold_val}`)\n"
            f"*Top channel:* `{ch_name}` = `{delta_mw:.0f}mW` deviation\n"
            f"*BRAHMA:* Execution (Possible) — see `/sitrep`"
        )
        telegram_sent = send_telegram_alert(settings, telegram_msg)

    elif ias_result.level == AnomalyLevel.CRITICAL:
        ch_lines = ""
        for ch in ias_result.top_divergent_channels[:2]:
            ch_lines += f"  • `{ch.get('channel')}`: `{ch.get('score', 0.0):.2f}`\n"

        telegram_msg = (
            f"🚨 *GARUDA CRITICAL ALERT* — `{timestamp_ist}`\n"
            f"*Asset:* `{hostname}` (`{agent_id}`)\n"
            f"*IAS Score:* `{ias_result.score:.2f}` (THRESHOLD: `{threshold_val}` | {calibrated_str})\n"
            f"*Top Divergent Channels:*\n{ch_lines}"
            f"*Physics Assessment:*\n_{narrative or 'Severe microarchitectural anomaly.'}_\n\n"
            f"*Action:* Automated DHARMA Trigger Dispatched."
        )
        telegram_sent = send_telegram_alert(settings, telegram_msg)

    # Publish to Supabase Realtime / DB Mirror if configured
    if settings.feature_flag_supabase_realtime and settings.supabase_url and settings.supabase_service_key:
        try:
            from supabase import create_client
            sb = create_client(settings.supabase_url, settings.supabase_service_key)
            sb.table("anomaly_alerts_mirror").insert({
                "alert_id": alert_id,
                "agent_id": agent_id,
                "hostname": hostname,
                "ias_score": ias_result.score,
                "anomaly_level": ias_result.level.value,
                "top_channels": ias_result.top_divergent_channels,
                "narrative": narrative,
            }).execute()
        except Exception as e:
            logger.warning(f"Failed to mirror alert to Supabase: {e}")

    return {
        "alert_id": alert_id,
        "narrative": narrative,
        "telegram_sent": telegram_sent,
    }
