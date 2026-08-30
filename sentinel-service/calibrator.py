"""
Self-Calibrating Threshold Manager for SENTINEL
Continuously tunes per-host IAS thresholds based on 7-day true/false positive outcomes in dharma_action_log.
"""

from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
import httpx

try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings


logger = logging.getLogger("sentinel.calibrator")


class ThresholdCalibrator:
    """
    Evaluates containment feedback and automatically adjusts per-host sensitivity.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._host_thresholds: Dict[str, float] = {}

    def get_host_threshold(self, hostname: str) -> float:
        return self._host_thresholds.get(hostname, self.settings.fusion_medium_threshold)

    async def calibrate_host_thresholds(
        self,
        dharma_actions_last_7d: List[Dict[str, Any]],
        sample_counts: Optional[Dict[str, int]] = None,
        supabase_client=None,
    ) -> List[Dict[str, Any]]:
        """
        Calculates tp_rate, fp_rate, fn_rate per host and adjusts thresholds.
        """
        actions_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for act in dharma_actions_last_7d:
            host = act.get("hostname", "default")
            actions_by_host.setdefault(host, []).append(act)

        adjustments = []

        for host, actions in actions_by_host.items():
            approved = [a for a in actions if a.get("status") in ("APPROVED", "EXECUTED")]
            rejected = [a for a in actions if a.get("status") == "REJECTED"]

            total_actions = len(actions)
            if total_actions == 0:
                continue

            fp_rate = round(len(rejected) / total_actions, 4)
            tp_rate = round(len(approved) / total_actions, 4)
            fn_rate = 0.05  # baseline estimation

            current_thresh = self.get_host_threshold(host)
            new_thresh = current_thresh
            adjustment_reason = "THRESHOLD_STABLE"

            # Rule 1: High False Positive Rate (> 0.30) -> Raise threshold +0.5
            if fp_rate > 0.30:
                new_thresh = round(current_thresh + 0.5, 2)
                adjustment_reason = "HIGH_FP_RATE_RAISED_THRESHOLD"
                await self._send_telegram_alert(
                    f"⚠️ High FP rate ({fp_rate*100:.1f}%) on `{host}`. Threshold raised {current_thresh} -> {new_thresh}. Manual calibration recommended."
                )

            # Rule 2: High Accuracy (FP < 0.05, TP > 0.80, samples >= 30) -> Lower threshold -0.25
            samples = (sample_counts or {}).get(host, 35)
            if fp_rate < 0.05 and tp_rate > 0.80 and samples >= 30:
                new_thresh = max(1.5, round(current_thresh - 0.25, 2))
                adjustment_reason = "HIGH_ACCURACY_LOWERED_THRESHOLD"
                await self._send_telegram_alert(
                    f"✅ High accuracy (TP={tp_rate*100:.1f}%) on `{host}`. Threshold lowered {current_thresh} -> {new_thresh}."
                )

            self._host_thresholds[host] = new_thresh

            log_entry = {
                "hostname": host,
                "tp_rate": tp_rate,
                "fp_rate": fp_rate,
                "fn_rate": fn_rate,
                "old_threshold": current_thresh,
                "new_threshold": new_thresh,
                "adjustment_reason": adjustment_reason,
            }
            adjustments.append(log_entry)

            # Persist to Supabase
            if supabase_client:
                try:
                    supabase_client.table("calibration_log").insert(log_entry).execute()
                except Exception as e:
                    logger.debug(f"Failed writing calibration_log to Supabase: {e}")

        logger.info(f"Threshold calibration completed across {len(adjustments)} monitored hosts.")
        return adjustments

    async def _send_telegram_alert(self, msg: str) -> None:
        """Send calibration notification to operator Telegram channel."""
        if not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.info(f"[TELEGRAM CALIBRATION]: {msg}")
            return
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(url, json={
                    "chat_id": self.settings.telegram_chat_id,
                    "text": msg,
                    "parse_mode": "Markdown",
                })
        except Exception as e:
            logger.debug(f"Telegram alert failed: {e}")


_calibrator = ThresholdCalibrator()


def get_threshold_calibrator() -> ThresholdCalibrator:
    return _calibrator
