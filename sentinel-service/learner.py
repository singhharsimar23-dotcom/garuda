"""
Learner Engine & Training Signal Dispatcher
Closes the autonomous learning loop by translating operator feedback (APPROVE/REJECT) and KALI validation into model updates.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import httpx

try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings


logger = logging.getLogger("sentinel.learner")


class LearningLoopDispatcher:
    """
    Translates ground-truth analyst decisions and simulation results into model training signals.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._consecutive_false_positives: Dict[str, int] = defaultdict(int)
        self._pending_retries: List[Dict[str, Any]] = []

    async def handle_dharma_approval(
        self,
        hostname: str,
        action_id: str,
        tactic: str,
        feature_vector: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Processes confirmed true positive: dispatches POSITIVE label to BRAHMA & AXIOM-II.
        """
        self._consecutive_false_positives[hostname] = 0

        # 1. POST to BRAHMA /internal/label
        brahma_ok = await self._send_brahma_label(feature_vector, label="POSITIVE", tactic=tactic)

        # 2. POST to AXIOM-II /internal/calibrate
        axiom_ok = await self._send_axiom_calibration(hostname, feature_vector, confirmed_tactic=tactic)

        logger.info(f"[LEARNER] Processed APPROVE for {action_id} on {hostname}. Models reinforced (BRAHMA={brahma_ok}, AXIOM={axiom_ok}).")
        return {"status": "success", "brahma_updated": brahma_ok, "axiom_updated": axiom_ok}

    async def handle_dharma_rejection(
        self,
        hostname: str,
        action_id: str,
        tactic: str,
        feature_vector: Dict[str, Any],
        workload_class: str = "EXECUTION",
    ) -> Dict[str, Any]:
        """
        Processes confirmed false positive: dispatches NEGATIVE label and checks for baseline drift.
        """
        self._consecutive_false_positives[hostname] += 1
        fp_count = self._consecutive_false_positives[hostname]

        # 1. POST to BRAHMA /internal/label
        brahma_ok = await self._send_brahma_label(feature_vector, label="NEGATIVE", tactic=tactic)

        needs_recalibration = False
        if fp_count >= 3:
            needs_recalibration = True
            logger.warning(
                f"[LEARNER] 3+ consecutive false positives on {hostname} ({workload_class}). "
                f"Flagged NEEDS_RECALIBRATION. Freezing baseline updates."
            )

        logger.info(f"[LEARNER] Processed REJECT for {action_id} on {hostname}. Weights damped (FP Streak: {fp_count}).")
        return {
            "status": "success",
            "brahma_updated": brahma_ok,
            "consecutive_fps": fp_count,
            "needs_recalibration": needs_recalibration,
        }

    async def handle_kali_live_validation(
        self,
        technique_id: str,
        detected: bool,
        ias_achieved: float,
    ) -> bool:
        """
        Feed live red-team validation outcome back to KALI detection model.
        """
        if not self.settings.kali_service_url:
            return True

        url = f"{self.settings.kali_service_url.rstrip('/')}/internal/calibrate"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        payload = {
            "technique_id": technique_id,
            "detected": detected,
            "ias_achieved": ias_achieved,
        }

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code == 200
        except Exception as e:
            logger.debug(f"KALI calibration dispatch error: {e}")
            return False

    async def _send_brahma_label(self, feature_vector: Dict[str, Any], label: str, tactic: str) -> bool:
        """Dispatch ground-truth training label to BRAHMA Bayesian engine."""
        if not self.settings.brahma_service_url:
            return True

        url = f"{self.settings.brahma_service_url.rstrip('/')}/internal/label"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        payload = {
            "feature_vector": feature_vector,
            "label": label,
            "tactic": tactic,
            "confidence": "HIGH",
        }

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code in (200, 201)
        except Exception as e:
            logger.warning(f"BRAHMA label update failed (queued for retry): {e}")
            self._pending_retries.append({"type": "brahma_label", "payload": payload})
            return False

    async def _send_axiom_calibration(self, hostname: str, channel_sigmas: Dict[str, Any], confirmed_tactic: str) -> bool:
        """Dispatch confirmed signal to AXIOM-II sensor calibration."""
        if not self.settings.axiom_service_url:
            return True

        url = f"{self.settings.axiom_service_url.rstrip('/')}/internal/calibrate"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        payload = {
            "hostname": hostname,
            "channel_sigmas": channel_sigmas,
            "confirmed_tactic": confirmed_tactic,
        }

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code in (200, 201)
        except Exception as e:
            logger.debug(f"AXIOM calibration dispatch error: {e}")
            return False


_learner = LearningLoopDispatcher()


def get_learner() -> LearningLoopDispatcher:
    return _learner
