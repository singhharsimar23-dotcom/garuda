"""
Offline IAS Computer for Air-Gapped Operation
Executes deterministic Gaussian KL divergence calculations against local SQLite baseline with baselining safety gates.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import math
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("garuda.usb.offline_ias")

CHANNEL_WEIGHTS: Dict[str, float] = {
    "rapl_pkg": 0.35,
    "rapl_core": 0.15,
    "perf_instr": 0.20,
    "perf_cache": 0.10,
    "entropy": 0.10,
    "schedstat": 0.10,
}

EPSILON = 1e-6


def compute_gaussian_kl(mu1: float, sigma1: float, mu2: float, sigma2: float) -> float:
    """Computes Gaussian KL divergence D_KL(N(mu1, sigma1^2) || N(mu2, sigma2^2))."""
    s1 = max(sigma1, EPSILON)
    s2 = max(sigma2, EPSILON)
    term1 = math.log(s2 / s1)
    term2 = (s1**2 + (mu1 - mu2)**2) / (2.0 * (s2**2))
    kl = term1 + term2 - 0.5
    return max(0.0, float(kl))


class OfflineIASComputer:
    """
    Computes IAS scores offline against SQLite baseline without cloud connectivity.
    """

    def __init__(self, alert_queue_dir: str = "/media/garuda/data/event_queue"):
        self.alert_queue_dir = alert_queue_dir
        os.makedirs(self.alert_queue_dir, exist_ok=True)

    def evaluate_observation(
        self,
        observed: Dict[str, Any],
        baseline_mu: Dict[str, float],
        baseline_sigma: Dict[str, float],
        observation_count: int,
        agent_id: str = "usb-node",
        hostname: str = "local-host",
    ) -> Dict[str, Any]:
        """
        Evaluates physical observation.
        If observation_count < 1000: strictly enforces 'BASELINING — NO ALERTS VALID'.
        """
        # 1. Enforce Baselining Safety Guard (< 1000 events)
        if observation_count < 1000:
            return {
                "score": 0.0,
                "level": "BASELINING",
                "status_label": "BASELINING — NO ALERTS VALID",
                "is_alert": False,
                "observation_count": observation_count,
                "events_remaining_for_baseline": max(0, 1000 - observation_count),
                "top_channels": [],
            }

        # 2. Compute weighted Gaussian KL divergence
        channel_scores = {}
        active_weights = {}

        channel_mapping = {
            "rapl_pkg": observed.get("rapl_pkg_uw"),
            "rapl_core": observed.get("rapl_core_uw"),
            "perf_instr": observed.get("instructions"),
            "perf_cache": observed.get("cache_misses"),
            "entropy": observed.get("entropy_avail"),
            "schedstat": observed.get("sched_run_ms"),
        }

        for ch, val in channel_mapping.items():
            if val is not None:
                active_weights[ch] = CHANNEL_WEIGHTS.get(ch, 0.1)
                mu2 = baseline_mu.get(ch, float(val))
                sigma2 = baseline_sigma.get(ch, 1000.0)
                mu1 = float(val)
                sigma1 = sigma2
                channel_scores[ch] = compute_gaussian_kl(mu1, sigma1, mu2, sigma2)

        if not active_weights:
            return {
                "score": 0.0,
                "level": "CLEAN",
                "status_label": "INVARIANTS_SATISFIED",
                "is_alert": False,
                "observation_count": observation_count,
                "top_channels": [],
            }

        total_weight = sum(active_weights.values())
        total_ias = sum(channel_scores[ch] * (active_weights[ch] / total_weight) for ch in channel_scores)
        score = round(total_ias, 4)

        # Classification
        if score >= 5.0:
            level = "CRITICAL"
        elif score >= 3.0:
            level = "MEDIUM"
        elif score >= 1.5:
            level = "LOG"
        else:
            level = "CLEAN"

        is_alert = level in ("CRITICAL", "MEDIUM")

        # Top divergent channels
        top_channels = sorted(
            [{"channel": ch, "score": round(score_val, 2)} for ch, score_val in channel_scores.items()],
            key=lambda x: x["score"],
            reverse=True,
        )[:3]

        result = {
            "score": score,
            "level": level,
            "status_label": f"ANOMALY_{level}" if is_alert else "INVARIANTS_SATISFIED",
            "is_alert": is_alert,
            "observation_count": observation_count,
            "top_channels": top_channels,
        }

        # 3. Persist Alert to LUKS partition event_queue if anomalous
        if is_alert:
            self._save_offline_alert(result, observed, agent_id, hostname)

        return result

    def _save_offline_alert(
        self,
        res: Dict[str, Any],
        observed: Dict[str, Any],
        agent_id: str,
        hostname: str,
    ) -> Optional[str]:
        """Saves alert JSON to event_queue directory for air-gapped analyst collection."""
        try:
            alert_id = str(uuid.uuid4())[:8]
            now_ist = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y%m%d_%H%M%S")
            filename = f"alert_{alert_id}_{now_ist}.json"
            filepath = os.path.join(self.alert_queue_dir, filename)

            payload = {
                "alert_id": alert_id,
                "agent_id": agent_id,
                "hostname": hostname,
                "timestamp_ist": now_ist,
                "ias_score": res["score"],
                "level": res["level"],
                "top_channels": res["top_channels"],
                "raw_observation": observed,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            logger.info(f"Saved offline alert to {filepath}")
            return filepath
        except Exception as e:
            logger.warning(f"Could not write offline alert JSON: {e}")
            return None
