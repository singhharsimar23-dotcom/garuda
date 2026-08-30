"""
Integrated Anomaly Score (IAS) Evaluation Engine
Computes multi-channel Gaussian physics deviation, evaluates dynamic CONFLICT_MODE thresholds,
and triggers auto-calibration after 1,000 observations per host.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from baseline import AlmanacBaselineStore, get_baseline_store
from config import get_settings
from models import TelemetryInput

logger = logging.getLogger("axiom.ias_engine")

WEIGHTS: Dict[str, float] = {
    "rapl_pkg": 0.35,
    "rapl_dram": 0.15,
    "perf_instructions": 0.20,
    "perf_cache_miss": 0.10,
    "entropy": 0.10,
    "schedstat_steal": 0.10,
}

CONFLICT_TENSION_INDEX_THRESHOLD = 0.65
CONFLICT_THRESHOLD_OFFSET = 1.5
AUTO_CALIBRATION_SAMPLE_COUNT = 1000


class IASEngine:
    """
    Evaluates real-time anomaly metrics for ingested host physics telemetry.
    """

    def __init__(self, baseline_store: Optional[AlmanacBaselineStore] = None):
        self.baseline_store = baseline_store or get_baseline_store()
        self._host_observation_counts: Dict[str, int] = {}
        self._host_ias_history: Dict[str, List[float]] = {}
        self._host_calibrated_thresholds: Dict[str, Dict[str, float]] = {}

    def get_conflict_mode(self, supabase_client=None) -> bool:
        """Query geopolitical_tension table to evaluate conflict mode."""
        if not supabase_client:
            return False
        try:
            res = (
                supabase_client.table("geopolitical_tension")
                .select("tension_index")
                .order("recorded_at", desc=True)
                .limit(1)
                .execute()
            )
            if res.data and len(res.data) > 0:
                tension = float(res.data[0].get("tension_index", 0.0))
                return tension >= CONFLICT_TENSION_INDEX_THRESHOLD
        except Exception as e:
            logger.debug(f"Failed to query geopolitical_tension table: {e}")
        return False

    def check_auto_calibration(self, hostname: str, ias_score: float, supabase_client=None) -> None:
        """Trigger dynamic 99th percentile auto-calibration when 1000 events reached."""
        if hostname not in self._host_ias_history:
            self._host_ias_history[hostname] = []
        self._host_ias_history[hostname].append(ias_score)

        count = len(self._host_ias_history[hostname])
        if count == AUTO_CALIBRATION_SAMPLE_COUNT or (count > 0 and count % 1000 == 0):
            # VERIFY: numpy percentile function signature: np.percentile(a, q)
            scores = np.array(self._host_ias_history[hostname][-1000:])
            p99 = float(np.percentile(scores, 99))
            p99 = max(p99, 0.5)

            log_thresh = round(2.0 * p99, 4)
            med_thresh = round(4.0 * p99, 4)
            crit_thresh = round(8.0 * p99, 4)

            self._host_calibrated_thresholds[hostname] = {
                "p99": p99,
                "LOG": log_thresh,
                "MEDIUM": med_thresh,
                "CRITICAL": crit_thresh,
            }
            logger.info(
                f"[AUTO-CALIBRATION COMPLETED] Host '{hostname}' thresholds updated: "
                f"P99={p99}, LOG={log_thresh}, MEDIUM={med_thresh}, CRITICAL={crit_thresh}"
            )

            if supabase_client:
                try:
                    payload = {
                        "hostname": hostname,
                        "p99_ias": p99,
                        "log_threshold": log_thresh,
                        "medium_threshold": med_thresh,
                        "critical_threshold": crit_thresh,
                        "sample_count": count,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                    supabase_client.table("host_thresholds").upsert(payload, on_conflict="hostname").execute()
                except Exception as e:
                    logger.warning(f"Failed writing host_thresholds to Supabase: {e}")

    def compute_ias(
        self,
        payload: TelemetryInput,
        supabase_client=None,
    ) -> Tuple[float, Dict[str, float], str, bool, str, List[str]]:
        """
        Compute Integrated Anomaly Score (IAS) and anomaly severity level.
        Returns:
            - ias_score: float
            - channel_sigmas: dict
            - anomaly_level: 'CLEAN' | 'LOG' | 'MEDIUM' | 'CRITICAL'
            - uncalibrated: bool
            - workload_class: str
            - flags: list of alert flags
        """
        hostname = payload.hostname
        workload_class = (
            payload.ias.workload_class
            if (payload.ias and payload.ias.workload_class)
            else "BASELINING"
        )

        # Track host observation count
        self._host_observation_counts[hostname] = self._host_observation_counts.get(hostname, 0) + 1
        obs_count = self._host_observation_counts[hostname]
        uncalibrated = obs_count < AUTO_CALIBRATION_SAMPLE_COUNT

        # Extract channel values, handling unavailable sensors gracefully
        channels: Dict[str, Optional[float]] = {}
        if not payload.rapl.unavailable:
            channels["rapl_pkg"] = float(payload.rapl.pkg_w or 0.0)
            channels["rapl_dram"] = float(payload.rapl.dram_w or 0.0)
        else:
            channels["rapl_pkg"] = None
            channels["rapl_dram"] = None

        if not payload.perf.unavailable:
            channels["perf_instructions"] = float(payload.perf.instructions_ps or 0.0)
            channels["perf_cache_miss"] = float(payload.perf.cache_misses_ps or 0.0)
        else:
            channels["perf_instructions"] = None
            channels["perf_cache_miss"] = None

        channels["entropy"] = float(payload.entropy.bits)
        channels["schedstat_steal"] = float(payload.schedstat.steal_ratio)

        # Compute per-channel sigmas and one-sided KL contributions
        channel_sigmas: Dict[str, float] = {}
        weighted_sum = 0.0
        total_active_weight = 0.0

        for ch_name, weight in WEIGHTS.items():
            val = channels.get(ch_name)
            if val is None:
                # Sensor unavailable: skip channel
                continue

            base = self.baseline_store.get_baseline(hostname, workload_class, ch_name, supabase_client)
            mean = base["mean"]
            std = max(base["std"], 1e-9)

            if ch_name == "entropy":
                # Inverted signal: Low entropy is suspicious
                sigma = (mean - val) / std
            else:
                # One-sided spike: Only elevated physics values are anomalous
                sigma = (val - mean) / std

            channel_sigmas[ch_name] = round(float(sigma), 4)
            weighted_sum += weight * max(0.0, sigma)
            total_active_weight += weight

        # Re-normalize if some channels were unavailable
        if total_active_weight > 0:
            ias_score = round(weighted_sum / total_active_weight, 4)
        else:
            ias_score = 0.0

        # Check Conflict Mode & Thresholds
        conflict_mode = self.get_conflict_mode(supabase_client)
        offset = CONFLICT_THRESHOLD_OFFSET if conflict_mode else 0.0

        # Load calibrated thresholds if available
        thresh = self._host_calibrated_thresholds.get(hostname, {
            "LOG": 1.5,
            "MEDIUM": 3.0,
            "CRITICAL": 5.0,
        })

        crit_threshold = max(0.1, thresh["CRITICAL"] - offset)
        med_threshold = max(0.1, thresh["MEDIUM"] - offset)
        log_threshold = max(0.0, thresh["LOG"] - offset)

        anomaly_level = "CLEAN"
        flags = []

        if ias_score >= crit_threshold:
            anomaly_level = "CRITICAL"
            flags.append("IAS_CRITICAL")
        elif ias_score >= med_threshold:
            anomaly_level = "MEDIUM"
            flags.append("IAS_MEDIUM")
        elif ias_score >= log_threshold:
            anomaly_level = "LOG"
            flags.append("IAS_LOG")

        if uncalibrated:
            flags.append("UNCALIBRATED")
        if conflict_mode:
            flags.append("CONFLICT_MODE")

        # Auto-Calibration evaluation
        self.check_auto_calibration(hostname, ias_score, supabase_client)

        logger.info(
            f"[IAS EVALUATED] Host '{hostname}' (Workload: {workload_class}): "
            f"IAS={ias_score} (Level: {anomaly_level}, ConflictMode={conflict_mode})"
        )

        return ias_score, channel_sigmas, anomaly_level, uncalibrated, workload_class, flags


_ias_engine = IASEngine()


def get_ias_engine() -> IASEngine:
    return _ias_engine
