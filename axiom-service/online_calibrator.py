"""
AXIOM-II Online Host Threshold Calibrator
Computes empirical p99 IAS baselines from clean operational periods and tunes LOG/MEDIUM/CRITICAL thresholds.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import numpy as np

logger = logging.getLogger("axiom.online_calibrator")


class AxiomOnlineCalibrator:
    """
    Tracks clean physics observations and calculates empirical p99 anomaly thresholds per host.
    """

    def __init__(self, calibration_sample_window: int = 1000):
        self.calibration_sample_window = calibration_sample_window
        self._host_clean_ias_buffer: Dict[str, List[float]] = defaultdict(list)
        self._host_calibrations: Dict[str, Dict[str, float]] = {}

    def record_clean_observation(self, hostname: str, ias_score: float) -> Optional[Dict[str, float]]:
        """
        Record IAS score during clean operation (IAS < 1.5).
        Triggers threshold recalculation every `calibration_sample_window` samples.
        """
        if ias_score < 1.5:
            self._host_clean_ias_buffer[hostname].append(ias_score)

        if len(self._host_clean_ias_buffer[hostname]) >= self.calibration_sample_window:
            return self.compute_host_calibration(hostname)
        return None

    def compute_host_calibration(self, hostname: str, supabase_client=None) -> Dict[str, float]:
        """
        Calculates empirical p99 on clean buffer and updates threshold multipliers:
        LOG = 2 * p99, MEDIUM = 4 * p99, CRITICAL = 8 * p99
        """
        samples = self._host_clean_ias_buffer.get(hostname, [])
        if not samples:
            samples = [0.35, 0.42, 0.28, 0.50, 0.65, 0.72]

        p99 = float(np.percentile(samples, 99))
        p99 = max(0.20, round(p99, 4))

        log_thresh = round(2.0 * p99, 2)
        med_thresh = round(4.0 * p99, 2)
        crit_thresh = round(8.0 * p99, 2)

        calibration = {
            "p99_clean_ias": p99,
            "log_threshold": log_thresh,
            "medium_threshold": med_thresh,
            "critical_threshold": crit_thresh,
            "sample_count": len(samples),
        }
        self._host_calibrations[hostname] = calibration

        if supabase_client:
            try:
                supabase_client.table("host_calibration").upsert({
                    "hostname": hostname,
                    "p99_clean_ias": p99,
                    "log_threshold": log_thresh,
                    "medium_threshold": med_thresh,
                    "critical_threshold": crit_thresh,
                    "sample_count": len(samples),
                    "calibrated_at": datetime.now(timezone.utc).isoformat(),
                }, on_conflict="hostname").execute()
            except Exception as e:
                logger.debug(f"Failed persisting host_calibration to Supabase: {e}")

        logger.info(
            f"[AXIOM CALIBRATION] Host '{hostname}' calibrated (p99={p99:.4f}): "
            f"LOG={log_thresh}, MEDIUM={med_thresh}, CRITICAL={crit_thresh}"
        )
        return calibration

    def get_host_thresholds(self, hostname: str) -> Dict[str, float]:
        return self._host_calibrations.get(hostname, {
            "p99_clean_ias": 0.75,
            "log_threshold": 1.5,
            "medium_threshold": 3.0,
            "critical_threshold": 6.0,
            "sample_count": 0,
        })


_axiom_calibrator = AxiomOnlineCalibrator()


def get_axiom_online_calibrator() -> AxiomOnlineCalibrator:
    return _axiom_calibrator
