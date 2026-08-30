"""
Integrated Anomaly Score (IAS) Engine
Computes multi-channel Gaussian Kullback-Leibler (KL) divergence across hardware physics channels.
Includes K-Means workload classification and contamination-prevention baseline protection.
"""

from collections import deque
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("garuda_agent.ias")

# Channel weights specified in architecture charter
CHANNEL_WEIGHTS: Dict[str, float] = {
    "rapl_pkg": 0.35,
    "rapl_dram": 0.15,
    "perf_instructions": 0.20,
    "perf_cache_miss": 0.10,
    "entropy": 0.10,
    "schedstat_steal": 0.10,
}

# Workload cluster labels
WORKLOAD_LABELS = ["IDLE", "WEB_SERVER", "DATABASE", "BATCH"]

# Calibration & Anomaly Thresholds
CALIBRATION_EVENT_COUNT = 1000
BASELINING_SAMPLE_COUNT = 50
CONTAMINATION_IAS_THRESHOLD = 1.5  # Do not update baseline if IAS >= 1.5

IAS_LOG_THRESHOLD = 1.5
IAS_MEDIUM_THRESHOLD = 3.0
IAS_CRITICAL_THRESHOLD = 5.0

EPSILON_STD = 1e-3  # Minimum standard deviation floor to avoid division by zero


def gaussian_kl_divergence(mu1: float, sigma1: float, mu2: float, sigma2: float) -> float:
    """
    Computes KL Divergence D_KL( P(mu1, sigma1^2) || Q(mu2, sigma2^2) ) for Gaussians.
    D_KL(P || Q) = ((mu1 - mu2)^2 + sigma1^2 - sigma2^2) / (2 * sigma2^2) + ln(sigma2 / sigma1)
    """
    s1 = max(sigma1, EPSILON_STD)
    s2 = max(sigma2, EPSILON_STD)
    
    term1 = ((mu1 - mu2) ** 2 + s1 ** 2 - s2 ** 2) / (2.0 * (s2 ** 2))
    term2 = math.log(s2 / s1)
    dkl = term1 + term2
    return max(0.0, float(dkl))


class ChannelBaseline:
    """Stores running Gaussian statistics (mean, std) for a channel."""

    def __init__(self, default_mean: float = 1.0, default_std: float = 1.0):
        self.mean: float = default_mean
        self.std: float = max(default_std, EPSILON_STD)
        self.sample_count: int = 0
        self._m2: float = (self.std ** 2) * max(1, self.sample_count)

    def update(self, value: float, learning_rate: float = 0.05) -> None:
        """Update Gaussian baseline using exponential moving statistics."""
        self.sample_count += 1
        delta = value - self.mean
        self.mean += learning_rate * delta
        var = (self.std ** 2) * (1.0 - learning_rate) + learning_rate * (delta ** 2)
        self.std = max(math.sqrt(max(var, 1e-6)), EPSILON_STD)


class IASComputer:
    """
    Computes Integrated Anomaly Score across physical and scheduler channels.
    """

    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.total_events: int = 0
        self.window: deque = deque(maxlen=window_size)
        
        # Workload classification data
        self.feature_history: List[List[float]] = []
        self.kmeans_fitted: bool = False
        self.kmeans_model = None

        # Baselines stored per workload class per channel
        self.baselines: Dict[str, Dict[str, ChannelBaseline]] = {}
        for wl in ["BASELINING"] + WORKLOAD_LABELS:
            self.baselines[wl] = {
                "rapl_pkg": ChannelBaseline(default_mean=15.0, default_std=5.0),
                "rapl_dram": ChannelBaseline(default_mean=3.0, default_std=1.0),
                "perf_instructions": ChannelBaseline(default_mean=1e6, default_std=3e5),
                "perf_cache_miss": ChannelBaseline(default_mean=5e4, default_std=2e4),
                "entropy": ChannelBaseline(default_mean=3500.0, default_std=400.0),
                "schedstat_steal": ChannelBaseline(default_mean=0.01, default_std=0.02),
            }

    def _classify_workload(self, rapl_pkg: float, instructions: float, cache_miss: float) -> str:
        """Classify current workload using k-means on physics telemetry."""
        features = [rapl_pkg, instructions, cache_miss]
        self.feature_history.append(features)

        if len(self.feature_history) < BASELINING_SAMPLE_COUNT:
            return "BASELINING"

        try:
            from sklearn.cluster import KMeans
            # Fit or update K-Means model periodically
            if not self.kmeans_fitted or len(self.feature_history) % 100 == 0:
                data = np.array(self.feature_history[-500:])  # Last 500 points
                self.kmeans_model = KMeans(n_clusters=4, random_state=42, n_init="auto")
                self.kmeans_model.fit(data)
                self.kmeans_fitted = True

            cluster_idx = int(self.kmeans_model.predict(np.array([features]))[0])
            # Map cluster index 0..3 to WORKLOAD_LABELS
            return WORKLOAD_LABELS[cluster_idx % len(WORKLOAD_LABELS)]
        except Exception as e:
            logger.debug(f"Workload classification fallback: {e}")
            return "BASELINING"

    def compute(
        self,
        rapl: Dict[str, Any],
        perf: Dict[str, Any],
        entropy: Dict[str, Any],
        schedstat: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Compute Integrated Anomaly Score for the current telemetry sample.
        """
        self.total_events += 1
        uncalibrated = self.total_events < CALIBRATION_EVENT_COUNT

        # Extract channel values
        rapl_pkg = float(rapl.get("pkg_w", 0.0))
        rapl_dram = float(rapl.get("dram_w", 0.0))
        perf_inst = float(perf.get("instructions_ps", 0.0))
        perf_cache = float(perf.get("cache_misses_ps", 0.0))
        entropy_val = float(entropy.get("bits", 3500))
        sched_steal = float(schedstat.get("steal_ratio", 0.0))

        current_sample = {
            "rapl_pkg": rapl_pkg,
            "rapl_dram": rapl_dram,
            "perf_instructions": perf_inst,
            "perf_cache_miss": perf_cache,
            "entropy": entropy_val,
            "schedstat_steal": sched_steal,
        }
        self.window.append(current_sample)

        # Determine Workload Class
        workload_class = self._classify_workload(rapl_pkg, perf_inst, perf_cache)
        active_baselines = self.baselines.get(workload_class, self.baselines["BASELINING"])

        # Compute Window Gaussian parameters for each channel
        channel_dkl: Dict[str, float] = {}
        channel_sigmas: Dict[str, float] = {}
        total_ias = 0.0

        for channel, weight in CHANNEL_WEIGHTS.items():
            vals = [s[channel] for s in self.window]
            mu1 = float(np.mean(vals))
            sigma1 = float(np.std(vals)) if len(vals) > 1 else EPSILON_STD
            sigma1 = max(sigma1, EPSILON_STD)

            base = active_baselines[channel]
            mu2 = base.mean
            sigma2 = base.std

            dkl = gaussian_kl_divergence(mu1, sigma1, mu2, sigma2)
            channel_dkl[channel] = dkl
            channel_sigmas[channel] = round(sigma1, 4)
            total_ias += weight * dkl

        total_ias = round(total_ias, 4)

        # Contamination Prevention Rule: NEVER update baseline when current IAS >= 1.5
        if total_ias < CONTAMINATION_IAS_THRESHOLD:
            for channel, val in current_sample.items():
                active_baselines[channel].update(val)
        else:
            logger.info(f"Contamination prevention active (IAS={total_ias} >= 1.5). Baseline update skipped.")

        flags: List[str] = []
        if uncalibrated:
            flags.append("UNCALIBRATED")

        if total_ias >= IAS_CRITICAL_THRESHOLD:
            flags.append("IAS_CRITICAL")
        elif total_ias >= IAS_MEDIUM_THRESHOLD:
            flags.append("IAS_MEDIUM")
        elif total_ias >= IAS_LOG_THRESHOLD:
            flags.append("IAS_LOG")

        payload = {
            "score": total_ias,
            "uncalibrated": uncalibrated,
            "workload_class": workload_class,
            "channel_sigmas": channel_sigmas,
        }
        return payload, flags
