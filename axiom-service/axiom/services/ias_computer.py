"""
Instruction/Anomaly Score (IAS) Computer
Computes Gaussian Kullback-Leibler (KL) Divergence across 6 physical channels,
handles dynamic weight renormalization, prevents baseline contamination, and performs auto-calibration.
"""

import math
import logging
from typing import Any, Dict, List, Optional
import numpy as np

from ..models.telemetry import (
    AlmanacBaselineModel,
    AnomalyLevel,
    ChannelObservation,
    IASResult,
)

logger = logging.getLogger("axiom.services.ias")

# Default Base Channel Weights
CHANNEL_WEIGHTS: Dict[str, float] = {
    "rapl_pkg": 0.35,
    "rapl_dram": 0.15,
    "perf_instr": 0.20,
    "perf_cache": 0.10,
    "entropy": 0.10,
    "schedstat": 0.10,
}

EPSILON = 1e-6


def _extract_channel_values(obs: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Map raw observation keys to standard channel identifiers."""
    return {
        "rapl_pkg": obs.get("rapl_pkg_uw"),
        "rapl_dram": obs.get("rapl_dram_uw"),
        "perf_instr": obs.get("instructions"),
        "perf_cache": obs.get("cache_misses"),
        "entropy": obs.get("entropy_avail"),
        "schedstat": obs.get("sched_delay_ratio") or (
            obs.get("sched_wait_ms_per_sec") / 1000.0 if obs.get("sched_wait_ms_per_sec") is not None else None
        ),
    }


def compute_gaussian_kl(
    mu1: float,
    sigma1: float,
    mu2: float,
    sigma2: float,
    eps: float = EPSILON,
) -> float:
    """
    Computes Gaussian KL Divergence D_KL( N(mu1, sigma1^2) || N(mu2, sigma2^2) ):
    D_KL = ln(sigma2/sigma1) + (sigma1^2 + (mu1 - mu2)^2) / (2 * sigma2^2) - 0.5
    """
    s1 = max(sigma1, eps)
    s2 = max(sigma2, eps)
    
    term1 = math.log(s2 / s1)
    term2 = (s1**2 + (mu1 - mu2)**2) / (2.0 * (s2**2))
    kl = term1 + term2 - 0.5
    return max(0.0, float(kl))


def compute_ias(
    observed: Dict[str, Any],
    baseline: Optional[Dict[str, Any]],
    default_thresholds: Optional[Dict[str, float]] = None,
) -> IASResult:
    """
    Computes total weighted IAS score across all available physical channels.
    """
    thresholds = default_thresholds or {
        "LOG": 1.5,
        "MEDIUM": 3.0,
        "CRITICAL": 5.0,
    }
    
    calibrated = False
    if baseline:
        calibrated = baseline.get("trust_established", False)
        if baseline.get("thresholds"):
            thresholds = baseline["thresholds"]

    channel_vals = _extract_channel_values(observed)
    channel_scores: Dict[str, float] = {}
    active_weights: Dict[str, float] = {}

    base_mu = baseline.get("mu", {}) if baseline else {}
    base_sigma = baseline.get("sigma", {}) if baseline else {}

    # 1. Compute per-channel divergence for available channels
    for ch, val in channel_vals.items():
        if val is not None:
            active_weights[ch] = CHANNEL_WEIGHTS.get(ch, 0.1)
            
            # If baseline exists for channel, compute KL divergence
            if ch in base_mu and ch in base_sigma:
                mu2 = float(base_mu[ch])
                sigma2 = float(base_sigma[ch])
                
                # If observed provides its own variance (e.g. from batch distribution)
                mu1 = float(val)
                # If sigma1 is not provided in single-point observation, default to sigma2
                # which reduces KL divergence to the normalized quadratic distance: (mu1 - mu2)^2 / (2 * sigma2^2)
                sigma1 = float(observed.get(f"{ch}_sigma", sigma2))
                
                # When evaluating against baseline distribution
                ch_kl = compute_gaussian_kl(mu1, sigma1, mu2, sigma2)
                channel_scores[ch] = ch_kl
            else:
                # No baseline yet; score is 0
                channel_scores[ch] = 0.0

    if not active_weights:
        # No channels available at all
        return IASResult(
            score=0.0,
            level=AnomalyLevel.CLEAN,
            channel_scores={},
            calibrated=calibrated,
            threshold_used=thresholds,
            top_divergent_channels=[],
        )

    # 2. Re-normalize weights across available channels
    total_weight = sum(active_weights.values())
    normalized_weights = {ch: w / total_weight for ch, w in active_weights.items()}

    # 3. Weighted sum IAS calculation
    total_ias = sum(channel_scores[ch] * normalized_weights[ch] for ch in channel_scores)

    # Determine Anomaly Level
    log_t = thresholds.get("LOG", 1.5)
    med_t = thresholds.get("MEDIUM", 3.0)
    crit_t = thresholds.get("CRITICAL", 5.0)

    if total_ias >= crit_t:
        level = AnomalyLevel.CRITICAL
    elif total_ias >= med_t:
        level = AnomalyLevel.MEDIUM
    elif total_ias >= log_t:
        level = AnomalyLevel.LOG
    else:
        level = AnomalyLevel.CLEAN

    # Identify top divergent channels
    top_channels = sorted(
        [{"channel": ch, "score": score, "delta_from_baseline": (channel_vals[ch] - base_mu.get(ch, 0.0)) if channel_vals[ch] is not None and ch in base_mu else 0.0}
         for ch, score in channel_scores.items()],
        key=lambda x: x["score"],
        reverse=True,
    )

    return IASResult(
        score=round(total_ias, 4),
        level=level,
        channel_scores={k: round(v, 4) for k, v in channel_scores.items()},
        calibrated=calibrated,
        threshold_used=thresholds,
        top_divergent_channels=top_channels[:3],
    )


def update_baseline_ema(
    current_baseline: Dict[str, Any],
    observation: Dict[str, Any],
    alpha: float = 0.001,
) -> Dict[str, Any]:
    """
    Updates baseline Gaussian parameters (mu, sigma) via Exponential Moving Average (EMA).
    Guaranteed only to be invoked when observation is clean (IAS < LOG_THRESHOLD).
    """
    mu = dict(current_baseline.get("mu", {}))
    sigma = dict(current_baseline.get("sigma", {}))
    obs_count = current_baseline.get("observation_count", 0) + 1
    channel_vals = _extract_channel_values(observation)

    for ch, val in channel_vals.items():
        if val is not None:
            x = float(val)
            if ch not in mu or obs_count <= 1:
                mu[ch] = x
                sigma[ch] = max(abs(x * 0.1), 1.0)
            else:
                old_mu = mu[ch]
                old_sigma = sigma[ch]
                # EMA updates
                new_mu = (1.0 - alpha) * old_mu + alpha * x
                var = (1.0 - alpha) * (old_sigma**2) + alpha * ((x - new_mu)**2)
                mu[ch] = new_mu
                sigma[ch] = max(math.sqrt(var), EPSILON)

    # Establish trust once observation count reaches 1000 clean samples
    trust_established = current_baseline.get("trust_established", False) or (obs_count >= 1000)

    return {
        "agent_id": current_baseline.get("agent_id"),
        "workload_class": current_baseline.get("workload_class"),
        "mu": mu,
        "sigma": sigma,
        "thresholds": current_baseline.get("thresholds", {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0}),
        "observation_count": obs_count,
        "trust_established": trust_established,
    }


def calibrate_thresholds(
    agent_id: str,
    workload_class: str,
    clean_ias_scores: List[float],
) -> Dict[str, float]:
    """
    Computes calibrated thresholds based on the empirical 99th percentile (p99)
    of clean baseline observations:
      LOG = 2 * p99
      MEDIUM = 4 * p99
      CRITICAL = 8 * p99
    """
    if len(clean_ias_scores) < 500:
        logger.warning(f"Insufficient baseline points ({len(clean_ias_scores)} < 500) for calibration. Returning default thresholds.")
        return {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0}

    p99 = float(np.percentile(clean_ias_scores, 99))
    p99 = max(p99, 0.25)  # Guard against degenerate zero noise

    calibrated_thresholds = {
        "LOG": round(2.0 * p99, 3),
        "MEDIUM": round(4.0 * p99, 3),
        "CRITICAL": round(8.0 * p99, 3),
    }

    logger.info(
        f"Calibrated thresholds for {agent_id}/{workload_class} (p99={p99:.4f}): "
        f"{calibrated_thresholds}"
    )
    return calibrated_thresholds
