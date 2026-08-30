"""
Gaussian Statistical Baseline Engine
Maintains online per-(host, workload_class, channel) Gaussian baselines via Welford's algorithm.
Implements strict contamination prevention (locks baseline when IAS >= 1.5) and 5,000-sample capping.
"""

from datetime import datetime, timezone
import logging
import math
from typing import Any, Dict, Optional, Tuple
import numpy as np

from config import get_settings

logger = logging.getLogger("axiom.baseline")

# Anti-Hallucination Charter: Schema verification signature for almanac_baselines table
# VERIFY columns: (hostname: text, workload_class: text, channel: text, mean: float8, std: float8, sample_count: int4, last_updated: timestamptz)
EXPECTED_ALMANAC_COLUMNS = ["hostname", "workload_class", "channel", "mean", "std", "sample_count"]

MIN_SAMPLE_COUNT_FOR_TRUST = 100
MAX_SAMPLE_COUNT_CAP = 5000
CONTAMINATION_IAS_THRESHOLD = 1.5  # Do NOT update baseline when IAS >= 1.5
MIN_STD_FLOOR = 1e-4

# Default priors before observations exist
DEFAULT_PRIORS: Dict[str, Tuple[float, float]] = {
    "rapl_pkg": (15.0, 5.0),
    "rapl_dram": (3.0, 1.0),
    "perf_instructions": (1_000_000.0, 300_000.0),
    "perf_cache_miss": (50_000.0, 20_000.0),
    "entropy": (3500.0, 400.0),
    "schedstat_steal": (0.01, 0.02),
}


class AlmanacBaselineStore:
    """
    In-memory cache & Supabase persistence for host Gaussian baselines.
    Key: (hostname, workload_class, channel) -> {"mean": float, "std": float, "sample_count": int}
    """

    def __init__(self):
        self._cache: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def get_baseline(
        self,
        hostname: str,
        workload_class: str,
        channel: str,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Retrieve (mean, std, sample_count) for a channel.
        Falls back to Supabase DB or default priors.
        """
        key = (hostname, workload_class, channel)
        if key in self._cache:
            return self._cache[key]

        # Query Supabase if client is provided
        if supabase_client:
            try:
                res = (
                    supabase_client.table("almanac_baselines")
                    .select("mean, std, sample_count")
                    .eq("hostname", hostname)
                    .eq("workload_class", workload_class)
                    .eq("channel", channel)
                    .execute()
                )
                if res.data and len(res.data) > 0:
                    row = res.data[0]
                    baseline = {
                        "mean": float(row["mean"]),
                        "std": max(float(row["std"]), MIN_STD_FLOOR),
                        "sample_count": int(row["sample_count"]),
                    }
                    self._cache[key] = baseline
                    return baseline
            except Exception as e:
                logger.debug(f"Baseline lookup from Supabase failed for {key}: {e}")

        # Fallback to default priors
        default_mean, default_std = DEFAULT_PRIORS.get(channel, (1.0, 1.0))
        baseline = {
            "mean": default_mean,
            "std": default_std,
            "sample_count": 0,
        }
        self._cache[key] = baseline
        return baseline

    def update_baseline(
        self,
        hostname: str,
        workload_class: str,
        channel: str,
        current_val: float,
        ias_score: float,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Online update using Welford's algorithm with contamination prevention.
        """
        key = (hostname, workload_class, channel)
        current = self.get_baseline(hostname, workload_class, channel, supabase_client)

        old_count = current["sample_count"]
        old_mean = current["mean"]
        old_std = current["std"]

        # 1. Contamination Prevention: Skip update if IAS is elevated
        if ias_score >= CONTAMINATION_IAS_THRESHOLD:
            logger.info(
                f"[CONTAMINATION PREVENTED] Skipping baseline update for {key}: "
                f"IAS={ias_score} >= {CONTAMINATION_IAS_THRESHOLD}"
            )
            return current

        # 2. Freeze baseline once max capacity (5,000 samples) reached
        if old_count >= MAX_SAMPLE_COUNT_CAP:
            logger.debug(f"Baseline for {key} capped at {MAX_SAMPLE_COUNT_CAP} samples; frozen.")
            return current

        # 3. Welford's Algorithm Online Update
        new_count = old_count + 1
        delta = current_val - old_mean
        new_mean = old_mean + (delta / new_count)
        delta2 = current_val - new_mean

        if old_count <= 1:
            new_std = max(abs(delta), MIN_STD_FLOOR)
        else:
            old_m2 = (old_std ** 2) * (old_count - 1)
            new_m2 = old_m2 + delta * delta2
            new_std = math.sqrt(max(0.0, new_m2 / (new_count - 1)))
            new_std = max(new_std, MIN_STD_FLOOR)

        updated = {
            "mean": round(new_mean, 6),
            "std": round(new_std, 6),
            "sample_count": new_count,
        }
        self._cache[key] = updated

        logger.info(
            f"[BASELINE UPDATED] {key}: count={new_count}, mean={updated['mean']}, std={updated['std']}"
        )

        # 4. Upsert to Supabase
        if supabase_client:
            try:
                upsert_payload = {
                    "hostname": hostname,
                    "workload_class": workload_class,
                    "channel": channel,
                    "mean": updated["mean"],
                    "std": updated["std"],
                    "sample_count": updated["sample_count"],
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                }
                supabase_client.table("almanac_baselines").upsert(
                    upsert_payload,
                    on_conflict="hostname,workload_class,channel",
                ).execute()
            except Exception as e:
                logger.warning(f"Failed to persist updated baseline to Supabase for {key}: {e}")

        return updated


_baseline_store = AlmanacBaselineStore()


def get_baseline_store() -> AlmanacBaselineStore:
    return _baseline_store
