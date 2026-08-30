"""
Almanac Baseline Lifecycle Service
Coordinates baseline persistence, memory caching, uncontaminated EMA updates, and calibration triggers.
"""

import logging
from typing import Any, Dict, List, Optional

from ..db.queries import (
    get_almanac_baseline,
    upsert_almanac_baseline,
    get_clean_baseline_observations,
)
from .ias_computer import update_baseline_ema, calibrate_thresholds

logger = logging.getLogger("axiom.services.almanac")


class AlmanacService:
    """
    Manages Gaussian baseline statistics and calibration state for monitored agents.
    """

    def __init__(self, db_pool: Optional[object] = None):
        self.db_pool = db_pool
        # In-memory baseline cache: (agent_id, workload_class) -> baseline_dict
        self._cache: Dict[tuple[str, str], Dict[str, Any]] = {}

    async def get_baseline(self, agent_id: str, workload_class: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves active baseline from cache or database.
        """
        cache_key = (agent_id, workload_class)
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.db_pool:
            db_base = await get_almanac_baseline(self.db_pool, agent_id, workload_class)
            if db_base:
                self._cache[cache_key] = db_base
                return db_base

        return None

    async def update_baseline(
        self,
        agent_id: str,
        workload_class: str,
        observation: Dict[str, Any],
        ias_score: float,
        log_threshold: float = 1.5,
    ) -> Optional[Dict[str, Any]]:
        """
        Updates baseline EMA if observation is clean (ias_score < log_threshold).
        Triggers auto-calibration when observation count crosses 1000.
        """
        if ias_score >= log_threshold:
            # Contaminated event: DO NOT update baseline
            logger.debug(f"Skipping baseline update for {agent_id}/{workload_class} (IAS {ias_score} >= {log_threshold})")
            return None

        current = await self.get_baseline(agent_id, workload_class)
        if not current:
            current = {
                "agent_id": agent_id,
                "workload_class": workload_class,
                "mu": {},
                "sigma": {},
                "thresholds": {"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0},
                "observation_count": 0,
                "trust_established": False,
            }

        updated = update_baseline_ema(current, observation)
        cache_key = (agent_id, workload_class)
        self._cache[cache_key] = updated

        # Check for auto-calibration milestone
        obs_count = updated["observation_count"]
        if obs_count == 1000 and self.db_pool:
            try:
                clean_scores = await get_clean_baseline_observations(self.db_pool, agent_id, workload_class, limit=1500)
                if len(clean_scores) >= 500:
                    calibrated_t = calibrate_thresholds(agent_id, workload_class, clean_scores)
                    updated["thresholds"] = calibrated_t
                    updated["trust_established"] = True
                    self._cache[cache_key] = updated
            except Exception as e:
                logger.warning(f"Auto-calibration failed for {agent_id}: {e}")

        # Persist to database if pool is available
        if self.db_pool:
            await upsert_almanac_baseline(
                self.db_pool,
                agent_id,
                workload_class,
                updated["mu"],
                updated["sigma"],
                updated["thresholds"],
                updated["observation_count"],
                updated["trust_established"],
            )

        return updated
