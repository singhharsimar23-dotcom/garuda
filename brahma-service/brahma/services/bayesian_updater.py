"""
Bayesian Adversary State Updater
Translates physical execution anomaly signatures into tactic likelihoods and updates the kill-chain posterior.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from .kill_chain_tracker import KillChainTracker, MITRE_TACTICS
from ..db.queries import get_brahma_model, upsert_brahma_model

logger = logging.getLogger("brahma.services.bayesian")


def compute_evidence_likelihood(
    ias_score: float,
    top_channels: List[Dict[str, Any]],
) -> Dict[str, float]:
    """
    Computes P(Evidence | Tactic) based on the divergent physical channels in the anomaly event.
    """
    # Base prior baseline
    likelihood = {t: 0.1 for t in MITRE_TACTICS}

    channel_names = [ch.get("channel") for ch in top_channels if isinstance(ch, dict)]

    # 1. RAPL CPU Package / Core Power Anomalies
    if "rapl_pkg" in channel_names or "rapl_core" in channel_names:
        likelihood["execution"] += 0.8
        likelihood["defense-evasion"] += 0.4
        likelihood["impact"] += 0.5

    # 2. Hardware Cache Miss Spikes (Side-channels / Process Injection)
    if "perf_cache" in channel_names:
        likelihood["defense-evasion"] += 0.9
        likelihood["discovery"] += 0.7
        likelihood["credential-access"] += 0.6

    # 3. Kernel Scheduler Latency / Context Switch Delays
    if "schedstat" in channel_names:
        likelihood["privilege-escalation"] += 0.8
        likelihood["persistence"] += 0.6
        likelihood["defense-evasion"] += 0.5

    # 4. Kernel Entropy Depletion (Payload Decryption / Crypto Ops)
    if "entropy" in channel_names:
        likelihood["defense-evasion"] += 0.7
        likelihood["command-and-control"] += 0.6
        likelihood["exfiltration"] += 0.5

    # 5. High Overall IAS Divergence (Intense Execution / C2 burst)
    if ias_score >= 5.0:
        likelihood["command-and-control"] += 0.8
        likelihood["exfiltration"] += 0.7
        likelihood["execution"] += 0.6

    return likelihood


class BayesianUpdater:
    """
    Manages continuous Bayesian updating of the adversary kill-chain state for all monitored agents.
    """

    def __init__(self, db_pool: Optional[object] = None):
        self.db_pool = db_pool
        # Memory cache: agent_id -> KillChainTracker
        self._trackers: Dict[str, KillChainTracker] = {}

    async def get_or_load_tracker(self, agent_id: str) -> KillChainTracker:
        """Retrieves active tracker from cache or database."""
        if agent_id in self._trackers:
            return self._trackers[agent_id]

        if self.db_pool:
            saved = await get_brahma_model(self.db_pool, agent_id)
            if saved:
                tracker = KillChainTracker(
                    agent_id=agent_id,
                    initial_posterior=saved.get("posterior"),
                    observation_count=saved.get("observation_count", 0),
                )
                self._trackers[agent_id] = tracker
                return tracker

        # Default new tracker with uniform prior
        tracker = KillChainTracker(agent_id=agent_id)
        self._trackers[agent_id] = tracker
        return tracker

    async def process_anomaly_event(
        self,
        agent_id: str,
        hostname: str,
        ias_score: float,
        top_channels: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Executes Bayesian update from anomaly observation:
        P(T_k | E) = P(E | T_k) * P(T_k) / sum(P(E | T_j) * P(T_j))
        """
        tracker = await self.get_or_load_tracker(agent_id)
        tracker.observation_count += 1

        # 1. Compute likelihood P(E | T)
        likelihood = compute_evidence_likelihood(ias_score, top_channels)

        # 2. Update posterior
        unnorm_posterior = {}
        for t in MITRE_TACTICS:
            prior_t = tracker.posterior.get(t, 1.0 / len(MITRE_TACTICS))
            lik_t = likelihood.get(t, 0.1)
            unnorm_posterior[t] = prior_t * lik_t

        tracker.posterior = tracker._normalize(unnorm_posterior)

        # 3. Compute metrics
        entropy = tracker.get_entropy_bits()
        map_tactic = tracker.get_map_tactic()
        predicted_next = tracker.predict_next_tactic()
        actor_id, status, confidence = tracker.evaluate_attribution()

        # Check if grammar expansion is warranted (Entropy > 2.0 after 10 observations)
        should_expand_grammar = (entropy > 2.0) and (tracker.observation_count >= 10)

        # 4. Persist to database if pool is active
        if self.db_pool:
            await upsert_brahma_model(
                pool=self.db_pool,
                agent_id=agent_id,
                actor_id=actor_id,
                map_tactic=map_tactic,
                posterior=tracker.posterior,
                observation_count=tracker.observation_count,
                entropy_bits=entropy,
                predicted_next_tactic=predicted_next,
                confidence=confidence,
                convergence_status=status,
            )

        return {
            "agent_id": agent_id,
            "actor_id": actor_id,
            "map_tactic": map_tactic,
            "predicted_next_tactic": predicted_next,
            "confidence": confidence,
            "observation_count": tracker.observation_count,
            "convergence_status": status,
            "entropy_bits": entropy,
            "posterior": tracker.posterior,
            "should_expand_grammar": should_expand_grammar,
        }
