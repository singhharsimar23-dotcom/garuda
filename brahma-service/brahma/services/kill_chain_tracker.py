"""
Kill Chain Tracker Service
Maintains Bayesian posterior over MITRE ATT&CK kill-chain tactics and enforces attribution thresholds.
"""

import math
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("brahma.services.kill_chain")

# 14 Standard Enterprise MITRE ATT&CK Tactics
MITRE_TACTICS: List[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Transition likelihood matrix (Next tactic prediction)
TACTIC_TRANSITIONS: Dict[str, str] = {
    "reconnaissance": "resource-development",
    "resource-development": "initial-access",
    "initial-access": "execution",
    "execution": "persistence",
    "persistence": "defense-evasion",
    "privilege-escalation": "defense-evasion",
    "defense-evasion": "discovery",
    "credential-access": "lateral-movement",
    "discovery": "command-and-control",
    "lateral-movement": "collection",
    "collection": "exfiltration",
    "command-and-control": "exfiltration",
    "exfiltration": "impact",
    "impact": "command-and-control",
}

EPSILON = 1e-9


class KillChainTracker:
    """
    Tracks adversary tactic progression using a discrete probability distribution over MITRE tactics.
    """

    def __init__(
        self,
        agent_id: str,
        initial_posterior: Optional[Dict[str, float]] = None,
        observation_count: int = 0,
    ):
        self.agent_id = agent_id
        self.observation_count = observation_count

        if initial_posterior:
            self.posterior = self._normalize(initial_posterior)
        else:
            # Uniform prior across all 14 tactics
            uniform_prob = 1.0 / len(MITRE_TACTICS)
            self.posterior = {t: uniform_prob for t in MITRE_TACTICS}

    def _normalize(self, dist: Dict[str, float]) -> Dict[str, float]:
        """Ensures probabilities sum to exactly 1.0."""
        clean_dist = {t: max(dist.get(t, EPSILON), EPSILON) for t in MITRE_TACTICS}
        total = sum(clean_dist.values())
        return {t: val / total for t, val in clean_dist.items()}

    def get_entropy_bits(self) -> float:
        """Computes Shannon entropy in bits: H = -sum(p * log2(p))."""
        entropy = 0.0
        for p in self.posterior.values():
            if p > 0:
                entropy -= p * math.log2(p)
        return round(max(0.0, entropy), 4)

    def get_map_tactic(self) -> str:
        """Returns the Maximum A Posteriori (MAP) tactic."""
        return max(self.posterior.items(), key=lambda x: x[1])[0]

    def predict_next_tactic(self) -> str:
        """Predicts the most probable next tactic based on transition graph."""
        map_t = self.get_map_tactic()
        return TACTIC_TRANSITIONS.get(map_t, "command-and-control")

    def evaluate_attribution(self) -> Tuple[str, str, float]:
        """
        Determines actor attribution, convergence status, and confidence.
        Strictly enforces Rule 8:
          - < 15 observations: 'UNATTRIBUTED' (INSUFFICIENT_DATA)
          - >= 15 observations: computes correlation with APT36 / SideCopy TTP patterns
        """
        if self.observation_count < 15:
            # Strict Rule 8 enforcement
            return ("UNATTRIBUTED", "INSUFFICIENT_DATA", round(min(0.35, self.observation_count / 30.0), 2))

        map_t = self.get_map_tactic()
        map_prob = self.posterior[map_t]
        entropy = self.get_entropy_bits()

        # APT36 high signature tactics: execution, defense-evasion, command-and-control, exfiltration
        apt36_score = (
            self.posterior.get("execution", 0) * 0.25
            + self.posterior.get("defense-evasion", 0) * 0.25
            + self.posterior.get("command-and-control", 0) * 0.35
            + self.posterior.get("exfiltration", 0) * 0.15
        )

        if apt36_score > 0.45 or map_prob > 0.5:
            actor = "APT36"
            status = "CONVERGED"
            conf = min(0.95, round(0.65 + (map_prob * 0.30), 2))
        elif apt36_score > 0.25:
            actor = "APT36 (possible)"
            status = "CONVERGING"
            conf = 0.55
        else:
            actor = "SideCopy" if self.posterior.get("initial-access", 0) > 0.3 else "UNATTRIBUTED"
            status = "CONVERGING" if actor != "UNATTRIBUTED" else "INSUFFICIENT_DATA"
            conf = 0.45

        return (actor, status, conf)
