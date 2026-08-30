"""
KALI ANPS (Autonomous Novel Path Synthesis) Batch Runner
Generates candidate attack paths, scores detection probability, and identifies proactive defensive gaps.
"""

import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

try:
    from .coverage_evaluator import evaluate_path_coverage
except (ImportError, ValueError):
    from coverage_evaluator import evaluate_path_coverage

logger = logging.getLogger("kali.anps")

# Standard APT36 / Transparent Tribe technique archetypes
SEED_TECHNIQUES = [
    ["T1566.001", "T1059.005", "T1055.012", "T1071.001"],
    ["T1566.002", "T1082", "T1027", "T1041"],
    ["T1190", "T1059.004", "T1055.001", "T1071.004"],
    ["T1566.001", "T1059.003", "T1055.002", "T1041"],
]


class ANPSBatchRunner:
    """
    Runs weekly automated red-team candidate path synthesis.
    """

    def __init__(self, max_batch_size: int = 20):
        self.max_batch_size = max_batch_size

    def synthesize_candidate_paths(
        self,
        actor_id: str = "APT36",
        base_posteriors: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Synthesizes candidate attack paths and computes utility + detection metrics.
        All utility and detection values strictly bounded in [0.0, 1.0].
        """
        discoveries = []

        for i in range(min(self.max_batch_size, 20)):
            tech_seq = SEED_TECHNIQUES[i % len(SEED_TECHNIQUES)]
            # Generate deterministic path hash
            seq_str = "->".join(tech_seq)
            path_hash = hashlib.sha256(seq_str.encode("utf-8")).hexdigest()[:12]
            discovery_id = f"kali-disc-{path_hash}"

            # Calculate deterministic detection and utility
            p_detect = evaluate_path_coverage(tech_seq)
            # Adversary utility is higher if detection probability is low
            utility_score = max(0.0, min(1.0, round(0.95 - (p_detect * 0.4) + ((i % 5) * 0.02), 4)))

            discovery = {
                "discovery_id": discovery_id,
                "actor_target": actor_id,
                "technique_sequence": tech_seq,
                "sequence_hash": path_hash,
                "adversary_utility_score": utility_score,
                "estimated_detection_probability": p_detect,
                "is_defensive_gap": (p_detect < 0.65),
                "recommended_hardening": f"Deploy EPPI kprobe filter for {tech_seq[1]} and monitor {tech_seq[-1]}.",
            }
            discoveries.append(discovery)

        # Sort by adversary utility descending
        discoveries.sort(key=lambda d: d["adversary_utility_score"], reverse=True)
        return discoveries
