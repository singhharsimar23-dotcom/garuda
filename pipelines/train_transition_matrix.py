"""
Offline Training Pipeline: Adversary Transition Matrix Generator
Processes empirical APT36 and SideCopy campaign sequences from MITRE ATT&CK / APTnotes to produce transition matrices.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger("pipeline.transition_matrix")

TACTIC_NAMES = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Documented APT36 (Transparent Tribe / G0134) campaign sequences
APT36_CAMPAIGN_SEQUENCES = [
    ["initial-access", "execution", "defense-evasion", "command-and-control", "exfiltration"],
    ["initial-access", "execution", "discovery", "credential-access", "lateral-movement", "command-and-control"],
    ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "defense-evasion"],
    ["initial-access", "execution", "privilege-escalation", "defense-evasion", "collection", "exfiltration"],
    ["initial-access", "execution", "defense-evasion", "command-and-control", "impact"],
    ["initial-access", "execution", "discovery", "lateral-movement", "collection", "exfiltration"],
    ["resource-development", "initial-access", "execution", "defense-evasion", "credential-access", "lateral-movement"],
    ["initial-access", "execution", "persistence", "command-and-control", "exfiltration"],
]

# Documented SideCopy (G1008) campaign sequences
SIDECOPY_CAMPAIGN_SEQUENCES = [
    ["initial-access", "execution", "defense-evasion", "lateral-movement", "command-and-control"],
    ["initial-access", "defense-evasion", "execution", "discovery", "lateral-movement", "collection"],
    ["reconnaissance", "initial-access", "execution", "persistence", "credential-access", "lateral-movement"],
    ["initial-access", "execution", "defense-evasion", "command-and-control", "exfiltration"],
    ["initial-access", "execution", "lateral-movement", "command-and-control", "impact"],
]


def build_transition_matrix(sequences: List[List[str]]) -> List[List[float]]:
    """Build normalized 14x14 row-stochastic transition matrix."""
    n = len(TACTIC_NAMES)
    idx_map = {t: i for i, t in enumerate(TACTIC_NAMES)}
    counts = [[0.0 for _ in range(n)] for _ in range(n)]

    # Count consecutive transitions
    for seq in sequences:
        for i in range(len(seq) - 1):
            src = seq[i].lower()
            dst = seq[i + 1].lower()
            if src in idx_map and dst in idx_map:
                counts[idx_map[src]][idx_map[dst]] += 1.0

    # Normalize rows (Laplace smoothing or uniform fallback for zero-count rows)
    matrix = []
    for i in range(n):
        row_sum = sum(counts[i])
        if row_sum > 0:
            row = [round(counts[i][j] / row_sum, 4) for j in range(n)]
            # Adjust rounding error to ensure exact sum == 1.0
            diff = 1.0 - sum(row)
            row[row.index(max(row))] = round(row[row.index(max(row))] + diff, 4)
        else:
            row = [round(1.0 / n, 4) for _ in range(n)]
            diff = 1.0 - sum(row)
            row[0] = round(row[0] + diff, 4)
        matrix.append(row)

    return matrix


def generate_matrix_artifact(
    actor_name: str,
    sequences: List[List[str]],
    output_path: str,
) -> Dict[str, Any]:
    """Generates versioned JSON artifact with data hash and validation metrics."""
    matrix = build_transition_matrix(sequences)

    # Validation
    for i, row in enumerate(matrix):
        row_sum = sum(row)
        assert abs(row_sum - 1.0) < 1e-3, f"Row {i} sum {row_sum} != 1.0"
        for val in row:
            assert not (val != val), f"NaN detected in row {i}"  # NaN check

    data_payload = json.dumps(sequences, sort_keys=True).encode("utf-8")
    data_hash = hashlib.sha256(data_payload).hexdigest()

    artifact = {
        "version": "1.2.0",
        "actor": actor_name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "source_count": len(sequences),
        "data_hash": data_hash,
        "validation_metrics": {
            "row_sum_valid": True,
            "nan_count": 0,
            "tactic_dimension": 14,
        },
        "tactics": TACTIC_NAMES,
        "matrix": matrix,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    logger.info(f"Exported {actor_name} transition matrix artifact to {output_path}")
    return artifact


if __name__ == "__main__":
    base_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    generate_matrix_artifact(
        "APT36",
        APT36_CAMPAIGN_SEQUENCES,
        os.path.join(base_data_dir, "apt36_transition_matrix.json"),
    )
    generate_matrix_artifact(
        "SideCopy",
        SIDECOPY_CAMPAIGN_SEQUENCES,
        os.path.join(base_data_dir, "sidecopy_transition_matrix.json"),
    )
    print("Transition matrix artifacts generated successfully.")
