"""
KALI Deterministic Coverage Evaluator
Calculates estimated detection probability per candidate attack sequence against microarchitectural physics signatures.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("kali.coverage")

# Microarchitectural IAS detection weights per MITRE technique category
TECHNIQUE_DETECTION_WEIGHTS: Dict[str, float] = {
    "T1059": 0.85,  # Command & Scripting Interpreter (High RAPL core/pkg power)
    "T1055": 0.90,  # Process Injection (Severe L3 cache misses)
    "T1027": 0.75,  # Obfuscated Files / Payloads (Entropy depletion)
    "T1082": 0.40,  # System Information Discovery (Low hardware footprint)
    "T1071": 0.65,  # Application Layer C2 (Burst network latency / context switches)
    "T1041": 0.80,  # Exfiltration Over C2 (Sustained memory / socket burst)
    "T1566": 0.50,  # Phishing Attachment (User space launch)
}


def evaluate_path_coverage(techniques: List[str]) -> float:
    """
    Computes estimated detection probability P(detection) in range [0.0, 1.0].
    P(detection) = 1 - product(1 - p_step)
    """
    if not techniques:
        return 0.5

    p_miss = 1.0
    for tech in techniques:
        prefix = tech.split(".")[0]
        step_p = TECHNIQUE_DETECTION_WEIGHTS.get(prefix, 0.45)
        p_miss *= (1.0 - step_p)

    p_detect = 1.0 - p_miss
    # Ensure strictly bounded in [0.0, 1.0]
    return max(0.0, min(1.0, round(p_detect, 4)))
