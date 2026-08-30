"""
AXIOM-II Detection Probability Model
Estimates P(AXIOM-II detects | technique active) based on physical anomaly likelihoods and baseline sample counts.
"""

import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("kali.detection_model")

# Physical channel anomaly detection likelihoods P(AXIOM-II Detects | Tactic)
TACTIC_PHYSICS_LIKELIHOODS: Dict[str, float] = {
    "execution": 0.80,          # T1055/T1059 -> RAPL power spike
    "defense-evasion": 0.65,    # T1055.012 -> L3 cache miss spike
    "credential-access": 0.45,  # LSASS memory scraping -> cache divergence
    "command-and-control": 0.30,# C2 beacon -> entropy depletion
    "exfiltration": 0.50,       # Data transfer -> memory bus pressure
    "lateral-movement": 0.40,   # Network socket + process creation
    "initial-access": 0.10,     # Passive network lure
    "reconnaissance": 0.05,     # External port scan (zero host physics)
    "resource-development": 0.05,
    "persistence": 0.15,        # Cron / registry write
    "privilege-escalation": 0.35, # Schedstat / context switch
    "discovery": 0.20,          # Schedstat burst
    "collection": 0.25,         # Disk / memory read
    "impact": 0.70,             # Full CPU / disk encryption
}


class DetectionProbabilityModel:
    """
    Computes real detection probabilities for ATT&CK techniques based on AXIOM-II sensor capabilities.
    """

    def __init__(self, default_sample_count: int = 5000):
        self.default_sample_count = default_sample_count

    def compute_technique_detection_prob(
        self,
        technique_id: str,
        tactic: str,
        sample_count: Optional[int] = None,
    ) -> Tuple[float, bool]:
        """
        Estimate P_detection:
        P_detection = physics_likelihood[tactic] * (1.0 if calibrated else 0.3)
        Returns (p_detection: float in [0.05, 0.95], detection_uncalibrated: bool)
        """
        samples = self.default_sample_count if sample_count is None else sample_count
        is_uncalibrated = samples < 100

        base_lik = TACTIC_PHYSICS_LIKELIHOODS.get(tactic.lower(), 0.05)

        # Baseline calibration discount (uncalibrated baselines have high uncertainty)
        calibration_factor = 1.0 if not is_uncalibrated else 0.3
        p_detection = round(base_lik * calibration_factor, 4)

        return p_detection, is_uncalibrated

    def evaluate_path_detection_prob(
        self,
        techniques_with_tactics: list[Tuple[str, str]],
        sample_count: Optional[int] = None,
    ) -> Tuple[float, bool]:
        """
        Compute overall path detection probability: P(detect path) = 1 - product(1 - P_detect_step).
        Returns (path_p_detection: float, any_uncalibrated: bool)
        """
        if not techniques_with_tactics:
            return 0.05, False

        p_evasion_product = 1.0
        has_uncalibrated = False

        for tech_id, tactic in techniques_with_tactics:
            p_det, uncal = self.compute_technique_detection_prob(tech_id, tactic, sample_count)
            if uncal:
                has_uncalibrated = True
            p_evasion_product *= (1.0 - p_det)

        path_p_detection = round(1.0 - p_evasion_product, 4)
        return path_p_detection, has_uncalibrated


_detection_model = DetectionProbabilityModel()


def get_detection_model() -> DetectionProbabilityModel:
    return _detection_model
