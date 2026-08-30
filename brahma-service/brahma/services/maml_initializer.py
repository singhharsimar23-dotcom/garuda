"""
MAML & Empirical Prior Initializer
Initializes adversary tactic priors using MITRE ATT&CK base frequencies and meta-learning weights.
"""

import logging
import os
import pickle
from typing import Dict, Optional

logger = logging.getLogger("brahma.services.maml")

# Base empirical prior frequencies derived from APT36 & SideCopy MITRE ATT&CK profiles
DEFAULT_PRIOR_WEIGHTS: Dict[str, float] = {
    "reconnaissance": 0.05,
    "resource-development": 0.05,
    "initial-access": 0.15,
    "execution": 0.20,
    "persistence": 0.10,
    "privilege-escalation": 0.05,
    "defense-evasion": 0.15,
    "credential-access": 0.05,
    "discovery": 0.05,
    "lateral-movement": 0.02,
    "collection": 0.03,
    "command-and-control": 0.08,
    "exfiltration": 0.01,
    "impact": 0.01,
}


def load_maml_priors(weights_path: Optional[str] = None) -> Dict[str, float]:
    """
    Loads MAML trained prior weights from pickle artifact or falls back to empirical priors.
    """
    if weights_path and os.path.exists(weights_path):
        try:
            with open(weights_path, "rb") as f:
                weights = pickle.load(f)
                if isinstance(weights, dict):
                    logger.info(f"Loaded trained MAML priors from {weights_path}")
                    total = sum(weights.values())
                    return {k: v / total for k, v in weights.items()}
        except Exception as e:
            logger.warning(f"Failed to load MAML weights file {weights_path}: {e}")

    # Fallback to normalized empirical defaults
    total = sum(DEFAULT_PRIOR_WEIGHTS.values())
    return {k: v / total for k, v in DEFAULT_PRIOR_WEIGHTS.items()}
