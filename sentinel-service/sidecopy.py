"""
Parallel SideCopy (MITRE Group G1008) Adversary Model
Tracks SideCopy actor state independently of APT36, detecting divergence or multi-actor coordination.
"""

from collections import defaultdict
import logging
import math
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.sidecopy")

TACTIC_NAMES = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# SideCopy (G1008) Empirical Prior (favors masquerading T1036 and SMB lateral movement T1021.002)
SIDECOPY_FALLBACK_COUNTS: Dict[str, float] = {
    "reconnaissance": 3.0,
    "resource-development": 6.0,
    "initial-access": 12.0,  # Heavy masquerading / fake lure documents
    "execution": 11.0,       # .NET / C# compiled payloads
    "persistence": 7.0,
    "privilege-escalation": 4.0,
    "defense-evasion": 9.0,
    "credential-access": 5.0,
    "discovery": 6.0,
    "lateral-movement": 9.0, # SMB / Admin Shares
    "collection": 6.0,
    "command-and-control": 10.0,
    "exfiltration": 5.0,
    "impact": 1.0,
}


class SideCopyModel:
    """
    Maintains parallel Bayesian Dirichlet posterior for SideCopy (MITRE Group G1008).
    """

    def __init__(self):
        self.alpha_prior = [SIDECOPY_FALLBACK_COUNTS.get(t, 1.0) + 1.0 for t in TACTIC_NAMES]
        self._host_alphas: Dict[str, List[float]] = {}

    def get_or_create_host_alphas(self, hostname: str) -> List[float]:
        if hostname not in self._host_alphas:
            self._host_alphas[hostname] = list(self.alpha_prior)
        return self._host_alphas[hostname]

    def update_observation(
        self,
        hostname: str,
        ias_score: float,
        top_channels: List[str],
    ) -> Dict[str, float]:
        """Update SideCopy Dirichlet posterior from hardware physics observation."""
        alphas = self.get_or_create_host_alphas(hostname)

        # Likelihood mapping for SideCopy (.NET compiled binaries -> higher instruction mix, SMB network)
        indicator = 1.0 if ias_score >= 3.0 else (ias_score / 3.0 if ias_score >= 1.5 else 0.05)

        for i, tactic in enumerate(TACTIC_NAMES):
            lik = 0.10
            if tactic == "initial-access":
                lik = 0.70
            elif tactic == "execution":
                lik = 0.85
            elif tactic == "lateral-movement":
                lik = 0.75
            elif tactic == "command-and-control":
                lik = 0.60

            alphas[i] += lik * indicator
            alphas[i] = round(alphas[i], 4)

        total = sum(alphas)
        posterior = {tactic: round(alphas[i] / total, 4) for i, tactic in enumerate(TACTIC_NAMES)}
        return posterior

    def compute_kl_divergence(
        self,
        apt36_posterior: Dict[str, float],
        sidecopy_posterior: Dict[str, float],
    ) -> Tuple[float, Optional[str]]:
        """
        Calculates symmetric Kullback-Leibler (KL) divergence between APT36 and SideCopy posteriors:
        D_KL(P || Q) = sum(P(i) * log(P(i) / Q(i)))
        """
        if not apt36_posterior or not sidecopy_posterior:
            return 0.0, None

        eps = 1e-6
        kl_forward = 0.0
        kl_reverse = 0.0

        for tactic in TACTIC_NAMES:
            p = max(eps, apt36_posterior.get(tactic, 1.0 / len(TACTIC_NAMES)))
            q = max(eps, sidecopy_posterior.get(tactic, 1.0 / len(TACTIC_NAMES)))
            kl_forward += p * math.log(p / q)
            kl_reverse += q * math.log(q / p)

        sym_kl = round((kl_forward + kl_reverse) / 2.0, 4)

        assessment = None
        if sym_kl > 0.30:
            assessment = "Evidence ambiguous between APT36 and SideCopy — possible coordinated operation"
        else:
            assessment = "Posteriors converging on consistent actor profile"

        return sym_kl, assessment


_sidecopy_model = SideCopyModel()


def get_sidecopy_model() -> SideCopyModel:
    return _sidecopy_model
