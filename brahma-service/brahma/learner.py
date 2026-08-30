"""
BRAHMA Online Learning & Model Drift Engine
Applies Bayesian Dirichlet updates from operator labels and tracks statistical model drift over 50-label batches.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("brahma.learner")

TACTIC_NAMES = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

DEFAULT_LIKELIHOODS: Dict[str, float] = {
    "execution": 0.85,
    "defense-evasion": 0.75,
    "credential-access": 0.65,
    "command-and-control": 0.50,
    "exfiltration": 0.60,
    "lateral-movement": 0.45,
    "initial-access": 0.15,
    "reconnaissance": 0.05,
    "resource-development": 0.05,
    "persistence": 0.20,
    "privilege-escalation": 0.40,
    "discovery": 0.30,
    "collection": 0.35,
    "impact": 0.85,
}


class BrahmaOnlineLearner:
    """
    Manages online label updates, rate-limiting, and 50-sample drift evaluations.
    """

    def __init__(self):
        self._host_alphas: Dict[str, List[float]] = {}
        self._recent_labels: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._total_label_count = 0
        self._rate_limit_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self._overflow_queue: List[Dict[str, Any]] = []

    def get_or_create_host_alphas(self, hostname: str) -> List[float]:
        if hostname not in self._host_alphas:
            # Uniform prior baseline
            self._host_alphas[hostname] = [5.0 for _ in range(len(TACTIC_NAMES))]
        return self._host_alphas[hostname]

    def check_rate_limit(self, hostname: str, max_per_minute: int = 10) -> bool:
        """Enforces rate limit of max 10 labels per host per minute."""
        now = datetime.now(timezone.utc)
        timestamps = self._rate_limit_tracker[hostname]
        # Keep only timestamps in last 60s
        self._rate_limit_tracker[hostname] = [t for t in timestamps if (now - t).total_seconds() < 60.0]

        if len(self._rate_limit_tracker[hostname]) >= max_per_minute:
            return False

        self._rate_limit_tracker[hostname].append(now)
        return True

    async def apply_label(
        self,
        hostname: str,
        tactic: str,
        label: str,
        feature_vector: Optional[Dict[str, Any]] = None,
        evidence_ids: Optional[List[str]] = None,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Applies POSITIVE (+2.0 * likelihood) or NEGATIVE (-0.5 * likelihood) Dirichlet update.
        """
        # Check Rate Limit (Anti-Spoofing / Flood Guard)
        if not self.check_rate_limit(hostname, max_per_minute=10):
            logger.warning(f"Rate limit exceeded for {hostname}. Queueing label for gradual processing.")
            self._overflow_queue.append({
                "hostname": hostname,
                "tactic": tactic,
                "label": label,
                "feature_vector": feature_vector,
                "evidence_ids": evidence_ids,
            })
            return {"status": "queued", "hostname": hostname, "rate_limited": True}

        alphas = self.get_or_create_host_alphas(hostname)
        tactic_clean = tactic.lower()
        if tactic_clean not in TACTIC_NAMES:
            tactic_clean = "execution"

        idx = TACTIC_NAMES.index(tactic_clean)
        lik = DEFAULT_LIKELIHOODS.get(tactic_clean, 0.50)

        label_clean = label.upper()
        if label_clean == "POSITIVE":
            alphas[idx] += lik * 2.0
        elif label_clean == "NEGATIVE":
            # Soft decrease, strictly bounded at >= 0.01
            alphas[idx] = max(0.01, alphas[idx] - (lik * 0.5))

        alphas[idx] = round(alphas[idx], 4)
        self._total_label_count += 1

        label_record = {
            "hostname": hostname,
            "tactic": tactic_clean,
            "label": label_clean,
            "feature_vector": feature_vector or {},
            "evidence_ids": evidence_ids or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._recent_labels[tactic_clean].append(label_record)

        # Evaluate Model Drift every 50 total labels
        drift_report = None
        if self._total_label_count % 50 == 0:
            drift_report = await self.evaluate_model_drift(supabase_client)

        # Persist label history to Supabase
        if supabase_client:
            try:
                supabase_client.table("brahma_label_history").insert(label_record).execute()
            except Exception as e:
                logger.debug(f"Failed writing label history to Supabase: {e}")

        logger.info(
            f"[ONLINE BRAHMA] Label '{label_clean}' applied for {hostname} on {tactic_clean}. "
            f"Updated alpha={alphas[idx]:.4f} (Total Labels: {self._total_label_count})"
        )

        return {
            "status": "applied",
            "hostname": hostname,
            "tactic": tactic_clean,
            "new_alpha": alphas[idx],
            "total_labels": self._total_label_count,
            "drift_evaluated": drift_report is not None,
        }

    async def evaluate_model_drift(self, supabase_client=None) -> List[Dict[str, Any]]:
        """
        Compares observed positive rate vs expected physics likelihood across recent labels.
        Flags discrepancy > 0.20 for analyst review.
        """
        discrepancies = []
        for tactic, records in self._recent_labels.items():
            if len(records) < 5:
                continue

            positives = sum(1 for r in records if r["label"] == "POSITIVE")
            total = len(records)
            observed_rate = round(positives / total, 4)
            expected = DEFAULT_LIKELIHOODS.get(tactic, 0.50)
            diff = round(abs(observed_rate - expected), 4)

            flagged = diff > 0.20
            drift_entry = {
                "tactic": tactic,
                "observed_rate": observed_rate,
                "expected_likelihood": expected,
                "discrepancy": diff,
                "flagged_for_review": flagged,
            }
            discrepancies.append(drift_entry)

            if flagged:
                logger.warning(
                    f"[MODEL DRIFT] Discrepancy on '{tactic}': Observed={observed_rate:.2f} vs Expected={expected:.2f} (Diff={diff:.2f} > 0.20)"
                )
                if supabase_client:
                    try:
                        supabase_client.table("model_drift_log").insert(drift_entry).execute()
                    except Exception as e:
                        logger.debug(f"Failed writing drift log: {e}")

        return discrepancies


_brahma_learner = BrahmaOnlineLearner()


def get_brahma_online_learner() -> BrahmaOnlineLearner:
    return _brahma_learner
