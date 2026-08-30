"""
KALI Online Technique Detection Bayesian Calibration
Applies continuous Beta conjugate updates on P_detection for simulated and operational ATT&CK techniques.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("kali.online_calibration")


class KaliOnlineCalibrator:
    """
    Maintains Beta prior concentration parameters (N=20) and updates P_detection per technique.
    """

    def __init__(self, prior_concentration: float = 20.0):
        self.prior_concentration = prior_concentration
        self._estimates: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "p_detection": 0.50,
            "total_simulations": 0,
            "total_detections": 0,
        })

    def get_estimate(self, technique_id: str) -> float:
        return self._estimates[technique_id]["p_detection"]

    def calibrate_technique(
        self,
        technique_id: str,
        detected: bool,
        ias_achieved: float = 0.0,
        supabase_client=None,
    ) -> float:
        rec = self._estimates[technique_id]
        current_p = rec["p_detection"]

        alpha_prior = current_p * self.prior_concentration
        beta_prior = (1.0 - current_p) * self.prior_concentration

        lik = 1.0 if detected else 0.0

        alpha_post = alpha_prior + lik
        beta_post = beta_prior + (1.0 - lik)

        new_p = round(alpha_post / (alpha_post + beta_post), 4)

        rec["p_detection"] = new_p
        rec["total_simulations"] += 1
        if detected:
            rec["total_detections"] += 1

        if supabase_client:
            try:
                supabase_client.table("kali_technique_estimates").upsert({
                    "technique_id": technique_id,
                    "p_detection": new_p,
                    "total_simulations": rec["total_simulations"],
                    "total_detections": rec["total_detections"],
                    "last_calibrated_at": datetime.now(timezone.utc).isoformat(),
                }, on_conflict="technique_id").execute()
            except Exception as e:
                logger.debug(f"Failed persisting kali estimate to Supabase: {e}")

        logger.info(
            f"[KALI CALIBRATION] Technique '{technique_id}' updated: "
            f"P_detection={new_p:.4f} (Detected={detected}, SimCount={rec['total_simulations']})"
        )
        return new_p


_kali_calibrator = KaliOnlineCalibrator()


def get_kali_online_calibrator() -> KaliOnlineCalibrator:
    return _kali_calibrator
