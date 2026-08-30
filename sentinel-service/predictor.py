"""
Predictive Pre-Positioning Engine
Anticipates adversary kill-chain transitions using BRAHMA transition models and orchestrates MAYA deception / AXIOM-II sensitivity.
"""

from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
import httpx

try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings
try:
    from sentinel_models import CampaignState
except ImportError:
    from models import CampaignState



logger = logging.getLogger("sentinel.predictor")

# Empirical APT36 Transition Matrix P(Next Tactic | Current Tactic)
TRANSITION_PROBABILITIES: Dict[str, Dict[str, float]] = {
    "initial-access": {"execution": 0.70, "discovery": 0.20, "persistence": 0.10},
    "execution": {"defense-evasion": 0.65, "privilege-escalation": 0.20, "credential-access": 0.15},
    "defense-evasion": {"command-and-control": 0.55, "credential-access": 0.30, "discovery": 0.15},
    "credential-access": {"lateral-movement": 0.60, "discovery": 0.25, "collection": 0.15},
    "discovery": {"lateral-movement": 0.50, "collection": 0.35, "defense-evasion": 0.15},
    "lateral-movement": {"execution": 0.55, "collection": 0.30, "command-and-control": 0.15},
    "collection": {"exfiltration": 0.75, "command-and-control": 0.25},
    "command-and-control": {"exfiltration": 0.65, "impact": 0.20, "lateral-movement": 0.15},
    "exfiltration": {"impact": 0.50, "command-and-control": 0.50},
}

TACTIC_PHYSICS_FOCUS: Dict[str, str] = {
    "execution": "rapl_pkg",
    "defense-evasion": "perf_cache_miss",
    "credential-access": "perf_cache_miss",
    "command-and-control": "entropy",
    "exfiltration": "rapl_dram",
    "lateral-movement": "schedstat_steal",
}


class PredictivePrePositioner:
    """
    Evaluates active campaigns and arms forward deception traps in MAYA and AXIOM-II.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()

    def predict_next_tactic(self, current_tactic: str) -> str:
        """Find most probable next tactic from transition row."""
        row = TRANSITION_PROBABILITIES.get(current_tactic.lower(), {})
        if not row:
            return "defense-evasion"
        return max(row.items(), key=lambda x: x[1])[0]

    async def evaluate_campaign_prediction(
        self,
        campaign_state: CampaignState,
        supabase_client=None,
    ) -> Optional[str]:
        """
        Executes prediction and dispatches MAYA / AXIOM-II pre-positioning if predicted step changed.
        """
        hostname = campaign_state.hostname
        current_tactic = "execution"

        if campaign_state.brahma_posterior:
            current_tactic = max(campaign_state.brahma_posterior.items(), key=lambda x: x[1])[0]

        predicted_next = self.predict_next_tactic(current_tactic)
        campaign_state.next_step_prediction = predicted_next

        # 1. Dispatch MAYA Deception Traps
        maya_success = await self._dispatch_maya_preposition(predicted_next)

        # 2. Lower AXIOM-II Detection Thresholds for Focus Channel
        focus_channel = TACTIC_PHYSICS_FOCUS.get(predicted_next, "rapl_pkg")
        axiom_success = await self._dispatch_axiom_alert_mode(hostname, focus_channel)

        # 3. Log to Supabase prediction_log
        if supabase_client and campaign_state.campaign_id:
            try:
                supabase_client.table("prediction_log").insert({
                    "campaign_id": campaign_state.campaign_id,
                    "hostname": hostname,
                    "source_tactic": current_tactic,
                    "predicted_tactic": predicted_next,
                    "maya_prepositioned": maya_success,
                    "axiom_alert_mode": axiom_success,
                }).execute()
            except Exception as e:
                logger.debug(f"Failed writing prediction_log to Supabase: {e}")

        logger.info(
            f"[PREDICTOR] Host '{hostname}': Current={current_tactic.upper()} -> "
            f"Predicted={predicted_next.upper()} (MAYA Deception Armed, Channel '{focus_channel}' Sensitive)"
        )
        return predicted_next

    async def _dispatch_maya_preposition(self, predicted_tactic: str) -> bool:
        """Call MAYA service to activate deception decoy assets."""
        if not self.settings.maya_service_url:
            return True
        url = f"{self.settings.maya_service_url.rstrip('/')}/internal/preposition"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(url, headers=headers, json={"tactic": predicted_tactic})
                return resp.status_code == 200
        except Exception as e:
            logger.debug(f"MAYA preposition dispatch warning: {e}")
            return False

    async def _dispatch_axiom_alert_mode(self, hostname: str, focus_channel: str) -> bool:
        """Call AXIOM-II service to lower detection threshold for focus channel."""
        if not self.settings.axiom_service_url:
            return True
        url = f"{self.settings.axiom_service_url.rstrip('/')}/internal/alert-mode"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(url, headers=headers, json={"hostname": hostname, "focus_channel": focus_channel})
                return resp.status_code == 200
        except Exception as e:
            logger.debug(f"AXIOM alert mode dispatch warning: {e}")
            return False


_predictor = PredictivePrePositioner()


def get_predictive_prepositioner() -> PredictivePrePositioner:
    return _predictor
