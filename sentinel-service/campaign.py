"""
Campaign State Management & Persistence for SENTINEL
Tracks autonomous lifecycle of host campaigns from initiation to containment or clean resolution.
"""

from datetime import datetime, timezone, timedelta
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
import uuid

try:
    from sentinel_models import CampaignState, EvidenceNode
except ImportError:
    from models import CampaignState, EvidenceNode


logger = logging.getLogger("sentinel.campaign")


class CampaignManager:
    """
    Manages in-memory and persistent campaign records per host.
    """

    def __init__(self, log_threshold: float = 1.5, medium_threshold: float = 3.0):
        self.log_threshold = log_threshold
        self.medium_threshold = medium_threshold
        self.host_states: Dict[str, CampaignState] = {}

    def get_or_create_host_state(self, hostname: str) -> CampaignState:
        if hostname not in self.host_states:
            self.host_states[hostname] = CampaignState(hostname=hostname)
        return self.host_states[hostname]

    async def update_host_campaign(
        self,
        hostname: str,
        ias_score: float,
        fusion_score: float,
        evidence_node: EvidenceNode,
        brahma_posterior: Optional[Dict[str, float]] = None,
        sidecopy_posterior: Optional[Dict[str, float]] = None,
        attribution_status: Optional[str] = None,
        dharma_action: Optional[str] = None,
        supabase_client=None,
    ) -> CampaignState:
        """
        Processes incoming evidence node and evaluates campaign state transitions.
        """
        state = self.get_or_create_host_state(hostname)
        now = datetime.now(timezone.utc)

        # Append evidence node
        state.evidence_chain.append(evidence_node)
        state.fusion_score = fusion_score
        state.peak_ias = max(state.peak_ias, ias_score)
        state.last_anomaly_at = now

        if brahma_posterior:
            state.brahma_posterior = brahma_posterior
        if sidecopy_posterior:
            state.sidecopy_posterior = sidecopy_posterior
        if attribution_status:
            state.attribution_status = attribution_status
        if dharma_action and dharma_action not in state.dharma_actions:
            state.dharma_actions.append(dharma_action)

        # 1. Initiate New Campaign if None Active
        if not state.campaign_id and fusion_score >= self.log_threshold:
            state.campaign_id = str(uuid.uuid4())
            state.first_anomaly_at = now
            state.attribution_status = attribution_status or "ACCUMULATING EVIDENCE (1/15)"
            logger.info(f"Initiated new Campaign '{state.campaign_id}' for host '{hostname}' (Fusion={fusion_score:.2f}).")

            if supabase_client:
                try:
                    supabase_client.table("campaigns").insert({
                        "id": state.campaign_id,
                        "hostname": hostname,
                        "start_at": state.first_anomaly_at.isoformat(),
                        "attribution_actor": "APT36 (Transparent Tribe)",
                        "attribution_status": state.attribution_status,
                        "peak_ias": state.peak_ias,
                        "fusion_score": state.fusion_score,
                        "resolution": "ACTIVE",
                    }).execute()
                except Exception as e:
                    logger.warning(f"Failed inserting campaign to Supabase: {e}")

        # 2. Update Active Campaign
        elif state.campaign_id:
            top_tactic_weight = max(state.brahma_posterior.values()) if state.brahma_posterior else 0.45
            hours_since_first = (now - state.first_anomaly_at).total_seconds() / 3600.0 if state.first_anomaly_at else 0.0

            current_features = [top_tactic_weight, fusion_score, ias_score, min(10.0, hours_since_first)]

            # Feature Drift Check (Euclidean distance > 2.0)
            if state.last_feature_vector:
                dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(current_features, state.last_feature_vector)))
                if dist > 2.0:
                    logger.warning(f"Feature vector drift ({dist:.2f} > 2.0) on host '{hostname}'. Flagging for review.")
                    if "FEATURE_DRIFT_REVIEW" not in state.analyst_labels:
                        state.analyst_labels.append("FEATURE_DRIFT_REVIEW")

            state.last_feature_vector = current_features

            # Check Close Conditions
            await self._evaluate_close_conditions(state, now, ias_score, supabase_client)

            if supabase_client:
                try:
                    supabase_client.table("campaigns").update({
                        "fusion_score": state.fusion_score,
                        "peak_ias": state.peak_ias,
                        "attribution_status": state.attribution_status,
                        "dharma_actions_taken": state.dharma_actions,
                        "analyst_labels": state.analyst_labels,
                        "updated_at": now.isoformat(),
                    }).eq("id", state.campaign_id).execute()
                except Exception as e:
                    logger.debug(f"Campaign update to Supabase failed: {e}")

        return state

    async def _evaluate_close_conditions(
        self,
        state: CampaignState,
        now: datetime,
        current_ias: float,
        supabase_client=None,
    ) -> None:
        """Evaluate campaign termination criteria."""
        if not state.first_anomaly_at or not state.campaign_id:
            return

        duration_hours = (now - state.first_anomaly_at).total_seconds() / 3600.0

        resolution = None
        # 1. Clean resolution after 48h calm
        if current_ias < self.log_threshold and state.last_anomaly_at:
            calm_hours = (now - state.last_anomaly_at).total_seconds() / 3600.0
            if calm_hours >= 48.0:
                resolution = "RESOLVED_CLEAN"

        # 2. Contained after DHARMA action
        if state.dharma_actions and current_ias < self.log_threshold:
            resolution = "RESOLVED_CONTAINED"

        # 3. Persistent campaign escalation (> 7 days with elevated IAS)
        if duration_hours >= 168.0 and current_ias >= self.medium_threshold:
            resolution = "PERSISTENT_CAMPAIGN"

        if resolution:
            logger.info(f"Campaign '{state.campaign_id}' transitioned to status: {resolution}")
            if supabase_client:
                try:
                    supabase_client.table("campaigns").update({
                        "end_at": now.isoformat(),
                        "resolution": resolution,
                        "duration_hours": round(duration_hours, 2),
                        "updated_at": now.isoformat(),
                    }).eq("id", state.campaign_id).execute()
                except Exception as e:
                    logger.debug(f"Failed closing campaign in Supabase: {e}")

            # Reset in-memory campaign state if closed
            if resolution in ("RESOLVED_CLEAN", "RESOLVED_CONTAINED"):
                state.campaign_id = None


_campaign_manager = CampaignManager()


def get_campaign_manager() -> CampaignManager:
    return _campaign_manager
