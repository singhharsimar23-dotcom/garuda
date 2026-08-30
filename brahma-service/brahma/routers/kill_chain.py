"""
Kill Chain API Router
Serves real Bayesian kill chain posterior distributions and evidence summaries.
Strictly returns evidence-count-based language and zero confidence percentages.
"""

import logging
from fastapi import APIRouter, HTTPException, status

from ..bayesian_engine import get_bayesian_engine
from ..models.brahma import KillChainAssessment, KillChainEvidenceResponse

logger = logging.getLogger("brahma.routers.kill_chain")
router = APIRouter(prefix="/api/v1", tags=["Kill Chain"])


@router.get(
    "/kill-chain/{hostname}",
    response_model=KillChainAssessment,
    status_code=status.HTTP_200_OK,
)
async def get_kill_chain_state(hostname: str):
    """
    Retrieve real Bayesian Dirichlet-Multinomial posterior distribution for a monitored host.
    """
    engine = get_bayesian_engine()
    state = engine.get_or_create_state(hostname)

    posterior = state.get_posterior()
    top_tactic, top_mass = state.get_top_tactic()
    attribution_status = state.evaluate_attribution_status()

    evidence_summary = {
        "physics_anomaly_events": state.observation_count,
        "medium_ias_observations": state.medium_ias_observations,
        "has_distinctive_physics_corroboration": state.has_distinctive_physics_corroboration,
        "max_distinctive_sigma": round(state.max_distinctive_sigma, 4),
        "top_tactic": top_tactic.upper(),
        "top_tactic_mass": top_mass,
        "stix_iocs_matched": state.stix_matches_count,
        "eppi_events_count": state.eppi_events_count,
        "ist_anomaly_count": state.ist_anomaly_count,
    }

    return KillChainAssessment(
        hostname=hostname,
        actor="APT36 (Transparent Tribe)",
        observation_count=state.observation_count,
        attribution_status=attribution_status,
        top_tactic=top_tactic.upper(),
        top_tactic_mass=top_mass,
        posterior=posterior,
        alpha_counts=state.alphas,
        evidence_summary=evidence_summary,
    )


@router.get(
    "/kill-chain/{hostname}/evidence",
    response_model=KillChainEvidenceResponse,
    status_code=status.HTTP_200_OK,
)
async def get_kill_chain_evidence(hostname: str):
    """
    Retrieve human-verifiable evidence chain for actor attribution without confidence percentages.
    """
    engine = get_bayesian_engine()
    state = engine.get_or_create_state(hostname)

    top_tactic, top_mass = state.get_top_tactic()
    attribution_status = state.evaluate_attribution_status()

    evidence_lines = [
        f"Attribution Evidence for {hostname}:",
        f"- {state.observation_count} total physics anomaly events recorded ({state.medium_ias_observations} with IAS >= 3.0)",
        f"- Physical Corroboration: {'CONFIRMED (Distinctive Channel Sigma >= 3.0)' if state.has_distinctive_physics_corroboration else 'ACCUMULATING'}",
        f"- Top Kill Chain Tactic: {top_tactic.upper()} (Posterior Probability Mass: {top_mass:.4f})",
        f"- EPPI Process Execution Events: {state.eppi_events_count}",
        f"- STIX C2 Indicators Matched: {state.stix_matches_count}",
        f"- IST Timezone Behavioral Overlap: {'YES (Documented APT36 operational hours)' if state.ist_anomaly_count > 0 else 'NO'}",
    ]

    evidence_summary = {
        "physics_anomaly_events": state.observation_count,
        "medium_ias_observations": state.medium_ias_observations,
        "has_distinctive_physics_corroboration": state.has_distinctive_physics_corroboration,
        "max_distinctive_sigma": round(state.max_distinctive_sigma, 4),
        "top_tactic": top_tactic.upper(),
        "top_tactic_mass": top_mass,
        "stix_iocs_matched": state.stix_matches_count,
        "eppi_events_count": state.eppi_events_count,
    }

    return KillChainEvidenceResponse(
        hostname=hostname,
        attribution_status=attribution_status,
        actor="APT36 (Transparent Tribe)",
        evidence=evidence_lines,
        evidence_summary=evidence_summary,
    )
