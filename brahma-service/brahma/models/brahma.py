"""
Pydantic Models for BRAHMA Adversary & Kill Chain Service
Strictly complies with the Anti-Hallucination Charter: NO confidence percentages.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ObserveInput(BaseModel):
    hostname: str
    ias_score: float
    channel_sigmas: Dict[str, float] = Field(default_factory=dict)
    workload_class: str = "BASELINING"
    observed_at: Optional[str] = None
    eppi_technique_id: Optional[str] = None
    source: str = "AXIOM_II_PHYSICS_ENGINE"


class ObserveResponse(BaseModel):
    status: str = "success"
    hostname: str
    observation_count: int
    attribution_status: str
    top_tactic: str
    top_tactic_mass: float
    posterior: Dict[str, float]


class KillChainAssessment(BaseModel):
    hostname: str
    actor: str = "APT36 (Transparent Tribe)"
    observation_count: int
    attribution_status: str
    top_tactic: str
    top_tactic_mass: float
    posterior: Dict[str, float]
    alpha_counts: List[float]
    evidence_summary: Dict[str, Any]


class KillChainEvidenceResponse(BaseModel):
    hostname: str
    attribution_status: str
    actor: str = "APT36 (Transparent Tribe)"
    evidence: List[str]
    evidence_summary: Dict[str, Any]


# Legacy / Compatibility models without fake confidence percentages
class BrahmaUpdateRequest(BaseModel):
    agent_id: str
    hostname: str
    ias_score: float
    top_channels: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: Optional[datetime] = None


class BrahmaUpdateResponse(BaseModel):
    status: str = "success"
    agent_id: str
    actor_id: str = "APT36 (Transparent Tribe)"
    map_tactic: str = "execution"
    predicted_next_tactic: str = "defense-evasion"
    observation_count: int = 1
    attribution_status: str = "ACCUMULATING EVIDENCE (1/15 minimum)"
    posterior: Dict[str, float] = Field(default_factory=dict)


class AdversaryAssessmentResponse(BaseModel):
    agent_id: str
    actor_id: str = "APT36 (Transparent Tribe)"
    map_tactic: str = "execution"
    predicted_next_tactic: str = "defense-evasion"
    observation_count: int = 1
    attribution_status: str = "ACCUMULATING EVIDENCE (1/15 minimum)"
    posterior: Dict[str, float] = Field(default_factory=dict)


class GrammarExpansionRequest(BaseModel):
    agent_id: str
    context: Optional[str] = None


class GrammarExpansionResponse(BaseModel):
    status: str = "success"
    agent_id: str
    generated_rules: List[str] = Field(default_factory=list)


class TTPMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
