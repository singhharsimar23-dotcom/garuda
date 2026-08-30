"""
BRAHMA Pydantic Data Models
Schemas for adversary modeling, Bayesian kill-chain progression, and grammar expansion.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BrahmaUpdateRequest(BaseModel):
    """Payload received from AXIOM upon anomaly detection."""
    agent_id: str
    hostname: str
    ias_score: float
    anomaly_level: str
    top_channels: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: Optional[float] = None


class BrahmaUpdateResponse(BaseModel):
    """Result of Bayesian kill-chain tracking and adversary attribution."""
    status: str = "PROCESSED"
    agent_id: str
    actor_id: str
    map_tactic: str
    predicted_next_tactic: str
    confidence: float
    observation_count: int
    convergence_status: str
    entropy_bits: float
    grammar_expanded: bool = False


class AdversaryAssessmentResponse(BaseModel):
    """Full adversary state assessment for an asset."""
    agent_id: str
    actor_id: str
    map_tactic: str
    predicted_next_tactic: str
    confidence: float
    observation_count: int
    convergence_status: str
    entropy_bits: float
    kill_chain_posterior: Dict[str, float]
    grammar_rules: Optional[List[Dict[str, Any]]] = None
    last_anomaly_at: str


class GrammarExpansionRequest(BaseModel):
    """Request to expand grammar for off-pattern adversary behavior."""
    agent_id: str
    current_tactic: str
    observed_channels: List[Dict[str, Any]] = Field(default_factory=list)
    entropy_bits: float = 2.5


class GrammarExpansionResponse(BaseModel):
    """Grammar expansion output."""
    agent_id: str
    expansion_triggered: bool
    new_rules: List[str]
    suggested_techniques: List[str]
    explanation: str


class TTPMapping(BaseModel):
    """MITRE ATT&CK technique to physical channel likelihood mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    likelihood: float
