"""
Pydantic Schemas and Domain Models for SENTINEL Autonomous Brain
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceNode(BaseModel):
    id: str
    source_table: str
    event_type: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    weight: float = 1.0


class CampaignState(BaseModel):
    campaign_id: Optional[str] = None
    hostname: str
    fusion_score: float = 0.0
    evidence_chain: List[EvidenceNode] = Field(default_factory=list)
    brahma_posterior: Dict[str, float] = Field(default_factory=dict)
    sidecopy_posterior: Dict[str, float] = Field(default_factory=dict)
    attribution_status: str = "ACCUMULATING EVIDENCE (0/15)"
    first_anomaly_at: Optional[datetime] = None
    last_anomaly_at: Optional[datetime] = None
    dharma_actions: List[str] = Field(default_factory=list)
    analyst_labels: List[str] = Field(default_factory=list)
    hypothesis: Optional[str] = None
    next_step_prediction: Optional[str] = None
    peak_ias: float = 0.0
    last_feature_vector: Optional[List[float]] = None


class ObservationEvent(BaseModel):
    table: str
    action: str = "INSERT"
    record: Dict[str, Any]


class MultiHostLink(BaseModel):
    host_a: str
    host_b: str
    tactic_a: str
    tactic_b: str
    joint_fusion_score: float
    lateral_movement_confirmed: bool = False
    campaign_ids: List[str] = Field(default_factory=list)


class CanaryTriggerPayload(BaseModel):
    token_id: str
    requester_ip: Optional[str] = None
    user_agent: Optional[str] = None
    opened_at: Optional[datetime] = None
    details: Dict[str, Any] = Field(default_factory=dict)
