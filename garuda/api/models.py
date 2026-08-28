from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class AlertResponse(BaseModel):
    """Pydantic model representing a single enriched threat alert."""

    id: str
    domain: str
    score: int = Field(ge=0, le=100)
    status: str = "pending"
    signals: Dict[str, Any] = Field(default_factory=dict)
    sector: Optional[str] = "Unclassified"
    registrar: Optional[str] = None
    hosting_ip: Optional[str] = None
    hosting_asn: Optional[int] = None
    nic_match: Optional[str] = None
    nic_similarity: Optional[float] = None
    detected_at: Optional[str] = None
    registered_at: Optional[str] = None
    cluster_id: Optional[str] = None
    llm_narrative: Optional[str] = None
    screenshot_url: Optional[str] = None
    age_days: Optional[int] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    """Paginated collection of threat alerts."""

    alerts: List[AlertResponse]
    total: int
    page: int = 1
    limit: int = 50


class CampaignResponse(BaseModel):
    """Correlated APT36 attack campaign cluster."""

    id: Optional[str] = None
    cluster_id: str
    domain_count: int = 1
    registrar: Optional[str] = None
    hosting_asn: Optional[int] = None
    sectors: List[str] = Field(default_factory=list)
    estimated_attack_window_days: Optional[int] = None
    confidence: Optional[str] = "medium"
    created_at: Optional[str] = None
    domains: Optional[List[str]] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class CampaignListResponse(BaseModel):
    """List of all active campaign clusters."""

    campaigns: List[CampaignResponse]


class AuditLogEntry(BaseModel):
    """Immutable audit trail log record."""

    id: Optional[str] = None
    alert_id: Optional[str] = None
    action: str
    analyst_id: Optional[str] = None
    justification: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class StatsResponse(BaseModel):
    """Aggregated real-time SOC metrics and threat posture telemetry."""

    total_alerts_24h: int = 0
    critical_24h: int = 0
    confirmed_24h: int = 0
    confirmed_indicators_30d: int = 0
    corroborated_2plus_sources_30d: int = 0
    false_positive_rate_7d: float = 0.0
    active_campaigns: int = 0
    tension_index: float = 0.50
    conflict_mode: bool = False
    domains_monitored: int = 0
    last_collection_at: Optional[str] = None
    lifecycle_metrics: Dict[str, Any] = Field(default_factory=dict)


class ConfirmAlertRequest(BaseModel):
    """Request payload for analyst threat confirmation."""

    alert_id: str
    analyst_id: str
    justification: str = Field(..., min_length=10, description="Mandatory reason (minimum 10 characters)")


class RejectAlertRequest(BaseModel):
    """Request payload for analyst alert rejection / false positive triage."""

    alert_id: str
    analyst_id: str
    justification: str
    reason_code: str = Field(
        default="other",
        description="Reason code: 'legitimate_domain', 'known_whitelist', 'insufficient_evidence', 'other'",
    )


class WhitelistRequest(BaseModel):
    """Request payload for whitelisting a domain."""

    domain: str
    reason: str
    analyst_id: str


class ConfirmAlertResponse(BaseModel):
    """Response payload returned upon analyst confirmation."""

    success: bool = True
    alert_id: str
    status: str = "confirmed"
    advisory_draft: Optional[str] = None
    stix_id: Optional[str] = None
    yara_rule: Optional[str] = None
