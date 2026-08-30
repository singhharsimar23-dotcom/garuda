"""
Anomaly and Provenance Pydantic Schemas
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .telemetry import AnomalyLevel


class AnomalyEvent(BaseModel):
    """Event model representing a detected physical anomaly."""
    alert_id: str
    agent_id: str
    hostname: str
    detected_at: str
    ias_score: float
    anomaly_level: AnomalyLevel
    calibrated: bool
    threshold_value: float
    top_channels: List[Dict[str, Any]]
    narrative: Optional[str] = None
    kill_chain_tactic: Optional[str] = "Execution"
    confidence: float = 0.0


class AnomalyAlertRecord(BaseModel):
    """Database entity representation of an anomaly alert."""
    alert_id: str
    agent_id: str
    detected_at: str
    ias_score: float
    anomaly_level: str
    top_channels: Dict[str, Any]
    narrative: Optional[str]
    telegram_sent: bool = False
    dharma_triggered: bool = False


class ProvenanceRequest(BaseModel):
    """Request to verify host TPM PCRs and process lineage."""
    agent_id: str
    hostname: str
    tpm_pcrs: Dict[str, str]
    target_process: Optional[str] = None


class ProvenanceResponse(BaseModel):
    """Result of platform provenance and integrity assessment."""
    agent_id: str
    integrity_valid: bool
    pcr_status: Dict[str, str]
    trust_level: str
    message: str
