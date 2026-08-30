"""
Telemetry Pydantic Schemas
Strict data models for raw host observations, baseline statistics, and detection responses.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class WorkloadClass(str, Enum):
    IDLE = "IDLE"
    COMPUTE_BOUND = "COMPUTE_BOUND"
    MEMORY_BOUND = "MEMORY_BOUND"
    IO_BOUND = "IO_BOUND"
    MIXED = "MIXED"


class AnomalyLevel(str, Enum):
    CLEAN = "CLEAN"
    LOG = "LOG"
    MEDIUM = "MEDIUM"
    CRITICAL = "CRITICAL"


class ChannelObservation(BaseModel):
    """Normalized observation per physical channel."""
    timestamp: float
    rapl_pkg_uw: Optional[float] = None
    rapl_dram_uw: Optional[float] = None
    rapl_core_uw: Optional[float] = None
    instructions: Optional[float] = None
    cache_misses: Optional[float] = None
    cycles: Optional[float] = None
    ipc: Optional[float] = None
    entropy_avail: Optional[float] = None
    sched_run_ms: Optional[float] = None
    sched_wait_ms: Optional[float] = None
    sched_delay_ratio: Optional[float] = None


class TelemetryObservation(BaseModel):
    """Raw single observation received from host agent."""
    timestamp: float
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    rapl_pkg_uw: Optional[float] = None
    rapl_dram_uw: Optional[float] = None
    rapl_core_uw: Optional[float] = None
    instructions: Optional[float] = None
    cache_misses: Optional[float] = None
    cycles: Optional[float] = None
    ipc: Optional[float] = None
    entropy_avail: Optional[float] = None
    sched_run_ms_per_sec: Optional[float] = None
    sched_wait_ms_per_sec: Optional[float] = None
    sched_delay_ratio: Optional[float] = None
    eppi_events: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    tpm_pcrs: Optional[Dict[str, str]] = None


class TelemetryRequest(BaseModel):
    """Batch payload sent by garuda-agent."""
    agent_id: str
    hostname: str
    readings: List[TelemetryObservation]
    timestamp: float

    @field_validator("readings")
    @classmethod
    def validate_readings_not_empty(cls, v: List[TelemetryObservation]) -> List[TelemetryObservation]:
        if not v:
            raise ValueError("Readings list must not be empty.")
        return v


class IASResult(BaseModel):
    """Output of Instruction/Anomaly Score evaluation."""
    score: float
    level: AnomalyLevel
    channel_scores: Dict[str, float]
    calibrated: bool
    threshold_used: Dict[str, float]
    top_divergent_channels: List[Dict[str, Any]] = Field(default_factory=list)


class AlmanacBaselineModel(BaseModel):
    """Statistical Gaussian baseline state for an agent and workload class."""
    agent_id: str
    workload_class: WorkloadClass
    mu: Dict[str, float]
    sigma: Dict[str, float]
    thresholds: Dict[str, float]
    observation_count: int = 0
    trust_established: bool = False


class TelemetryResponse(BaseModel):
    """Response returned to garuda-agent."""
    status: str = "PROCESSED"
    agent_id: str
    processed_count: int
    anomaly_level: AnomalyLevel
    ias_score: float
    calibrated: bool
    recommended_poll_interval_sec: float = 1.0
