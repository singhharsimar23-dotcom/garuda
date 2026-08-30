"""
Pydantic v2 Models for Telemetry Ingestion and Invariant Evaluation
Matches exact JSON schema emitted by garuda_agent daemon.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class RAPLPayload(BaseModel):
    pkg_w: Optional[float] = 0.0
    dram_w: Optional[float] = 0.0
    core_w: Optional[float] = 0.0
    unavailable: bool = False


class PerfPayload(BaseModel):
    instructions_ps: Optional[float] = 0.0
    cache_misses_ps: Optional[float] = 0.0
    cycles_ps: Optional[float] = 0.0
    unavailable: bool = False


class EntropyPayload(BaseModel):
    bits: int = 4096
    depleting: bool = False
    sustained_low_s: int = 0


class SchedstatPayload(BaseModel):
    steal_ratio: float = 0.0


class IASPayload(BaseModel):
    score: float = 0.0
    uncalibrated: bool = True
    workload_class: str = "BASELINING"
    channel_sigmas: Dict[str, float] = Field(default_factory=dict)


class TelemetryInput(BaseModel):
    agent_id: str
    hostname: str
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rapl: RAPLPayload
    perf: PerfPayload
    entropy: EntropyPayload
    schedstat: SchedstatPayload
    ias: Optional[IASPayload] = None
    flags: List[str] = Field(default_factory=list)


class TelemetryResponse(BaseModel):
    status: str = "success"
    message: str
    observation_id: Optional[str] = None
    computed_ias: float
    anomaly_level: str
    workload_class: str
    triggers: List[str] = Field(default_factory=list)


class FleetFusionAlert(BaseModel):
    alert_id: str
    alert_type: str = "LATERAL_MOVEMENT"
    confidence_source: str = "FLEET_CORRELATION"
    affected_hosts: List[str]
    workload_class: str
    window_start: datetime
    window_end: datetime
    evidence_description: str
