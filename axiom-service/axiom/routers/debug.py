"""
Debug and Validation Router
Allows injecting simulated anomalies for end-to-end testing of Telegram and Supabase alerting channels.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from ..config import AxiomSettings, get_settings
from ..models.telemetry import AnomalyLevel, IASResult
from ..services.anomaly_publisher import publish_anomaly_alert

router = APIRouter(prefix="/api/v1/debug", tags=["Debug"])


class InjectAnomalyRequest(BaseModel):
    agent_id: str = "debug-agent-01"
    hostname: str = "boss-linux-secnode"
    anomaly_level: AnomalyLevel = AnomalyLevel.CRITICAL
    ias_score: float = 6.42
    calibrated: bool = False


@router.post("/inject-anomaly")
async def inject_anomaly(
    request: InjectAnomalyRequest,
    settings: AxiomSettings = Depends(get_settings),
):
    """
    Injects a test anomaly event to verify Telegram and Supabase Realtime alerts.
    """
    ias_result = IASResult(
        score=request.ias_score,
        level=request.anomaly_level,
        channel_scores={"rapl_pkg": 5.8, "perf_cache": 3.2, "schedstat": 2.1},
        calibrated=request.calibrated,
        threshold_used={"LOG": 1.5, "MEDIUM": 3.0, "CRITICAL": 5.0},
        top_divergent_channels=[
            {"channel": "rapl_pkg", "score": 5.8, "delta_from_baseline": 850000.0},
            {"channel": "perf_cache", "score": 3.2, "delta_from_baseline": 42000.0},
        ],
    )

    result = await publish_anomaly_alert(
        agent_id=request.agent_id,
        hostname=request.hostname,
        ias_result=ias_result,
        settings=settings,
    )

    return {
        "status": "INJECTED",
        "result": result,
    }
