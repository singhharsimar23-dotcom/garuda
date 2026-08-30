"""
Telemetry Ingestion and Physics Anomaly Detection Router
Processes batches of host physical channel measurements through the 13-step AXIOM detection pipeline.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from ..config import AxiomSettings, get_settings
from ..db.pool import get_db_pool
from ..db.queries import (
    insert_anomaly_alert,
    insert_physics_observations_bulk,
    insert_tpm_snapshot,
    upsert_monitored_agent,
)
from ..models.telemetry import (
    AnomalyLevel,
    TelemetryRequest,
    TelemetryResponse,
    WorkloadClass,
)
from ..services.almanac_service import AlmanacService
from ..services.anomaly_publisher import publish_anomaly_alert
from ..services.dharma_trigger import trigger_dharma
from ..services.ias_computer import compute_ias
from ..services.workload_classifier import classify_workload

logger = logging.getLogger("axiom.routers.telemetry")
router = APIRouter(prefix="/api/v1", tags=["Telemetry"])


def verify_agent_auth(
    authorization: Optional[str] = Header(None),
    settings: AxiomSettings = Depends(get_settings),
) -> str:
    """
    Validates Bearer token in Authorization header against AGENT_API_KEY.
    """
    if not settings.agent_api_key:
        return "authenticated_unrestricted"

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Bearer token required.",
        )

    token = authorization.split("Bearer ", 1)[1].strip()
    if token != settings.agent_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Agent API Key.",
        )

    return token


@router.post("/telemetry", response_model=TelemetryResponse)
async def ingest_telemetry(
    request: TelemetryRequest,
    auth: str = Depends(verify_agent_auth),
    settings: AxiomSettings = Depends(get_settings),
) -> TelemetryResponse:
    """
    Ingests a telemetry batch, performs workload classification, evaluates IAS against Gaussian baselines,
    updates baseline EMA, and triggers alerts/subsystems.
    """
    db_pool = await get_db_pool()
    almanac_svc = AlmanacService(db_pool)

    # 1. Heartbeat & Agent Registry
    if db_pool:
        await upsert_monitored_agent(
            pool=db_pool,
            agent_id=request.agent_id,
            hostname=request.hostname,
            poll_interval=1.0,
        )

    # Convert request readings to dictionaries
    raw_readings = [r.model_dump() for r in request.readings]

    # Process TPM snapshots if included in batch
    for r in request.readings:
        if r.tpm_pcrs and db_pool:
            await insert_tpm_snapshot(db_pool, request.agent_id, r.tpm_pcrs)

    # Use the most recent reading for real-time anomaly evaluation
    latest_reading = raw_readings[-1]

    # 2. Classify Workload
    workload_class = classify_workload(latest_reading)
    w_class_str = workload_class.value

    # 3. Load Baseline
    baseline = await almanac_svc.get_baseline(request.agent_id, w_class_str)
    trust_established = baseline.get("trust_established", False) if baseline else False

    # 4. Handle Baselining Phase (< 1000 observations / untrusted)
    if not trust_established:
        # Compute preliminary IAS with defaults
        ias_result = compute_ias(
            observed=latest_reading,
            baseline=baseline,
            default_thresholds={
                "LOG": settings.default_log_threshold,
                "MEDIUM": settings.default_medium_threshold,
                "CRITICAL": settings.default_critical_threshold,
            },
        )
        
        # In baselining phase, always keep level CLEAN and update baseline
        await almanac_svc.update_baseline(
            agent_id=request.agent_id,
            workload_class=w_class_str,
            observation=latest_reading,
            ias_score=0.0,  # Force clean during initialization
            log_threshold=settings.default_log_threshold,
        )

        if db_pool:
            await insert_physics_observations_bulk(
                pool=db_pool,
                agent_id=request.agent_id,
                observations=raw_readings,
                workload_class=w_class_str,
                ias_score=ias_result.score,
                anomaly_level="CLEAN",
                baseline_qualified=True,
            )

        return TelemetryResponse(
            status="BASELINING",
            agent_id=request.agent_id,
            processed_count=len(request.readings),
            anomaly_level=AnomalyLevel.CLEAN,
            ias_score=ias_result.score,
            calibrated=False,
            recommended_poll_interval_sec=1.0,
        )

    # 5. Full IAS Computation (Trust established)
    ias_result = compute_ias(
        observed=latest_reading,
        baseline=baseline,
        default_thresholds={
            "LOG": settings.default_log_threshold,
            "MEDIUM": settings.default_medium_threshold,
            "CRITICAL": settings.default_critical_threshold,
        },
    )

    # 6. Persistence & Branching Logic
    baseline_qual = ias_result.level == AnomalyLevel.CLEAN

    if db_pool:
        await insert_physics_observations_bulk(
            pool=db_pool,
            agent_id=request.agent_id,
            observations=raw_readings,
            workload_class=w_class_str,
            ias_score=ias_result.score,
            anomaly_level=ias_result.level.value,
            baseline_qualified=baseline_qual,
        )

    # 7. Update Baseline EMA if clean
    if ias_result.level == AnomalyLevel.CLEAN:
        await almanac_svc.update_baseline(
            agent_id=request.agent_id,
            workload_class=w_class_str,
            observation=latest_reading,
            ias_score=ias_result.score,
            log_threshold=settings.default_log_threshold,
        )

    # 8. Alerting & Triggers on Anomalies
    if ias_result.level in (AnomalyLevel.MEDIUM, AnomalyLevel.CRITICAL):
        alert_info = await publish_anomaly_alert(
            agent_id=request.agent_id,
            hostname=request.hostname,
            ias_result=ias_result,
            settings=settings,
        )

        dharma_dispatched = False
        if ias_result.level == AnomalyLevel.CRITICAL:
            dharma_dispatched = await trigger_dharma(
                agent_id=request.agent_id,
                hostname=request.hostname,
                ias_result=ias_result,
                settings=settings,
            )

        if db_pool:
            await insert_anomaly_alert(
                pool=db_pool,
                alert_id=alert_info.get("alert_id", f"alert-{request.agent_id}"),
                agent_id=request.agent_id,
                ias_score=ias_result.score,
                anomaly_level=ias_result.level.value,
                top_channels=ias_result.top_divergent_channels,
                narrative=alert_info.get("narrative"),
                telegram_sent=alert_info.get("telegram_sent", False),
                dharma_triggered=dharma_dispatched,
            )

    # 9. Dynamic Polling Rate Recommendation
    recommended_poll = 1.0
    if ias_result.level == AnomalyLevel.CRITICAL:
        recommended_poll = 0.1  # 10Hz intensification
    elif ias_result.level == AnomalyLevel.MEDIUM:
        recommended_poll = 0.5  # 2Hz elevated

    return TelemetryResponse(
        status="PROCESSED",
        agent_id=request.agent_id,
        processed_count=len(request.readings),
        anomaly_level=ias_result.level,
        ias_score=ias_result.score,
        calibrated=ias_result.calibrated,
        recommended_poll_interval_sec=recommended_poll,
    )


class AnomalyInjectionRequest(BaseModel):
    agent_id: str
    hostname: str = "test-node-001"
    ias_override: float = 5.5
    channel_pattern: Dict[str, Any] = Field(default_factory=dict)


@router.post("/debug/inject-anomaly")
async def inject_simulated_anomaly(
    req: AnomalyInjectionRequest,
    settings: AxiomSettings = Depends(get_settings),
):
    """Debug simulation endpoint to inject test anomalies for end-to-end integration drills."""
    db_pool = await get_db_pool()
    level = AnomalyLevel.CRITICAL if req.ias_override >= 5.0 else AnomalyLevel.MEDIUM

    ias_res = type("IASResult", (), {
        "score": req.ias_override,
        "level": level,
        "calibrated": True,
        "top_divergent_channels": [{"channel": "rapl_pkg", "score": req.ias_override}],
    })()

    alert_info = await publish_anomaly_alert(
        agent_id=req.agent_id,
        hostname=req.hostname,
        ias_result=ias_res,
        settings=settings,
        pool=db_pool,
    )

    dharma_dispatched = await trigger_dharma(
        agent_id=req.agent_id,
        hostname=req.hostname,
        ias_result=ias_res,
        settings=settings,
    )

    if db_pool:
        await insert_anomaly_alert(
            pool=db_pool,
            alert_id=alert_info.get("alert_id", f"alert-{req.agent_id}"),
            agent_id=req.agent_id,
            ias_score=req.ias_override,
            anomaly_level=level.value,
            top_channels=ias_res.top_divergent_channels,
            narrative=alert_info.get("narrative"),
            telegram_sent=alert_info.get("telegram_sent", False),
            dharma_triggered=dharma_dispatched,
        )

    return {
        "status": "ANOMALY_INJECTED",
        "agent_id": req.agent_id,
        "ias_score": req.ias_override,
        "anomaly_level": level.value,
        "alert_id": alert_info.get("alert_id"),
        "dharma_triggered": dharma_dispatched,
    }
