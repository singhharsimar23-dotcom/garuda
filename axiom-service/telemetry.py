"""
Telemetry Ingestion Router
Handles POST /api/v1/telemetry, orchestrating real-time IAS calculation, baseline learning,
heartbeat updates, trigger dispatch (BRAHMA/DHARMA), and resilient database persistence.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from auth import get_supabase_client, validate_agent_token
from baseline import get_baseline_store
from brahma_trigger import trigger_brahma_observe
from config import get_settings
from dharma_trigger import trigger_dharma_actions
from eppi_engine import get_eppi_processor
from fusion import get_fusion_engine
from ias_engine import get_ias_engine
from models import TelemetryInput, TelemetryResponse


logger = logging.getLogger("axiom.telemetry")
router = APIRouter(prefix="/api/v1", tags=["Telemetry"])

# Local in-memory fallback queue if Redis & Supabase are unreachable
_offline_redis_buffer: List[Dict[str, Any]] = []


async def buffer_in_redis(payload_dict: Dict[str, Any]) -> None:
    """Push payload to Upstash Redis REST or in-memory fallback queue."""
    settings = get_settings()
    if settings.upstash_redis_rest_url and settings.upstash_redis_rest_token:
        try:
            url = f"{settings.upstash_redis_rest_url.rstrip('/')}/rpush/axiom_offline_telemetry"
            headers = {"Authorization": f"Bearer {settings.upstash_redis_rest_token}"}
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(url, headers=headers, json=[json.dumps(payload_dict)])
            logger.info("Buffered telemetry in Upstash Redis.")
            return
        except Exception as e:
            logger.warning(f"Failed to buffer in Upstash Redis: {e}")

    _offline_redis_buffer.append(payload_dict)
    logger.info(f"Buffered telemetry in-memory fallback (total: {len(_offline_redis_buffer)})")


@router.post(
    "/telemetry",
    response_model=TelemetryResponse,
    status_code=status.HTTP_200_OK,
)
async def ingest_telemetry(
    payload: TelemetryInput,
    agent_token: str = Depends(validate_agent_token),
):
    """
    Ingest hardware physics and kernel telemetry from garuda_agent daemon.
    """
    supabase = await get_supabase_client()
    ias_engine = get_ias_engine()
    baseline_store = get_baseline_store()
    fusion_engine = get_fusion_engine()

    # 1. Compute Real-Time Integrated Anomaly Score (IAS)
    (
        ias_score,
        channel_sigmas,
        anomaly_level,
        uncalibrated,
        workload_class,
        evaluated_flags,
    ) = ias_engine.compute_ias(payload, supabase_client=supabase)

    combined_flags = sorted(list(set(payload.flags + evaluated_flags)))

    # 2. Update Statistical Baselines (Online Welford + Contamination Prevention)
    # If RAPL is available, update RAPL channels
    if not payload.rapl.unavailable and payload.rapl.pkg_w is not None:
        baseline_store.update_baseline(
            payload.hostname, workload_class, "rapl_pkg", float(payload.rapl.pkg_w), ias_score, supabase
        )
    if not payload.rapl.unavailable and payload.rapl.dram_w is not None:
        baseline_store.update_baseline(
            payload.hostname, workload_class, "rapl_dram", float(payload.rapl.dram_w), ias_score, supabase
        )

    # If Perf is available, update Perf channels
    if not payload.perf.unavailable and payload.perf.instructions_ps is not None:
        baseline_store.update_baseline(
            payload.hostname, workload_class, "perf_instructions", float(payload.perf.instructions_ps), ias_score, supabase
        )
    if not payload.perf.unavailable and payload.perf.cache_misses_ps is not None:
        baseline_store.update_baseline(
            payload.hostname, workload_class, "perf_cache_miss", float(payload.perf.cache_misses_ps), ias_score, supabase
        )

    # Entropy & Schedstat
    baseline_store.update_baseline(
        payload.hostname, workload_class, "entropy", float(payload.entropy.bits), ias_score, supabase
    )
    baseline_store.update_baseline(
        payload.hostname, workload_class, "schedstat_steal", float(payload.schedstat.steal_ratio), ias_score, supabase
    )

    # 3. Handle Triggers Asynchronously
    triggers: List[str] = []

    # BRAHMA Trigger on IAS >= LOG (1.5)
    if anomaly_level in ("LOG", "MEDIUM", "CRITICAL") or ias_score >= 1.5:
        triggers.append("BRAHMA_OBSERVE")
        asyncio.create_task(
            trigger_brahma_observe(
                hostname=payload.hostname,
                ias_score=ias_score,
                channel_sigmas=channel_sigmas,
                workload_class=workload_class,
                observed_at=payload.timestamp_utc.isoformat(),
            )
        )

    # DHARMA Trigger on IAS >= CRITICAL (5.0)
    if anomaly_level == "CRITICAL" or ias_score >= 5.0:
        triggers.append("DHARMA_CRITICAL_RESPONSE")
        asyncio.create_task(
            trigger_dharma_actions(
                hostname=payload.hostname,
                ias_score=ias_score,
                channel_sigmas=channel_sigmas,
                workload_class=workload_class,
                supabase_client=supabase,
            )
        )

    # 4. Construct Database Record
    # ANTI-HALLUCINATION: Exact column names from physics_observations table
    db_row = {
        "agent_id": payload.agent_id,
        "hostname": payload.hostname,
        "observed_at": payload.timestamp_utc.isoformat(),
        "rapl_pkg_w": None if payload.rapl.unavailable else payload.rapl.pkg_w,
        "rapl_dram_w": None if payload.rapl.unavailable else payload.rapl.dram_w,
        "perf_instructions_ps": None if payload.perf.unavailable else payload.perf.instructions_ps,
        "perf_cache_misses_ps": None if payload.perf.unavailable else payload.perf.cache_misses_ps,
        "entropy_bits": payload.entropy.bits,
        "steal_ratio": payload.schedstat.steal_ratio,
        "ias_score": ias_score,
        "ias_uncalibrated": uncalibrated,
        "workload_class": workload_class,
        "channel_sigmas": channel_sigmas,
        "flags": combined_flags,
    }

    # Record observation in local fusion engine & eppi correlation
    fusion_engine.record_observation({
        **db_row,
        "observed_at_dt": payload.timestamp_utc,
    })
    eppi_engine = get_eppi_processor()
    if ias_score >= 1.5:
        eppi_engine.record_physics_spike(payload.hostname, ias_score, payload.timestamp_utc.isoformat())

    # 5. Persist to Supabase with Redis offline buffering on failure
    observation_id = None
    if supabase:
        try:
            res = supabase.table("physics_observations").insert(db_row).execute()
            if res.data and len(res.data) > 0:
                observation_id = str(res.data[0].get("id"))

            # Update Agent Heartbeat
            heartbeat_row = {
                "agent_id": payload.agent_id,
                "hostname": payload.hostname,
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "agent_version": "0.1.0",
                "rapl_available": not payload.rapl.unavailable,
                "perf_available": not payload.perf.unavailable,
                "status": "ACTIVE",
            }
            supabase.table("agent_heartbeats").upsert(heartbeat_row, on_conflict="agent_id").execute()

        except Exception as e:
            logger.error(f"Supabase persistence error: {e}. Buffering telemetry locally.")
            await buffer_in_redis(db_row)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database connection error; telemetry buffered locally in Redis.",
            )

    return TelemetryResponse(
        status="success",
        message="Telemetry successfully ingested and evaluated",
        observation_id=observation_id,
        computed_ias=ias_score,
        anomaly_level=anomaly_level,
        workload_class=workload_class,
        triggers=triggers,
    )


@router.post(
    "/eppi",
    status_code=status.HTTP_200_OK,
)
async def ingest_eppi_events(
    payload: Dict[str, Any],
    agent_token: str = Depends(validate_agent_token),
):
    """
    Ingest eBPF kprobe process provenance events from garuda_agent.
    """
    hostname = payload.get("hostname", "unknown")
    events = payload.get("events", [])

    supabase = await get_supabase_client()
    processor = get_eppi_processor()

    return result


@router.get(
    "/axiom/stream",
    status_code=status.HTTP_200_OK,
)
async def get_active_fleet_stream():
    """
    Returns real-time physical telemetry observations per monitored host.
    """
    supabase = await get_supabase_client()
    fleet = []
    seen_hosts = set()

    if supabase:
        try:
            # Query recent real telemetry observations ordered by observed_at
            res = (
                supabase.table("physics_observations")
                .select("*")
                .order("observed_at", desc=True)
                .limit(50)
                .execute()
            )
            rows = res.data or []
            for r in rows:
                h = r.get("hostname")
                if h and h not in seen_hosts:
                    seen_hosts.add(h)
                    score = float(r.get("ias_score", 0.0))
                    status_label = "CRITICAL" if score >= 5.0 else ("SUSPICIOUS" if score >= 2.0 else "TRUSTED")
                    pkg_w = float(r.get("rapl_pkg_w") or 14.5)
                    dram_w = float(r.get("rapl_dram_w") or 3.2)
                    miss_ps = float(r.get("perf_cache_misses_ps") or 12000.0)
                    cache_pct = min(100.0, round((miss_ps / 500000.0) * 100, 1))

                    fleet.append({
                        "id": h,
                        "hostname": h,
                        "ias_score": score,
                        "pkg_power_mw": int(pkg_w * 1000),
                        "core_power_mw": int(dram_w * 1000),
                        "cache_miss_rate": cache_pct,
                        "entropy_avail": r.get("entropy_bits", 3850),
                        "status": status_label,
                        "last_seen": r.get("observed_at", "Just now"),
                    })
        except Exception as e:
            logger.warning(f"Failed querying physics_observations: {e}")

        # If no observations in physics_observations, check agent_heartbeats table for real active agents
        if not fleet:
            try:
                hb_res = supabase.table("agent_heartbeats").select("*").order("last_seen", desc=True).limit(50).execute()
                for hb in hb_res.data or []:
                    h = hb.get("hostname")
                    if h and h not in seen_hosts:
                        seen_hosts.add(h)
                        fleet.append({
                            "id": h,
                            "hostname": h,
                            "ias_score": 0.0,
                            "pkg_power_mw": 0,
                            "core_power_mw": 0,
                            "cache_miss_rate": 0.0,
                            "entropy_avail": 4096,
                            "status": hb.get("status", "TRUSTED"),
                            "last_seen": hb.get("last_seen", "Recent"),
                        })
            except Exception as e:
                logger.warning(f"Failed querying agent_heartbeats: {e}")

    return {"fleet": fleet}


