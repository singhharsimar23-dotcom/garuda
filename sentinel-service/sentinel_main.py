"""
GARUDA SENTINEL Service Main Entrypoint
FastAPI application with persistent asyncio lifespan orchestrating autonomous learning, cross-host chaining, and predictive pre-positioning.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from supabase import Client, create_client

from calibrator import get_threshold_calibrator
from campaign import get_campaign_manager
from canary import router as canary_router
from sentinel_config import get_settings
from cross_host import get_cross_host_correlator
from learner import get_learner
from observation import get_observation_loop
from predictor import get_predictive_prepositioner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.main")

_supabase_client: Optional[Client] = None


async def get_supabase() -> Optional[Client]:
    global _supabase_client
    settings = get_settings()
    if _supabase_client is None and settings.supabase_url and settings.supabase_service_key:
        try:
            _supabase_client = create_client(settings.supabase_url, settings.supabase_service_key)
        except Exception as e:
            logger.warning(f"Failed initializing Supabase client: {e}")
    return _supabase_client


# Periodic Background Loops
async def periodic_cross_host_loop():
    correlator = get_cross_host_correlator()
    camp_mgr = get_campaign_manager()
    while True:
        try:
            await asyncio.sleep(300)
            obs_map = {
                host: {
                    "top_tactic": "execution",
                    "fusion_score": state.fusion_score,
                    "timestamp": state.last_anomaly_at,
                    "campaign_id": state.campaign_id,
                }
                for host, state in camp_mgr.host_states.items()
                if state.campaign_id
            }
            if len(obs_map) >= 2:
                supabase = await get_supabase()
                await correlator.correlate_cross_host_activity(obs_map, supabase_client=supabase)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in cross-host background loop: {e}")


async def periodic_predictor_loop():
    predictor = get_predictive_prepositioner()
    camp_mgr = get_campaign_manager()
    while True:
        try:
            await asyncio.sleep(900)
            supabase = await get_supabase()
            for host, state in list(camp_mgr.host_states.items()):
                if state.campaign_id:
                    await predictor.evaluate_campaign_prediction(state, supabase_client=supabase)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in predictor background loop: {e}")


async def periodic_calibrator_loop():
    calibrator = get_threshold_calibrator()
    while True:
        try:
            await asyncio.sleep(86400)
            supabase = await get_supabase()
            actions = []
            if supabase:
                try:
                    res = supabase.table("dharma_action_log").select("*").limit(200).execute()
                    actions = res.data or []
                except Exception:
                    pass
            await calibrator.calibrate_host_thresholds(actions, supabase_client=supabase)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in calibrator background loop: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info(f"Starting GARUDA SENTINEL Service on port {settings.port} (Conflict Mode={settings.conflict_mode})...")

    supabase = await get_supabase()
    obs_loop = get_observation_loop()
    await obs_loop.start(supabase_client=supabase)

    cross_host_task = asyncio.create_task(periodic_cross_host_loop())
    predictor_task = asyncio.create_task(periodic_predictor_loop())
    calibrator_task = asyncio.create_task(periodic_calibrator_loop())

    yield

    logger.info("Stopping SENTINEL background loops...")
    await obs_loop.stop()
    cross_host_task.cancel()
    predictor_task.cancel()
    calibrator_task.cancel()
    await asyncio.gather(cross_host_task, predictor_task, calibrator_task, return_exceptions=True)


sentinel_app = FastAPI(
    title="GARUDA SENTINEL Autonomous Brain Service",
    version="1.0.0",
    lifespan=lifespan,
)

sentinel_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sentinel_app.include_router(canary_router)


@sentinel_app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    obs_loop = get_observation_loop()
    camp_mgr = get_campaign_manager()
    return {
        "status": "healthy",
        "service": "garuda-sentinel-service",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_campaigns_count": len([c for c in camp_mgr.host_states.values() if c.campaign_id]),
        "observation_queue_size": obs_loop.queue.qsize(),
    }


@sentinel_app.get("/api/v1/sentinel/state/{hostname}", status_code=status.HTTP_200_OK)
async def get_host_campaign_state(hostname: str):
    camp_mgr = get_campaign_manager()
    state = camp_mgr.get_or_create_host_state(hostname)
    return state.dict()


@sentinel_app.post("/api/v1/sentinel/observe", status_code=status.HTTP_200_OK)
async def direct_observation_ingest(payload: Dict[str, Any]):
    table = payload.get("table", "physics_observations")
    record = payload.get("record", {})
    obs_loop = get_observation_loop()
    obs_loop.enqueue_event(table=table, record=record)
    return {"status": "enqueued", "table": table}


@sentinel_app.post("/api/v1/sentinel/dharma-feedback", status_code=status.HTTP_200_OK)
async def dharma_feedback_webhook(payload: Dict[str, Any]):
    hostname = payload.get("hostname", "unknown")
    action_id = payload.get("action_id", "act-01")
    verdict = payload.get("verdict", "APPROVE").upper()
    tactic = payload.get("tactic", "execution")
    feature_vector = payload.get("feature_vector", {})

    learner = get_learner()
    if verdict == "APPROVE":
        res = await learner.handle_dharma_approval(hostname, action_id, tactic, feature_vector)
    else:
        res = await learner.handle_dharma_rejection(hostname, action_id, tactic, feature_vector)
    return res

app = sentinel_app
