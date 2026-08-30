"""
GARUDA SENTINEL Service Main Entrypoint
FastAPI application orchestrating autonomous learning, cross-host chaining, and predictive pre-positioning.
"""

import asyncio
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from supabase import Client, create_client

from calibrator import get_threshold_calibrator
from campaign import get_campaign_manager
from canary import router as canary_router
from config import get_settings
from cross_host import get_cross_host_correlator
from learner import get_learner
from observation import get_observation_loop
from predictor import get_predictive_prepositioner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.main")

app = FastAPI(
    title="GARUDA SENTINEL Autonomous Brain Service",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(canary_router)

_supabase_client: Optional[Client] = None


def get_supabase() -> Optional[Client]:
    global _supabase_client
    settings = get_settings()
    if _supabase_client is None and settings.supabase_url and settings.supabase_service_key:
        try:
            _supabase_client = create_client(settings.supabase_url, settings.supabase_service_key)
        except Exception as e:
            logger.warning(f"Failed initializing Supabase client: {e}")
    return _supabase_client


@app.get("/health")
def health_check():
    """Keepalive and status health check endpoint matching AXIOM/BRAHMA pattern."""
    return {
        "status": "HEALTHY",
        "service": "garuda-sentinel-service",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/sentinel/state/{hostname}")
def get_host_campaign_state(hostname: str):
    """Retrieve full autonomous campaign state and evidence chain for a specific host."""
    camp_mgr = get_campaign_manager()
    state = camp_mgr.get_or_create_host_state(hostname)
    return state.dict()


@app.post("/api/v1/sentinel/observe")
def direct_observation_ingest(payload: Dict[str, Any]):
    """Directly push observation event to internal queue for fast-path ingestion."""
    table = payload.get("table", "physics_observations")
    record = payload.get("record", {})
    obs_loop = get_observation_loop()
    obs_loop.enqueue_event(table=table, record=record)
    return {"status": "enqueued", "table": table}


@app.post("/api/v1/sentinel/dharma-feedback")
async def dharma_feedback_webhook(payload: Dict[str, Any]):
    """Receives operator APPROVE/REJECT decisions and triggers the learning loop."""
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
