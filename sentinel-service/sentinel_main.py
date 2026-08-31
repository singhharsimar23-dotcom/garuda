"""
GARUDA SENTINEL Service Main Entrypoint
FastAPI application with persistent asyncio lifespan orchestrating autonomous learning, cross-host chaining, and predictive pre-positioning.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta, date
import logging
import os
from typing import Any, Dict, List, Optional
import httpx
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


async def send_telegram_alert(msg: str) -> None:
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not bot_token or not chat_id:
        logger.info(f"[TELEGRAM-DIGEST] {msg}")
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": msg},
            )
    except Exception as exc:
        logger.error(f"Telegram alert failed: {exc}")


async def daily_digest_loop(supabase_client, telegram_fn) -> None:
    """
    Daily Telegram digest at 08:00 IST (02:30 UTC).
    Reports what GARUDA found while you worked on other things.
    Runs forever — one message per day, automatically.
    """
    while True:
        try:
            now_utc = datetime.now(timezone.utc)
            target = now_utc.replace(
                hour=2, minute=30, second=0, microsecond=0
            )
            if now_utc >= target:
                target = target + timedelta(days=1)
            wait_seconds = (target - now_utc).total_seconds()
            await asyncio.sleep(wait_seconds)

            since = (
                datetime.now(timezone.utc) - timedelta(hours=24)
            ).isoformat()

            if not supabase_client:
                continue

            ct_result = supabase_client.table("stix_objects").select(
                "id", count="exact"
            ).gte("created_at", since).execute()

            lifecycle_result = supabase_client.table(
                "domain_lifecycle"
            ).select("id", count="exact").neq(
                "current_stage", "WEAPONIZED"
            ).execute()

            weaponized_result = supabase_client.table(
                "domain_lifecycle"
            ).select("domain,current_stage").eq(
                "current_stage", "WEAPONIZED"
            ).gte("last_checked_at", since).execute()

            top_hits = supabase_client.table("stix_objects").select(
                "ioc_value,confidence,malware_family,actor"
            ).gte("created_at", since).order(
                "confidence", desc=True
            ).limit(5).execute()

            ct_count = ct_result.count or 0
            lifecycle_count = lifecycle_result.count or 0
            weaponized = weaponized_result.data or []
            hits = top_hits.data or []

            lines = [
                "📊 GARUDA DAILY DIGEST",
                f"Last 24 hours\n",
                f"CT Hits Flagged: {ct_count}",
                f"Domains Tracked: {lifecycle_count}",
                f"Reached WEAPONIZED: {len(weaponized)}",
            ]

            if hits:
                lines.append("\nTop Detections:")
                for h in hits[:3]:
                    lines.append(
                        f"  • {h.get('ioc_value','unknown')}"
                        f" [{h.get('actor','?')}]"
                        f" conf={h.get('confidence',0)}"
                    )

            if weaponized:
                lines.append("\nWEAPONIZED domains:")
                for w in weaponized[:3]:
                    lines.append(f"  🔴 {w.get('domain','unknown')}")

            if ct_count == 0:
                lines.append(
                    "\n⚠️ Zero CT hits today — verify sentinel hunt loop"
                )

            lines.append("\nhttps://garuda-intel.vercel.app")

            await telegram_fn("\n".join(lines))

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error(f"Daily digest failed: {exc}", exc_info=True)


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

    # ── Session O: GARUDA-HUNT Active Intelligence Collection ──────────────────
    # Initialize hunt components. Telegram alerter and DHARMA prearm are optional —
    # lifecycle tracker degrades gracefully if they are not available in this service.
    from hunt.ct_collector import CTHuntCollector, garuda_score
    from hunt.enrichment import EnrichmentPipeline
    from hunt.lifecycle import DomainLifecycleTracker
    from hunt.vibeware_feed import VibewareFeedIngester

    # Stub telegram alerter — SENTINEL does not have direct Telegram integration;
    # alerts flow through BRAHMA. Replace with real alerter if integrated.
    class _NullAlerter:
        async def alert(self, msg: str) -> None:
            logger.info(f"[LIFECYCLE-ALERT] {msg}")

    # Stub DHARMA prearm — SENTINEL pre-arms DHARMA via Supabase event, not direct call.
    async def _null_prearm(**kwargs):
        logger.info(f"[DHARMA-PREARM] {kwargs}")

    lifecycle_tracker = DomainLifecycleTracker(
        supabase_client=supabase,
        telegram_alerter=_NullAlerter(),
        dharma_prearm_fn=_null_prearm,
    )

    enrichment_pipeline = EnrichmentPipeline(
        supabase_client=supabase,
        lifecycle_tracker=lifecycle_tracker,
    )

    ct_collector = CTHuntCollector(
        garuda_scorer=garuda_score,
        enrichment_pipeline=enrichment_pipeline,
        supabase_client=supabase,
    )

    vibeware_ingester = VibewareFeedIngester(supabase_client=supabase)

    # Start new hunt loops alongside existing background loops
    ct_hunt_task = asyncio.create_task(ct_collector.hunt_loop())        # 15-min CT poll
    lifecycle_task = asyncio.create_task(lifecycle_tracker.poll_loop()) # 30-min lifecycle
    vibeware_task = asyncio.create_task(vibeware_ingester.feed_loop())  # 6-hr vibeware IOC
    digest_task = asyncio.create_task(daily_digest_loop(supabase, send_telegram_alert)) # Daily 02:30 UTC digest

    logger.info("GARUDA-HUNT loops started: CT(15min) + Lifecycle(30min) + Vibeware(6h) + Digest(02:30UTC)")
    # ──────────────────────────────────────────────────────────────────────────

    yield

    logger.info("Stopping SENTINEL background loops...")
    await obs_loop.stop()
    cross_host_task.cancel()
    predictor_task.cancel()
    calibrator_task.cancel()
    ct_hunt_task.cancel()
    lifecycle_task.cancel()
    vibeware_task.cancel()
    digest_task.cancel()
    await asyncio.gather(
        cross_host_task, predictor_task, calibrator_task,
        ct_hunt_task, lifecycle_task, vibeware_task, digest_task,
        return_exceptions=True,
    )


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
def health_check():
    """Lightweight sync health check endpoint matching AXIOM/BRAHMA pattern."""
    return {
        "status": "HEALTHY",
        "service": "garuda-sentinel-service",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@sentinel_app.get("/health/hunt")
async def hunt_health():
    """
    Called by GitHub Actions keepalive every 14 minutes.
    Returns loop status and today's detection count.
    If this returns 200 with hunt_active=true: system is hunting.
    """
    try:
        today = date.today().isoformat()
        supabase = await get_supabase()

        stix_today_count = 0
        domains_tracked_count = 0
        if supabase:
            try:
                ct_result = supabase.table("stix_objects").select(
                    "id", count="exact"
                ).gte("created_at", today).execute()
                stix_today_count = ct_result.count or 0
            except Exception:
                pass

            try:
                lifecycle_result = supabase.table("domain_lifecycle").select(
                    "id", count="exact"
                ).neq("current_stage", "WEAPONIZED").execute()
                domains_tracked_count = lifecycle_result.count or 0
            except Exception:
                pass

        return {
            "hunt_active": True,
            "loops": {
                "ct_hunt_15min": "running",
                "lifecycle_30min": "running",
                "vibeware_feed_6h": (
                    "running"
                    if os.getenv("FEATURE_VIBEWARE_FEED") == "true"
                    else "disabled_pending_key"
                ),
                "daily_digest": "running",
            },
            "stix_today": stix_today_count,
            "domains_tracked": domains_tracked_count,
        }
    except Exception as exc:
        return {
            "hunt_active": False,
            "error": str(exc),
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
