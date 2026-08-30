"""
GARUDA AXIOM-II Physics Detection Service
Main FastAPI Application Entrypoint with Lifespan Management & Health Endpoints.
"""

import asyncio
from contextlib import asynccontextmanager
import logging
from typing import Dict
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from auth import get_supabase_client
from config import get_settings
from fusion import get_fusion_engine
from telemetry import router as telemetry_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("axiom.main")

fusion_task: asyncio.Task = None


async def periodic_fleet_fusion():
    """Background task evaluating fleet-wide multi-sensor fusion every 60 seconds."""
    fusion_engine = get_fusion_engine()
    while True:
        try:
            await asyncio.sleep(60)
            supabase = await get_supabase_client()
            alerts = fusion_engine.evaluate_fleet_fusion(supabase_client=supabase)
            if alerts:
                logger.info(f"Periodic Fleet Fusion generated {len(alerts)} alert(s).")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"Error in periodic fleet fusion loop: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context."""
    global fusion_task
    settings = get_settings()
    logger.info(f"Starting AXIOM-II Telemetry Service (env={settings.environment}, port={settings.port})")

    # Start background fleet fusion task
    fusion_task = asyncio.create_task(periodic_fleet_fusion())
    yield

    # Teardown
    if fusion_task:
        fusion_task.cancel()
        try:
            await fusion_task
        except asyncio.CancelledError:
            pass
    logger.info("AXIOM-II Telemetry Service shutdown complete.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="GARUDA AXIOM-II Telemetry & Physics Invariant Service",
        description="Receives real-time hardware physics telemetry, computes IAS, and triggers defensive responses.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", status_code=status.HTTP_200_OK)
    async def health_check() -> Dict[str, str]:
        """Health check endpoint for Render.com and GitHub Actions Keepalive."""
        return {
            "status": "HEALTHY",
            "service": "garuda-axiom-service",
            "version": "0.1.0",
        }

    @app.get("/", status_code=status.HTTP_200_OK)
    async def root_info() -> Dict[str, str]:
        return {
            "service": "GARUDA AXIOM-II Telemetry Ingestion",
            "documentation": "/docs",
            "status": "ONLINE",
        }

    @app.post("/api/v1/fusion/evaluate", status_code=status.HTTP_200_OK)
    async def trigger_manual_fusion():
        """Manual trigger for fleet-wide multi-sensor fusion evaluation."""
        supabase = await get_supabase_client()
        fusion_engine = get_fusion_engine()
        alerts = fusion_engine.evaluate_fleet_fusion(supabase_client=supabase)
        return {"status": "success", "alerts_count": len(alerts), "alerts": alerts}

    # Register Telemetry Router
    app.include_router(telemetry_router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=settings.debug)
