"""
GARUDA BRAHMA Adversary & Kill Chain Modeling Service
FastAPI application with startup MITRE training pipeline, Bayesian update engine, and attribution routes.
"""

from contextlib import asynccontextmanager
import logging
from typing import Dict
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .mitre_pipeline import get_mitre_pipeline
from .routers.dharma import router as dharma_router
from .routers.kali import router as kali_router
from .routers.kill_chain import router as kill_chain_router
from .routers.label import router as label_router
from .routers.observe import router as observe_router




logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("brahma.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: runs MITRE G0134 empirical training pipeline at boot."""
    settings = get_settings()
    logger.info(f"Starting BRAHMA Adversary Modeling Service (env: {settings.environment}, port: {settings.port})...")

    # Run real MITRE ATT&CK extraction pipeline
    pipeline = get_mitre_pipeline()
    try:
        await pipeline.run_pipeline()
        logger.info("MITRE ATT&CK training pipeline completed successfully at boot.")
    except Exception as e:
        logger.warning(f"MITRE ATT&CK training pipeline warning at startup: {e}")

    yield

    logger.info("Shutting down BRAHMA Service...")


def create_app() -> FastAPI:
    """Configures the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title="GARUDA BRAHMA Adversary Modeling Service",
        description="Real-time Bayesian kill-chain tracking, MITRE ATT&CK Group G0134 modeling, and verifiable attribution for Indian Defense Infrastructure",
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
        """Health check endpoint for Render.com and keepalive."""
        return {
            "status": "HEALTHY",
            "service": "garuda-brahma-service",
            "version": "0.1.0",
        }

    @app.get("/", status_code=status.HTTP_200_OK)
    async def root_info() -> Dict[str, str]:
        return {
            "service": "GARUDA BRAHMA Adversary Modeling",
            "documentation": "/docs",
            "status": "ONLINE",
        }

    # Register Routers
    app.include_router(observe_router)
    app.include_router(kill_chain_router)
    app.include_router(dharma_router)
    app.include_router(kali_router)
    app.include_router(label_router)

    return app





app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run("brahma.main:app", host=settings.host, port=settings.port, reload=settings.debug)
