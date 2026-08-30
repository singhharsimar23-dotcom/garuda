"""
BRAHMA Service Main Application
FastAPI application for Service 2 with lifespan management and router registrations.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .db.pool import close_db_pool, get_db_pool, init_db_pool
from .routers import assessment_router, dharma_router, grammar_router, health_router, update_router
from maya.maya_router import router as maya_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("brahma.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for database initialization and cleanup."""
    settings = get_settings()
    logger.info(f"Starting GARUDA BRAHMA Adversary Modeling Service (env: {settings.environment})...")

    await init_db_pool(
        db_url=settings.northflank_db_url,
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
    )

    yield

    logger.info("Shutting down BRAHMA Service...")
    await close_db_pool()


def create_app() -> FastAPI:
    """Configures the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title="GARUDA BRAHMA Adversary Modeling Service",
        description="Real-time Bayesian kill-chain tracking, behavioral grammar synthesis, and threat actor attribution for Indian Defense Infrastructure",
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

    # Register Routers
    app.include_router(health_router)
    app.include_router(update_router)
    app.include_router(assessment_router)
    app.include_router(grammar_router)
    app.include_router(dharma_router)
    app.include_router(maya_router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run("brahma.main:app", host=settings.host, port=settings.port, reload=settings.debug)
