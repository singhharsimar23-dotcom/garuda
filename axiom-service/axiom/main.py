"""
AXIOM Service Main Application
FastAPI application with lifespan management, database pooling, and router registration.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .db.pool import close_db_pool, get_db_pool, init_db_pool
from .db.queries import check_tables_exist
from .routers import debug_router, health_router, provenance_router, telemetry_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("axiom.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager for database pool initialization and graceful teardown.
    """
    settings = get_settings()
    logger.info(f"Starting AXIOM Physics Detection Service (env: {settings.environment})...")
    
    # 1. Initialize Database Pool
    pool = await init_db_pool(
        db_url=settings.database_url,
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
    )
    if pool:
        tables_ok = await check_tables_exist(pool)
        if not tables_ok:
            logger.warning("Database tables not fully initialized. Ensure migrations have run.")

    yield

    # Teardown
    logger.info("Shutting down AXIOM Service...")
    await close_db_pool()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title="GARUDA AXIOM-II Physics Detection Engine",
        description="Real-time physical side-channel and microarchitectural invariant detection for Indian Defense Infrastructure",
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
    app.include_router(telemetry_router)
    app.include_router(provenance_router)
    app.include_router(debug_router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run("axiom.main:app", host=settings.host, port=settings.port, reload=settings.debug)
