from contextlib import asynccontextmanager
import logging
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
try:
    from mangum import Mangum
except ImportError:
    Mangum = None

from garuda.api.routes import (
    alerts_router,
    analyst_router,
    campaigns_router,
    collect_router,
    stats_router,
    stix_router,
    telegram_router,
)
from garuda.config import settings
from garuda.database import init_database_tables
from garuda.detection.nic_ground_truth import load_nic_domains
from garuda.intelligence.honeypot import init_known_actor_ips
from garuda.intelligence.tension_index import fetch_tension_index

logger = logging.getLogger("garuda.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup telemetry loading and shutdown hooks."""
    logger.info("[lifespan] Initializing GARUDA threat intelligence subsystems in background...")

    async def _bg_init():
        try:
            await init_database_tables()
            await load_nic_domains()
            await init_known_actor_ips()
            await fetch_tension_index()
            logger.info("[lifespan] Background initialization complete.")
        except Exception as e:
            logger.warning(f"[lifespan] Non-fatal background startup error: {e}")

    import asyncio
    asyncio.create_task(_bg_init())
    yield
    logger.info("[lifespan] Shutting down GARUDA API services.")


def create_app() -> FastAPI:
    """FastAPI Application Factory."""
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS Middleware: allow origins=["*"] for development/hackathon
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handlers
    @application.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "status_code": exc.status_code,
                "message": exc.detail,
                "path": str(request.url.path),
            },
        )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error(f"[api.unhandled] Error on {request.url.path}: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": True,
                "status_code": 500,
                "message": "Internal server error occurred.",
                "details": str(exc) if settings.DEBUG else None,
                "path": str(request.url.path),
            },
        )

    # Health & Posture Check Endpoint
    @application.get("/", tags=["System"])
    @application.get("/health", tags=["System"])
    @application.get("/api/health", tags=["System"])
    async def health_check() -> Dict[str, Any]:
        tension = await fetch_tension_index()
        return {
            "status": "ok",
            "conflict_mode": settings.CONFLICT_MODE,
            "tension_index": tension,
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
        }

    @application.post("/retrohunt", tags=["Retrohunt"])
    @application.post("/api/retrohunt", tags=["Retrohunt"])
    async def run_retrohunt_endpoint() -> Dict[str, Any]:
        from garuda.intelligence.retrohunt import run_retrohunt
        return await run_retrohunt()

    # Mount all subrouters under both /api and root for Vercel rewrite resilience
    routers = [
        alerts_router,
        analyst_router,
        campaigns_router,
        stix_router,
        collect_router,
        stats_router,
        telegram_router,
    ]
    for r in routers:
        application.include_router(r, prefix="/api")
        application.include_router(r)

    return application


# FastAPI application singleton instance
app = create_app()

# Mangum serverless handler for Vercel / AWS Lambda
handler = Mangum(app) if Mangum is not None else None
