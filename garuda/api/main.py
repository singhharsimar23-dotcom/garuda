from contextlib import asynccontextmanager
import json
import logging
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
try:
    from mangum import Mangum
except ImportError:
    Mangum = None

from garuda.api.routes import (
    alerts_router,
    analyst_router,
    bgp_router,
    canary_router,
    campaigns_router,
    clusters_router,
    collect_router,
    dashboard_router,
    easm_router,
    pdns_router,
    predictive_router,
    rpz_router,
    stats_router,
    stix_router,
    taxii_router,
    telegram_router,
    malware_hunt_router,
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

    @application.middleware("http")
    async def vercel_path_rewrite_middleware(request: Request, call_next):
        """Restore original client request path if Vercel rewritten to /api/index.py."""
        client_url = request.query_params.get("__url__")
        if client_url:
            request.scope["path"] = client_url.split("?")[0]
        else:
            matched_path = request.headers.get("x-matched-path")
            if matched_path and request.scope.get("path") == "/api/index.py":
                request.scope["path"] = matched_path.split("?")[0]
        return await call_next(request)

    # Global Exception Handlers
    @application.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        # Format as TAXII Error if requesting TAXII endpoint
        if "/taxii2" in request.url.path:
            return Response(
                content=json.dumps({
                    "title": "TAXII Error",
                    "description": str(exc.detail),
                    "error_id": f"TAXII-HTTP-{exc.status_code}",
                    "http_status": str(exc.status_code),
                }),
                status_code=exc.status_code,
                media_type="application/taxii+json;version=2.1",
                headers={"Content-Type": "application/taxii+json;version=2.1"},
            )
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
        if "/taxii2" in request.url.path:
            return Response(
                content=json.dumps({
                    "title": "Internal Server Error",
                    "description": str(exc) if settings.DEBUG else "An internal server error occurred.",
                    "error_id": "TAXII-ERR-500",
                    "http_status": "500",
                }),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/taxii+json;version=2.1",
                headers={"Content-Type": "application/taxii+json;version=2.1"},
            )
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
        taxii_router,
        rpz_router,
        pdns_router,
        predictive_router,
        clusters_router,
        bgp_router,
        canary_router,
        alerts_router,
        analyst_router,
        campaigns_router,
        easm_router,
        stix_router,
    collect_router,
    dashboard_router,
    stats_router,
        telegram_router,
        malware_hunt_router,
    ]
    for r in routers:
        application.include_router(r)
        application.include_router(r, prefix="/api")


    # Mount frontend static assets and SPA fallback
    from pathlib import Path
    dist_dir = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if dist_dir.exists():
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse

        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            application.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @application.get("/favicon.ico", include_in_schema=False)
        async def favicon():
            fav = dist_dir / "favicon.ico"
            if fav.exists():
                return FileResponse(fav)
            return JSONResponse(status_code=204, content={})

        @application.get("/index.html", include_in_schema=False)
        @application.get("/", include_in_schema=False)
        async def serve_root_index():
            return FileResponse(dist_dir / "index.html")

        @application.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa_fallback(full_path: str):
            # If requesting an api/taxii path that was not found, return 404
            if full_path.startswith("api/") or full_path.startswith("taxii2"):
                raise HTTPException(status_code=404, detail="API endpoint not found")
            target = dist_dir / full_path
            if target.exists() and target.is_file():
                return FileResponse(target)
            return FileResponse(dist_dir / "index.html")

    return application


# FastAPI application singleton instance
app = create_app()

# Mangum serverless handler for Vercel / AWS Lambda
handler = Mangum(app, lifespan="off") if Mangum is not None else None
