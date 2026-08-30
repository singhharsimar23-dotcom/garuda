"""
Health Check Router
Provides container readiness/liveness status for Northflank and orchestrator probes.
"""

from fastapi import APIRouter
from ..db.pool import get_db_pool

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Health check endpoint for Northflank deployment.
    """
    db_pool = await get_db_pool()
    db_connected = db_pool is not None

    return {
        "status": "HEALTHY",
        "service": "axiom-service",
        "version": "0.1.0",
        "database_connected": db_connected,
    }
