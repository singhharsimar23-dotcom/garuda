"""
BRAHMA Health Check Router
"""

from fastapi import APIRouter
from ..db.pool import get_db_pool

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Production liveness / readiness probe."""
    db_pool = await get_db_pool()
    return {
        "status": "HEALTHY",
        "service": "brahma-service",
        "version": "0.1.0",
        "database_connected": db_pool is not None,
    }
