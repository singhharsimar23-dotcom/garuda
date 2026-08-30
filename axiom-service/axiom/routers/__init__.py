"""
AXIOM API Routers Package
"""

from .health import router as health_router
from .telemetry import router as telemetry_router
from .provenance import router as provenance_router
from .debug import router as debug_router

__all__ = [
    "health_router",
    "telemetry_router",
    "provenance_router",
    "debug_router",
]
