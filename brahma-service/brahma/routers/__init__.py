"""
BRAHMA API Routers Package
"""

from .health import router as health_router
from .update import router as update_router
from .assessment import router as assessment_router
from .grammar import router as grammar_router
from .dharma import router as dharma_router

__all__ = [
    "health_router",
    "update_router",
    "assessment_router",
    "grammar_router",
    "dharma_router",
]
