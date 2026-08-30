"""
BRAHMA API Routers Package
"""

from .health import router as health_router
from .update import router as update_router
from .assessment import router as assessment_router
from .grammar import router as grammar_router
from .dharma import router as dharma_router
from .observe import router as observe_router
from .kill_chain import router as kill_chain_router

__all__ = [
    "health_router",
    "update_router",
    "assessment_router",
    "grammar_router",
    "dharma_router",
    "observe_router",
    "kill_chain_router",
]

