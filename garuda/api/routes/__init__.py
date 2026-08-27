"""GARUDA API Subroutes Package."""

from garuda.api.routes.alerts import router as alerts_router
from garuda.api.routes.analyst import router as analyst_router
from garuda.api.routes.campaigns import router as campaigns_router
from garuda.api.routes.collect import router as collect_router
from garuda.api.routes.stats import router as stats_router
from garuda.api.routes.stix import router as stix_router
from garuda.api.routes.telegram import router as telegram_router

__all__ = [
    "alerts_router",
    "analyst_router",
    "campaigns_router",
    "stix_router",
    "collect_router",
    "stats_router",
    "telegram_router",
]
