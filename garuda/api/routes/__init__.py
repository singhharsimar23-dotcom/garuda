"""GARUDA API Subroutes Package."""

from garuda.api.routes.alerts import router as alerts_router
from garuda.api.routes.analyst import router as analyst_router
from garuda.api.routes.campaigns import router as campaigns_router
from garuda.api.routes.clusters import router as clusters_router
from garuda.api.routes.collect import router as collect_router
from garuda.api.routes.easm import router as easm_router
from garuda.api.routes.pdns import router as pdns_router
from garuda.api.routes.rpz import router as rpz_router
from garuda.api.routes.stats import router as stats_router
from garuda.api.routes.stix import router as stix_router
from garuda.api.routes.taxii import router as taxii_router
from garuda.api.routes.telegram import router as telegram_router

__all__ = [
    "alerts_router",
    "analyst_router",
    "campaigns_router",
    "clusters_router",
    "easm_router",
    "pdns_router",
    "rpz_router",
    "stix_router",
    "taxii_router",
    "collect_router",
    "stats_router",
    "telegram_router",
]
