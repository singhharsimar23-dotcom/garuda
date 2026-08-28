"""GARUDA API Subroutes Package."""

from garuda.api.routes.alerts import router as alerts_router
from garuda.api.routes.analyst import router as analyst_router
from garuda.api.routes.bgp import router as bgp_router
from garuda.api.routes.canary import router as canary_router
from garuda.api.routes.campaigns import router as campaigns_router
from garuda.api.routes.clusters import router as clusters_router
from garuda.api.routes.collect import router as collect_router
from garuda.api.routes.easm import router as easm_router
from garuda.api.routes.pdns import router as pdns_router
from garuda.api.routes.predictive import router as predictive_router
from garuda.api.routes.rpz import router as rpz_router
from garuda.api.routes.stats import router as stats_router
from garuda.api.routes.stix import router as stix_router
from garuda.api.routes.taxii import router as taxii_router
from garuda.api.routes.telegram import router as telegram_router
from garuda.api.routes.dashboard import router as dashboard_router
from garuda.api.routes.malware_hunt import router as malware_hunt_router

__all__ = [
    "alerts_router",
    "analyst_router",
    "bgp_router",
    "canary_router",
    "campaigns_router",
    "clusters_router",
    "easm_router",
    "pdns_router",
    "predictive_router",
    "rpz_router",
    "stix_router",
    "taxii_router",
    "collect_router",
    "stats_router",
    "telegram_router",
    "malware_hunt_router",
    "dashboard_router",
]
