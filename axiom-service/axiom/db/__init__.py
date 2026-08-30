"""
AXIOM Database Layer
"""

from .pool import get_db_pool, init_db_pool, close_db_pool
from .queries import (
    check_tables_exist,
    upsert_monitored_agent,
    insert_physics_observations_bulk,
    get_almanac_baseline,
    upsert_almanac_baseline,
    insert_anomaly_alert,
    insert_tpm_snapshot,
    get_clean_baseline_observations,
)

__all__ = [
    "get_db_pool",
    "init_db_pool",
    "close_db_pool",
    "check_tables_exist",
    "upsert_monitored_agent",
    "insert_physics_observations_bulk",
    "get_almanac_baseline",
    "upsert_almanac_baseline",
    "insert_anomaly_alert",
    "insert_tpm_snapshot",
    "get_clean_baseline_observations",
]
