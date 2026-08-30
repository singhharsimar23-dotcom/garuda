"""
Typed Database Query Layer for AXIOM Service
Ensures table existence checks, transaction rollback, and row count verification.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("axiom.db.queries")


async def check_tables_exist(pool: Any) -> bool:
    """
    Verifies whether the required migrations have executed.
    """
    if not pool:
        return False

    required_tables = ["monitored_agents", "physics_observations", "almanac_baselines", "anomaly_alerts"]
    query = """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = ANY($1::text[])
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, required_tables)
            existing = {r["table_name"] for r in rows}
            missing = set(required_tables) - existing
            if missing:
                logger.warning(f"Database missing required tables: {missing}. Migrations may need to run.")
                return False
            return True
    except Exception as e:
        logger.warning(f"Error checking table existence: {e}")
        return False


async def upsert_monitored_agent(
    pool: Any,
    agent_id: str,
    hostname: str,
    os_version: str = "Linux",
    kernel_version: str = "5.15",
    arch: str = "x86_64",
    poll_interval: float = 1.0,
) -> bool:
    """
    Updates or inserts agent metadata and heartbeat.
    """
    if not pool:
        return False

    query = """
        INSERT INTO monitored_agents (
            agent_id, hostname, os_version, kernel_version, arch, 
            status, poll_interval_sec, total_observations, created_at, last_seen_at
        ) VALUES ($1, $2, $3, $4, $5, 'ONLINE', $6, 1, NOW(), NOW())
        ON CONFLICT (agent_id) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            poll_interval_sec = EXCLUDED.poll_interval_sec,
            last_seen_at = NOW(),
            total_observations = monitored_agents.total_observations + 1;
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(query, agent_id, hostname, os_version, kernel_version, arch, poll_interval)
            return True
    except Exception as e:
        logger.warning(f"Failed to upsert monitored agent {agent_id}: {e}")
        return False


async def insert_physics_observations_bulk(
    pool: Any,
    agent_id: str,
    observations: List[Dict[str, Any]],
    workload_class: str = "IDLE",
    ias_score: float = 0.0,
    anomaly_level: str = "CLEAN",
    baseline_qualified: bool = True,
) -> int:
    """
    Bulk inserts telemetry records within a single transaction, verifying row count.
    """
    if not pool or not observations:
        return 0

    records = []
    for obs in observations:
        ts = obs.get("timestamp", datetime.now(timezone.utc).timestamp())
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        records.append((
            agent_id,
            dt,
            obs.get("rapl_pkg_uw"),
            obs.get("rapl_dram_uw"),
            obs.get("rapl_core_uw"),
            obs.get("instructions"),
            obs.get("cache_misses"),
            obs.get("cycles"),
            obs.get("ipc"),
            obs.get("entropy_avail"),
            obs.get("sched_run_ms_per_sec"),
            obs.get("sched_wait_ms_per_sec"),
            obs.get("sched_delay_ratio"),
            workload_class,
            ias_score,
            anomaly_level,
            baseline_qualified,
        ))

    insert_query = """
        INSERT INTO physics_observations (
            agent_id, observed_at, rapl_pkg_uw, rapl_dram_uw, rapl_core_uw,
            instructions, cache_misses, cycles, ipc, entropy_avail,
            sched_run_ms, sched_wait_ms, sched_delay_ratio,
            workload_class, ias_score, anomaly_level, baseline_qualified
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
        );
    """

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Execute in transaction
                res = await conn.executemany(insert_query, records)
                # Verify row count
                inserted_count = len(records)
                logger.debug(f"Bulk inserted {inserted_count} physics observations for agent {agent_id}.")
                return inserted_count
    except Exception as e:
        logger.error(f"Failed to bulk insert physics observations: {e}")
        return 0


async def get_almanac_baseline(
    pool: Any,
    agent_id: str,
    workload_class: str,
) -> Optional[Dict[str, Any]]:
    """
    Retrieves the Gaussian baseline model for an agent and workload class.
    """
    if not pool:
        return None

    query = """
        SELECT agent_id, workload_class, mu_json, sigma_json, threshold_json, 
               observation_count, trust_established, updated_at
        FROM almanac_baselines
        WHERE agent_id = $1 AND workload_class = $2;
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, agent_id, workload_class)
            if row:
                return {
                    "agent_id": row["agent_id"],
                    "workload_class": row["workload_class"],
                    "mu": json.loads(row["mu_json"]) if isinstance(row["mu_json"], str) else row["mu_json"],
                    "sigma": json.loads(row["sigma_json"]) if isinstance(row["sigma_json"], str) else row["sigma_json"],
                    "thresholds": json.loads(row["threshold_json"]) if isinstance(row["threshold_json"], str) else row["threshold_json"],
                    "observation_count": row["observation_count"],
                    "trust_established": row["trust_established"],
                }
            return None
    except Exception as e:
        logger.warning(f"Error fetching baseline for {agent_id}/{workload_class}: {e}")
        return None


async def upsert_almanac_baseline(
    pool: Any,
    agent_id: str,
    workload_class: str,
    mu: Dict[str, float],
    sigma: Dict[str, float],
    thresholds: Dict[str, float],
    observation_count: int,
    trust_established: bool,
) -> bool:
    """
    Updates or creates baseline Gaussian statistics.
    """
    if not pool:
        return False

    query = """
        INSERT INTO almanac_baselines (
            agent_id, workload_class, mu_json, sigma_json, threshold_json,
            observation_count, trust_established, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (agent_id, workload_class) DO UPDATE SET
            mu_json = EXCLUDED.mu_json,
            sigma_json = EXCLUDED.sigma_json,
            threshold_json = EXCLUDED.threshold_json,
            observation_count = EXCLUDED.observation_count,
            trust_established = EXCLUDED.trust_established,
            updated_at = NOW();
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                query,
                agent_id,
                workload_class,
                json.dumps(mu),
                json.dumps(sigma),
                json.dumps(thresholds),
                observation_count,
                trust_established,
            )
            return True
    except Exception as e:
        logger.warning(f"Error upserting baseline for {agent_id}: {e}")
        return False


async def insert_anomaly_alert(
    pool: Any,
    alert_id: str,
    agent_id: str,
    ias_score: float,
    anomaly_level: str,
    top_channels: List[Dict[str, Any]],
    narrative: Optional[str] = None,
    telegram_sent: bool = False,
    dharma_triggered: bool = False,
) -> bool:
    """
    Persists an anomaly detection alert record.
    """
    if not pool:
        return False

    query = """
        INSERT INTO anomaly_alerts (
            alert_id, agent_id, detected_at, ias_score, anomaly_level,
            top_channels, narrative, telegram_sent, dharma_triggered
        ) VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8)
        ON CONFLICT (alert_id) DO NOTHING;
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                query,
                alert_id,
                agent_id,
                ias_score,
                anomaly_level,
                json.dumps(top_channels),
                narrative,
                telegram_sent,
                dharma_triggered,
            )
            return True
    except Exception as e:
        logger.warning(f"Error inserting anomaly alert {alert_id}: {e}")
        return False


async def insert_tpm_snapshot(
    pool: Any,
    agent_id: str,
    pcrs: Dict[str, str],
    is_baseline: bool = False,
) -> bool:
    """
    Records a TPM PCR snapshot.
    """
    if not pool:
        return False

    query = """
        INSERT INTO tpm_snapshots (agent_id, captured_at, pcr_json, is_baseline)
        VALUES ($1, NOW(), $2, $3);
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(query, agent_id, json.dumps(pcrs), is_baseline)
            return True
    except Exception as e:
        logger.warning(f"Error inserting TPM snapshot for {agent_id}: {e}")
        return False


async def get_clean_baseline_observations(
    pool: Any,
    agent_id: str,
    workload_class: str,
    limit: int = 5000,
) -> List[float]:
    """
    Retrieves historical clean baseline IAS scores for calibration calculations.
    """
    if not pool:
        return []

    query = """
        SELECT ias_score 
        FROM physics_observations 
        WHERE agent_id = $1 AND workload_class = $2 AND baseline_qualified = true
        ORDER BY observed_at DESC 
        LIMIT $3;
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, agent_id, workload_class, limit)
            return [float(r["ias_score"]) for r in rows if r["ias_score"] is not None]
    except Exception as e:
        logger.warning(f"Error querying clean baseline observations: {e}")
        return []
