"""
Typed Database Queries for BRAHMA Service
Manages persistence of adversary program models and ingested TTP intel.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("brahma.db.queries")


async def get_brahma_model(pool: Any, agent_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves active adversary model for an agent."""
    if not pool:
        return None

    query = """
        SELECT agent_id, actor_id, kill_chain_tactic, posterior_json,
               observation_count, entropy_bits, predicted_next_tactic,
               confidence, convergence_status, grammar_rules_json,
               last_anomaly_at, updated_at
        FROM brahma_program_models
        WHERE agent_id = $1;
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, agent_id)
            if row:
                return {
                    "agent_id": row["agent_id"],
                    "actor_id": row["actor_id"],
                    "kill_chain_tactic": row["kill_chain_tactic"],
                    "posterior": json.loads(row["posterior_json"]) if isinstance(row["posterior_json"], str) else row["posterior_json"],
                    "observation_count": row["observation_count"],
                    "entropy_bits": row["entropy_bits"],
                    "predicted_next_tactic": row["predicted_next_tactic"],
                    "confidence": row["confidence"],
                    "convergence_status": row["convergence_status"],
                    "grammar_rules": json.loads(row["grammar_rules_json"]) if row["grammar_rules_json"] else None,
                    "last_anomaly_at": row["last_anomaly_at"].isoformat() if hasattr(row["last_anomaly_at"], "isoformat") else str(row["last_anomaly_at"]),
                    "updated_at": row["updated_at"].isoformat() if hasattr(row["updated_at"], "isoformat") else str(row["updated_at"]),
                }
            return None
    except Exception as e:
        logger.warning(f"Error fetching BRAHMA model for {agent_id}: {e}")
        return None


async def upsert_brahma_model(
    pool: Any,
    agent_id: str,
    actor_id: str,
    map_tactic: str,
    posterior: Dict[str, float],
    observation_count: int,
    entropy_bits: float,
    predicted_next_tactic: str,
    confidence: float,
    convergence_status: str,
    grammar_rules: Optional[List[Any]] = None,
) -> bool:
    """Upserts adversary state model into PostgreSQL."""
    if not pool:
        return False

    query = """
        INSERT INTO brahma_program_models (
            agent_id, actor_id, kill_chain_tactic, posterior_json,
            observation_count, entropy_bits, predicted_next_tactic,
            confidence, convergence_status, grammar_rules_json,
            last_anomaly_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW()
        )
        ON CONFLICT (agent_id) DO UPDATE SET
            actor_id = EXCLUDED.actor_id,
            kill_chain_tactic = EXCLUDED.kill_chain_tactic,
            posterior_json = EXCLUDED.posterior_json,
            observation_count = EXCLUDED.observation_count,
            entropy_bits = EXCLUDED.entropy_bits,
            predicted_next_tactic = EXCLUDED.predicted_next_tactic,
            confidence = EXCLUDED.confidence,
            convergence_status = EXCLUDED.convergence_status,
            grammar_rules_json = EXCLUDED.grammar_rules_json,
            last_anomaly_at = NOW(),
            updated_at = NOW();
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                query,
                agent_id,
                actor_id,
                map_tactic,
                json.dumps(posterior),
                observation_count,
                entropy_bits,
                predicted_next_tactic,
                confidence,
                convergence_status,
                json.dumps(grammar_rules) if grammar_rules else None,
            )
            return True
    except Exception as e:
        logger.error(f"Error upserting BRAHMA model for {agent_id}: {e}")
        return False


async def insert_ttp_intel_bulk(pool: Any, records: List[Dict[str, Any]]) -> int:
    """Bulk inserts TTP threat intelligence records."""
    if not pool or not records:
        return 0

    tuples = [
        (
            r.get("actor_name", "APT36"),
            r.get("technique_id", "T1000"),
            r.get("technique_name", "Unknown Technique"),
            r.get("tactic", "execution"),
            r.get("frequency_weight", 1.0),
            r.get("source", "MITRE_ATTACK"),
        )
        for r in records
    ]

    query = """
        INSERT INTO brahma_ttp_intel (
            actor_name, technique_id, technique_name, tactic, frequency_weight, source, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW());
    """
    try:
        async with pool.acquire() as conn:
            await conn.executemany(query, tuples)
            return len(tuples)
    except Exception as e:
        logger.warning(f"Failed to bulk insert TTP intel: {e}")
        return 0
