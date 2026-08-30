"""
DHARMA Action Log Repository
Manages append-only execution history for all automated and operator-authorized containment actions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("brahma.dharma.log")


class ActionLogRepository:
    """
    Appends action records to PostgreSQL dharma_action_log table.
    """

    def __init__(self, db_pool: Optional[Any] = None):
        self.db_pool = db_pool
        # In-memory log buffer for testing
        self._memory_log: List[Dict[str, Any]] = []

    async def log_action(
        self,
        action_id: str,
        action_type: str,
        tier: int,
        target: str,
        agent_status_before: str = "ONLINE",
        brahma_posterior_before: Optional[Dict[str, Any]] = None,
        ias_score_before: float = 0.0,
        rollback_available: bool = True,
        rollback_state: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
    ) -> bool:
        """
        Inserts an immutable execution record into dharma_action_log.
        """
        record = {
            "action_id": action_id,
            "action_type": action_type,
            "tier": tier,
            "target": target,
            "agent_status_before": agent_status_before,
            "brahma_posterior_before": brahma_posterior_before or {},
            "ias_score_before": ias_score_before,
            "rollback_available": rollback_available,
            "rollback_state": rollback_state or {},
            "operator_id": operator_id,
        }
        self._memory_log.append(record)

        if not self.db_pool:
            return True

        query = """
            INSERT INTO dharma_action_log (
                action_id, action_type, tier, target, executed_at,
                agent_status_before, brahma_posterior_before, ias_score_before,
                rollback_available, rollback_state, operator_id, approved_at
            ) VALUES (
                $1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9, $10, NOW()
            );
        """
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    query,
                    action_id,
                    action_type,
                    tier,
                    target,
                    agent_status_before,
                    json.dumps(brahma_posterior_before or {}),
                    ias_score_before,
                    rollback_available,
                    json.dumps(rollback_state or {}),
                    operator_id,
                )
                return True
        except Exception as e:
            logger.error(f"Failed to log action to PostgreSQL: {e}")
            return False

    def get_recent_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent action logs."""
        return list(reversed(self._memory_log[-limit:]))
