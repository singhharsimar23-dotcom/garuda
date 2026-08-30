"""
Append-Only Immutable Action Log Repository
Records all DHARMA containment events to Supabase dharma_action_log table.
Strictly append-only: updates are never performed to comply with immutable RLS security policy.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("brahma.dharma.action_log")


class DharmaActionLogRepository:
    """
    Manages append-only immutable action records in Supabase.
    """

    def __init__(
        self,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
    ):
        self.supabase_url = supabase_url or os.environ.get("SUPABASE_URL")
        self.supabase_key = (
            supabase_key
            or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_SERVICE_KEY")
        )
        self._in_memory_log: List[Dict[str, Any]] = []

    async def log_action(
        self,
        action_id: str,
        action_type: str,
        tier: int,
        target: str,
        ias_score_before: float = 0.0,
        rollback_available: bool = True,
        rollback_state: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = "operator_hq",
        hostname: str = "host-01",
    ) -> Dict[str, Any]:
        """Convenience method for logging action events."""
        return await self.append_action_event(
            action_id=action_id,
            action_type=action_type,
            tier=tier,
            hostname=hostname,
            target=target,
            status="EXECUTED",
            ias_score=ias_score_before,
            operator_id=operator_id,
            execution_detail={"rollback_available": rollback_available, "rollback_state": rollback_state},
        )

    def _get_supabase_client(self):
        if not self.supabase_url or not self.supabase_key:
            return None
        try:
            from supabase import create_client
            return create_client(self.supabase_url, self.supabase_key)
        except Exception as e:
            logger.debug(f"Failed creating Supabase client for action log: {e}")
            return None

    async def append_action_event(
        self,
        action_id: str,
        action_type: str,
        tier: int,
        hostname: str,
        target: str,
        status: str,
        ias_score: Optional[float] = None,
        ioc_evidence: Optional[Dict[str, Any]] = None,
        physics_evidence: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
        execution_detail: Optional[Dict[str, Any]] = None,
        approved_at: Optional[str] = None,
        executed_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Appends an immutable state transition row to dharma_action_log.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        entry = {
            "action_id": action_id,
            "action_type": action_type,
            "tier": tier,
            "hostname": hostname,
            "target": target,
            "ias_score_at_trigger": round(ias_score, 4) if ias_score is not None else None,
            "ioc_evidence": ioc_evidence or {},
            "physics_evidence": physics_evidence or {},
            "status": status,
            "operator_id": operator_id,
            "approved_at": approved_at,
            "executed_at": executed_at,
            "execution_detail": execution_detail or {},
            "created_at": now_iso,
        }

        # Keep in local in-memory log
        self._in_memory_log.append(entry)
        logger.info(
            f"[DHARMA LOG APPEND] Action {action_id} ({action_type} - Tier {tier}) on {hostname}: "
            f"Status='{status}'"
        )

        # Write to Supabase (Insert only — never Update)
        client = self._get_supabase_client()
        if client:
            try:
                res = client.table("dharma_action_log").insert(entry).execute()
                if res.data:
                    return res.data[0]
            except Exception as e:
                logger.warning(f"Failed to append to dharma_action_log in Supabase: {e}")

        return entry

    async def get_recent_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent actions from Supabase or memory."""
        client = self._get_supabase_client()
        if client:
            try:
                res = (
                    client.table("dharma_action_log")
                    .select("*")
                    .order("created_at", desc=True)
                    .limit(limit)
                    .execute()
                )
                if res.data:
                    return res.data
            except Exception as e:
                logger.debug(f"Failed to query dharma_action_log from Supabase: {e}")

        # Return in-memory fallback reversed
        return list(reversed(self._in_memory_log[-limit:]))


_action_log_repo = DharmaActionLogRepository()
ActionLogRepository = DharmaActionLogRepository


def get_dharma_action_log_repo() -> DharmaActionLogRepository:
    return _action_log_repo

