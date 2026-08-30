"""
DHARMA Defensive Response & Mitigation Trigger
Enqueues autonomous and human-in-the-loop defense actions when IAS >= CRITICAL.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from brahma_trigger import trigger_brahma_observe

logger = logging.getLogger("axiom.dharma_trigger")


async def check_recent_stix_c2_match(hostname: str, supabase_client=None) -> bool:
    """Check if any STIX C2 domain was matched in the last 24 hours."""
    if not supabase_client:
        return False
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        res = (
            supabase_client.table("stix_c2_domains")
            .select("id, domain")
            .gte("matched_at", cutoff)
            .limit(1)
            .execute()
        )
        return bool(res.data and len(res.data) > 0)
    except Exception as e:
        logger.debug(f"STIX C2 query failed: {e}")
        return False


async def trigger_dharma_actions(
    hostname: str,
    ias_score: float,
    channel_sigmas: Dict[str, float],
    workload_class: str,
    supabase_client=None,
) -> List[Dict[str, Any]]:
    """
    Evaluate and dispatch DHARMA critical actions:
    1. Forward to BRAHMA
    2. Auto-execute DNS_SINKHOLE if STIX C2 match in last 24h
    3. Queue PROCESS_ISOLATION for operator authorization
    4. Write action records to dharma_action_log in Supabase
    """
    actions_created: List[Dict[str, Any]] = []

    # 1. Forward to BRAHMA
    await trigger_brahma_observe(
        hostname=hostname,
        ias_score=ias_score,
        channel_sigmas=channel_sigmas,
        workload_class=workload_class,
    )

    evidence = {
        "ias_score": ias_score,
        "channel_sigmas": channel_sigmas,
        "workload_class": workload_class,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
    }

    # 2. Check for recent STIX C2 match for autonomous DNS Sinkhole
    has_c2_match = await check_recent_stix_c2_match(hostname, supabase_client)
    if has_c2_match:
        sinkhole_action = {
            "action_id": f"DHARMA-SINKHOLE-{uuid.uuid4().hex[:8].upper()}",
            "hostname": hostname,
            "action_type": "DNS_SINKHOLE",
            "status": "EXECUTING_AUTONOMOUS",
            "evidence": {**evidence, "stix_c2_correlated": True},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        actions_created.append(sinkhole_action)
        logger.warning(
            f"[DHARMA AUTO-RESPONSE] Triggered DNS_SINKHOLE for {hostname} (IAS={ias_score}, STIX C2 matched)"
        )

    # 3. Queue Process Isolation for Operator Confirmation
    isolation_action = {
        "action_id": f"DHARMA-ISOLATE-{uuid.uuid4().hex[:8].upper()}",
        "hostname": hostname,
        "action_type": "PROCESS_ISOLATION",
        "status": "QUEUED_APPROVAL",
        "evidence": evidence,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    actions_created.append(isolation_action)
    logger.warning(
        f"[DHARMA ACTION QUEUED] Queued PROCESS_ISOLATION for {hostname} pending human authorization."
    )

    # 4. Write to dharma_action_log in Supabase
    if supabase_client:
        for action in actions_created:
            try:
                supabase_client.table("dharma_action_log").insert(action).execute()
            except Exception as e:
                logger.warning(f"Failed to record action in dharma_action_log: {e}")

    return actions_created
