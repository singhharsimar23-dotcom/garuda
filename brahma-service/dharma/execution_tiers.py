"""
DHARMA Execution Tiers & Response Engine
Implements the 4-tier containment hierarchy, orchestrating autonomous Tier 2 execution,
human-authorized Tier 1/3 queues with Redis SLA timers, and append-only audit logging.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from .action_log import get_dharma_action_log_repo
from .cloudflare_sinkhole import get_cloudflare_sinkhole_executor
from .redis_sla import get_redis_sla_manager
from .ssh_process_isolator import get_ssh_process_isolator
from .telegram_notifier import get_telegram_notifier

logger = logging.getLogger("brahma.dharma.tiers")


class DharmaExecutionEngine:
    """
    Core defensive execution orchestrator for GARUDA.
    """

    def __init__(self):
        self.action_log = get_dharma_action_log_repo()
        self.cf_executor = get_cloudflare_sinkhole_executor()
        self.ssh_isolator = get_ssh_process_isolator()
        self.redis_sla = get_redis_sla_manager()
        self.telegram = get_telegram_notifier()

    async def evaluate_and_dispatch(
        self,
        hostname: str,
        ias_score: float,
        attribution_status: str,
        target_pid: Optional[int] = None,
        target_domain: Optional[str] = None,
        lateral_movement_suspected: bool = False,
        ioc_evidence: Optional[Dict[str, Any]] = None,
        physics_evidence: Optional[Dict[str, Any]] = None,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Evaluate incoming event across Tier 0..3 and execute or queue actions accordingly.
        """
        # ==========================================
        # TIER 3: IAS >= 8.0 AND LATERAL MOVEMENT
        # ==========================================
        if ias_score >= 8.0 and lateral_movement_suspected:
            action_id = f"DHARMA-T3-{uuid.uuid4().hex[:8].upper()}"
            action_payload = {
                "action_id": action_id,
                "action_type": "NETWORK_ISOLATION",
                "tier": 3,
                "hostname": hostname,
                "target": f"ALL_TRAFFIC_{hostname}",
                "ias_score": ias_score,
                "ioc_evidence": ioc_evidence or {},
                "physics_evidence": physics_evidence or {},
                "status": "QUEUED_EMERGENCY_APPROVAL",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            # 5-minute emergency SLA
            await self.redis_sla.queue_action_sla(action_id, action_payload, ttl_seconds=300)
            await self.action_log.append_action_event(
                action_id=action_id,
                action_type="NETWORK_ISOLATION",
                tier=3,
                hostname=hostname,
                target=f"ALL_TRAFFIC_{hostname}",
                status="QUEUED_EMERGENCY_APPROVAL",
                ias_score=ias_score,
                ioc_evidence=ioc_evidence,
                physics_evidence=physics_evidence,
            )

            # Alert operator immediately
            await self.telegram.send_alert(
                f"🚨 *[DHARMA TIER 3 EMERGENCY NETWORK ISOLATION]* 🚨\n\n"
                f"*Action ID:* `{action_id}`\n"
                f"*Host:* `{hostname}`\n"
                f"*IAS Score:* `{ias_score:.2f} (Extreme)`\n"
                f"*Campaign:* Coordinated Lateral Movement Detected\n"
                f"*SLA Countdown:* 5 Minutes\n\n"
                f"_Immediate operator confirmation required. No autonomous execution for Tier 3._",
                action_id=action_id,
                include_buttons=True,
            )

            return {"tier": 3, "status": "QUEUED_EMERGENCY_APPROVAL", "action_id": action_id}

        # ==========================================
        # TIER 2: IAS >= 5.0 AND ATTRIBUTED ACTOR
        # ==========================================
        is_attributed = "ATTRIBUTED" in attribution_status
        if ias_score >= 5.0 and is_attributed:
            results = []

            # 1. Cloudflare DNS Sinkhole for C2 Domain (if provided)
            if target_domain:
                sinkhole_action_id = f"DHARMA-CF-{uuid.uuid4().hex[:8].upper()}"
                status_cf, detail_cf = await self.cf_executor.execute_sinkhole(
                    domain=target_domain,
                    action_id=sinkhole_action_id,
                    hostname=hostname,
                )

                await self.action_log.append_action_event(
                    action_id=sinkhole_action_id,
                    action_type="DNS_SINKHOLE",
                    tier=2,
                    hostname=hostname,
                    target=target_domain,
                    status=status_cf,
                    ias_score=ias_score,
                    ioc_evidence=ioc_evidence,
                    physics_evidence=physics_evidence,
                    executed_at=datetime.now(timezone.utc).isoformat() if status_cf == "EXECUTED" else None,
                    execution_detail=detail_cf,
                )

                if status_cf in ("EXECUTED", "ALREADY_APPLIED"):
                    await self.telegram.notify_tier2_auto_execute(
                        action_id=sinkhole_action_id,
                        action_type="DNS_SINKHOLE",
                        hostname=hostname,
                        target=target_domain,
                        ias_score=ias_score,
                        evidence_count=len(ioc_evidence or {}) + len(physics_evidence or {}),
                    )
                results.append({"action_id": sinkhole_action_id, "type": "DNS_SINKHOLE", "status": status_cf})

            # 2. Process Isolation via SSH SIGSTOP (if target PID provided)
            if target_pid:
                iso_action_id = f"DHARMA-ISO-{uuid.uuid4().hex[:8].upper()}"
                status_ssh, detail_ssh = await self.ssh_isolator.isolate_process(
                    hostname=hostname,
                    pid=target_pid,
                    action_id=iso_action_id,
                    supabase_client=supabase_client,
                )

                await self.action_log.append_action_event(
                    action_id=iso_action_id,
                    action_type="PROCESS_ISOLATION",
                    tier=2,
                    hostname=hostname,
                    target=f"PID {target_pid}",
                    status=status_ssh,
                    ias_score=ias_score,
                    ioc_evidence=ioc_evidence,
                    physics_evidence=physics_evidence,
                    executed_at=datetime.now(timezone.utc).isoformat() if status_ssh == "EXECUTED" else None,
                    execution_detail=detail_ssh,
                )

                if status_ssh == "EXECUTED":
                    await self.telegram.notify_tier2_auto_execute(
                        action_id=iso_action_id,
                        action_type="PROCESS_ISOLATION",
                        hostname=hostname,
                        target=f"PID {target_pid}",
                        ias_score=ias_score,
                        evidence_count=len(physics_evidence or {}),
                    )
                results.append({"action_id": iso_action_id, "type": "PROCESS_ISOLATION", "status": status_ssh})

            return {"tier": 2, "status": "EXECUTED_AUTO", "actions": results}

        # ==========================================
        # TIER 1: IAS >= 3.0 (MEDIUM)
        # ==========================================
        if ias_score >= 3.0:
            target_desc = f"PID {target_pid}" if target_pid else (target_domain or f"NODE_{hostname}")
            action_type = "PROCESS_ISOLATION" if target_pid else "DNS_SINKHOLE" if target_domain else "FILE_QUARANTINE"
            action_id = f"DHARMA-T1-{uuid.uuid4().hex[:8].upper()}"

            action_payload = {
                "action_id": action_id,
                "action_type": action_type,
                "tier": 1,
                "hostname": hostname,
                "target": target_desc,
                "target_pid": target_pid,
                "target_domain": target_domain,
                "ias_score": ias_score,
                "attribution_status": attribution_status,
                "ioc_evidence": ioc_evidence or {},
                "physics_evidence": physics_evidence or {},
                "status": "QUEUED",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            # 15-minute SLA countdown
            await self.redis_sla.queue_action_sla(action_id, action_payload, ttl_seconds=900)
            await self.action_log.append_action_event(
                action_id=action_id,
                action_type=action_type,
                tier=1,
                hostname=hostname,
                target=target_desc,
                status="QUEUED",
                ias_score=ias_score,
                ioc_evidence=ioc_evidence,
                physics_evidence=physics_evidence,
            )

            # Telegram inline approval alert
            await self.telegram.send_alert(
                f"🛡️ *[DHARMA TIER 1 APPROVAL QUEUED]*\n\n"
                f"*Action ID:* `{action_id}`\n"
                f"*Type:* `{action_type}`\n"
                f"*Host:* `{hostname}`\n"
                f"*Target:* `{target_desc}`\n"
                f"*Trigger IAS:* `{ias_score:.2f}`\n"
                f"*SLA Countdown:* 15 Minutes\n\n"
                f"_Approve or Reject via buttons below:_",
                action_id=action_id,
                include_buttons=True,
            )

            return {"tier": 1, "status": "QUEUED", "action_id": action_id}

        # ==========================================
        # TIER 0: IAS in [1.5, 3.0) — Observe Only
        # ==========================================
        logger.info(f"[DHARMA TIER 0] Observation logged for {hostname} (IAS={ias_score:.2f}). No containment action.")
        return {"tier": 0, "status": "OBSERVE_ONLY", "action_id": None}

    async def approve_action(
        self,
        action_id: str,
        operator_id: str = "operator_hq",
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Execute operator approval: runs real SSH SIGSTOP or Cloudflare DNS sinkhole,
        appends EXECUTED row to dharma_action_log, and clears Redis SLA.
        """
        # 1. Remove SLA timer
        await self.redis_sla.delete_action_sla(action_id)

        # Retrieve action context
        history = await self.action_log.get_recent_actions(limit=100)
        action_entry = next((a for a in history if a.get("action_id") == action_id), None)

        hostname = action_entry.get("hostname", "unknown") if action_entry else "unknown"
        target = action_entry.get("target", "") if action_entry else ""
        action_type = action_entry.get("action_type", "PROCESS_ISOLATION") if action_entry else "PROCESS_ISOLATION"
        tier = int(action_entry.get("tier", 1)) if action_entry else 1

        exec_status = "EXECUTED"
        exec_detail = {}

        # 2. Execute Real Containment
        if action_type == "PROCESS_ISOLATION":
            pid_match = None
            if "PID" in target:
                try:
                    pid_match = int(target.replace("PID", "").replace("pid_", "").strip())
                except ValueError:
                    pid_match = None

            if pid_match:
                exec_status, exec_detail = await self.ssh_isolator.isolate_process(
                    hostname=hostname,
                    pid=pid_match,
                    action_id=action_id,
                    supabase_client=supabase_client,
                )
            else:
                exec_status = "FAILED"
                exec_detail = {"error": f"Could not parse PID from target '{target}'"}

        elif action_type == "DNS_SINKHOLE":
            exec_status, exec_detail = await self.cf_executor.execute_sinkhole(
                domain=target,
                action_id=action_id,
                hostname=hostname,
            )

        # 3. Append Immutable Log Event
        approved_entry = await self.action_log.append_action_event(
            action_id=action_id,
            action_type=action_type,
            tier=tier,
            hostname=hostname,
            target=target,
            status=exec_status,
            operator_id=operator_id,
            approved_at=datetime.now(timezone.utc).isoformat(),
            executed_at=datetime.now(timezone.utc).isoformat() if exec_status == "EXECUTED" else None,
            execution_detail=exec_detail,
        )

        return {
            "success": exec_status in ("EXECUTED", "ALREADY_APPLIED"),
            "action_id": action_id,
            "status": exec_status,
            "execution_detail": exec_detail,
        }

    async def reject_action(
        self,
        action_id: str,
        operator_id: str = "operator_hq",
        resume_process: bool = False,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Execute operator rejection: cancels action, optionally reverses process isolation (SIGCONT),
        appends REJECTED row to dharma_action_log, and clears Redis SLA.
        """
        await self.redis_sla.delete_action_sla(action_id)

        history = await self.action_log.get_recent_actions(limit=100)
        action_entry = next((a for a in history if a.get("action_id") == action_id), None)

        hostname = action_entry.get("hostname", "unknown") if action_entry else "unknown"
        target = action_entry.get("target", "") if action_entry else ""
        action_type = action_entry.get("action_type", "PROCESS_ISOLATION") if action_entry else "PROCESS_ISOLATION"
        tier = int(action_entry.get("tier", 1)) if action_entry else 1

        reversal_detail = {}
        if resume_process and action_type == "PROCESS_ISOLATION":
            try:
                pid = int(target.replace("PID", "").replace("pid_", "").strip())
                _, reversal_detail = await self.ssh_isolator.resume_process(
                    hostname=hostname,
                    pid=pid,
                    action_id=action_id,
                    supabase_client=supabase_client,
                )
            except Exception as e:
                reversal_detail = {"error": str(e)}

        await self.action_log.append_action_event(
            action_id=action_id,
            action_type=action_type,
            tier=tier,
            hostname=hostname,
            target=target,
            status="REJECTED",
            operator_id=operator_id,
            execution_detail=reversal_detail,
        )

        return {
            "success": True,
            "action_id": action_id,
            "status": "REJECTED",
            "reversal_detail": reversal_detail,
        }


_execution_engine = DharmaExecutionEngine()


def get_dharma_execution_engine() -> DharmaExecutionEngine:
    return _execution_engine
