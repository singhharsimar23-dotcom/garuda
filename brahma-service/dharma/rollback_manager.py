"""
Rollback Manager Subsystem
Pre-computes and executes safe rollbacks for all automated Tier 0 and Tier 1 containment actions.
"""

import logging
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger("brahma.dharma.rollback")


class RollbackManager:
    """
    Manages pre-computation and execution of rollback states.
    """

    def __init__(self, commander: Optional[Any] = None):
        self.commander = commander

    def compute_rollback_state(
        self,
        action_type: str,
        target: str,
        initial_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Pre-computes deterministic rollback state for an action before execution.
        """
        rollback_id = f"rb-{uuid.uuid4().hex[:12]}"
        init_state = initial_state or {}

        if action_type == "SENSOR_INTENSIFICATION":
            return {
                "rollback_id": rollback_id,
                "action_type": "REVERT_SENSOR_POLL_RATE",
                "target_agent": target,
                "revert_command": {"command": "set_poll_rate", "rate_hz": init_state.get("previous_rate_hz", 1.0)},
            }

        elif action_type == "PROCESS_ISOLATION":
            pid = int(target) if target.isdigit() else init_state.get("pid", 0)
            return {
                "rollback_id": rollback_id,
                "action_type": "SIGCONT_PID",
                "target_pid": pid,
                "target_agent": init_state.get("agent_id"),
                "revert_command": {"command": "sigcont_pid", "pid": pid},
            }

        elif action_type == "DNS_SINKHOLE":
            return {
                "rollback_id": rollback_id,
                "action_type": "RESTORE_DNS_RECORD",
                "domain": target,
                "previous_record": init_state.get("previous_dns_record"),
            }

        elif action_type == "CREDENTIAL_SHADOW_ROTATION":
            return {
                "rollback_id": rollback_id,
                "action_type": "REMOVE_CANARY_FILE",
                "canary_path": target,
                "target_agent": init_state.get("agent_id"),
                "revert_command": {"command": "delete_file", "path": target},
            }

        return {
            "rollback_id": rollback_id,
            "action_type": "NOOP",
            "target": target,
        }

    def execute_rollback(self, rollback_state: Dict[str, Any]) -> bool:
        """
        Executes pre-computed rollback instructions.
        """
        action_type = rollback_state.get("action_type")
        target_agent = rollback_state.get("target_agent")
        revert_cmd = rollback_state.get("revert_command")

        logger.info(f"Executing rollback action '{action_type}' for target {target_agent}")

        if self.commander and target_agent and revert_cmd:
            return self.commander.send_command(target_agent, revert_cmd)

        return True
