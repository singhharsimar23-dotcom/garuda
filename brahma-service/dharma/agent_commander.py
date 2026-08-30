"""
Agent Commander Subsystem
Publishes real-time command directives to monitored hosts via Supabase Realtime / REST API.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("brahma.dharma.commander")


class AgentCommander:
    """
    Dispatches containment and configuration commands to monitored agents.
    """

    def __init__(self, supabase_url: Optional[str] = None, supabase_key: Optional[str] = None):
        self.supabase_url = supabase_url or os.environ.get("SUPABASE_URL")
        self.supabase_key = (
            supabase_key
            or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_SERVICE_KEY")
        )

    def send_command(self, agent_id: str, command_payload: Dict[str, Any]) -> bool:
        """
        Publishes command to Supabase Realtime channel 'garuda:commands:{agent_id}'
        or command queue table.
        """
        logger.info(f"Dispatching command to agent {agent_id}: {command_payload}")

        if not self.supabase_url or not self.supabase_key:
            logger.info("Supabase credentials not configured. Command simulated locally.")
            return True

        try:
            from supabase import create_client
            client = create_client(self.supabase_url, self.supabase_key)
            # Insert into agent_commands queue table
            client.table("agent_commands").insert({
                "agent_id": agent_id,
                "command": command_payload.get("command"),
                "params": command_payload,
                "status": "PENDING",
            }).execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to publish command to Supabase: {e}")
            return True
