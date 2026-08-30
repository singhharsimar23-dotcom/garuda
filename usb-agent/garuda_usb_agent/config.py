"""
GARUDA USB Agent Configuration
Loads configuration from LUKS partition 2 (agent_config.json) or environment variables.
"""

import json
import logging
import os
from typing import Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("garuda.usb.config")

DEFAULT_DATA_DIR = "/media/garuda/data"


class USBConfig(BaseModel):
    agent_id: str = Field(default="usb-node-uncalibrated")
    hostname: str = Field(default="unknown-host")
    axiom_url: Optional[str] = Field(default=None)
    agent_api_key: Optional[str] = Field(default=None)
    data_dir: str = Field(default=DEFAULT_DATA_DIR)
    local_db_path: str = Field(default="/media/garuda/data/almanac.db")
    alert_queue_dir: str = Field(default="/media/garuda/data/event_queue")
    poll_rate_hz: int = Field(default=1)
    air_gapped_mode: bool = Field(default=False)


def load_usb_config(config_path: Optional[str] = None) -> USBConfig:
    """Loads configuration with fallback hierarchy."""
    path = config_path or os.path.join(DEFAULT_DATA_DIR, "agent_config.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return USBConfig(**data)
        except Exception as e:
            logger.warning(f"Could not parse config from {path}: {e}")

    # Fallback to environment variables
    data_dir = os.environ.get("GARUDA_DATA_DIR", DEFAULT_DATA_DIR)
    return USBConfig(
        agent_id=os.environ.get("GARUDA_AGENT_ID", "usb-node-uncalibrated"),
        hostname=os.environ.get("GARUDA_HOSTNAME", os.uname().nodename if hasattr(os, "uname") else "unknown-host"),
        axiom_url=os.environ.get("AXIOM_URL"),
        agent_api_key=os.environ.get("AGENT_API_KEY"),
        data_dir=data_dir,
        local_db_path=os.path.join(data_dir, "almanac.db"),
        alert_queue_dir=os.path.join(data_dir, "event_queue"),
        poll_rate_hz=int(os.environ.get("POLL_RATE_HZ", "1")),
        air_gapped_mode=os.environ.get("AIR_GAPPED_MODE", "false").lower() in ("true", "1", "yes"),
    )
