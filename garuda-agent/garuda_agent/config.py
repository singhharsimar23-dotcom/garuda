"""
GARUDA Agent Configuration Module
Loads configuration from environment variables with sensible defaults.
"""

import os
import socket
import uuid
from typing import Optional

try:
    from pydantic_settings import BaseSettings
    from pydantic import Field
except ImportError:  # Fallback for older pydantic versions
    try:
        from pydantic import BaseSettings, Field  # type: ignore
    except ImportError:
        # Minimal pure Python fallback if pydantic is not installed
        class BaseSettings:  # type: ignore
            def __init__(self, **kwargs):
                for k, v in self.__class__.__dict__.items():
                    if not k.startswith("_") and not callable(v):
                        env_val = os.environ.get(k.upper())
                        if env_val is not None:
                            # basic type conversion
                            if isinstance(v, bool):
                                setattr(self, k, env_val.lower() in ("true", "1", "yes"))
                            elif isinstance(v, int):
                                setattr(self, k, int(env_val))
                            elif isinstance(v, float):
                                setattr(self, k, float(env_val))
                            else:
                                setattr(self, k, env_val)
                        else:
                            setattr(self, k, kwargs.get(k, v))
                for k, v in kwargs.items():
                    setattr(self, k, v)

        def Field(default=None, **kwargs):  # type: ignore
            return default


class AgentConfig(BaseSettings):
    """Agent runtime configuration."""

    agent_id: str = Field(
        default_factory=lambda: os.environ.get(
            "GARUDA_AGENT_ID",
            f"agent-{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        )
    )
    hostname: str = Field(
        default_factory=lambda: os.environ.get("GARUDA_HOSTNAME", socket.gethostname())
    )
    agent_api_key: str = Field(
        default_factory=lambda: os.environ.get("AGENT_API_KEY", "")
    )
    axiom_url: str = Field(
        default_factory=lambda: os.environ.get("AXIOM_URL", "http://localhost:8000")
    )
    poll_interval_sec: float = Field(
        default_factory=lambda: float(os.environ.get("POLL_INTERVAL_SEC", "1.0"))
    )
    batch_size: int = Field(
        default_factory=lambda: int(os.environ.get("BATCH_SIZE", "20"))
    )
    local_db_path: str = Field(
        default_factory=lambda: os.environ.get("LOCAL_DB_PATH", "./garuda_almanac.db")
    )
    
    # Feature flags for physical & kernel channels
    rapl_enabled: bool = Field(
        default_factory=lambda: os.environ.get("RAPL_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    perf_enabled: bool = Field(
        default_factory=lambda: os.environ.get("PERF_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    entropy_enabled: bool = Field(
        default_factory=lambda: os.environ.get("ENTROPY_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    tpm_enabled: bool = Field(
        default_factory=lambda: os.environ.get("TPM_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    schedstat_enabled: bool = Field(
        default_factory=lambda: os.environ.get("SCHEDSTAT_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    eppi_enabled: bool = Field(
        default_factory=lambda: os.environ.get("EPPI_ENABLED", "true").lower() in ("true", "1", "yes")
    )

    class Config:
        env_prefix = "GARUDA_"
        extra = "ignore"


def get_config() -> AgentConfig:
    """Retrieve active configuration instance."""
    return AgentConfig()
