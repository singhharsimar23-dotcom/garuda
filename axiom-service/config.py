"""
AXIOM Service Configuration Module
Loads environment variables using pydantic-settings.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Configuration settings for AXIOM-II telemetry and anomaly microservice."""

    environment: str = Field(default_factory=lambda: os.environ.get("ENVIRONMENT", "production"))
    debug: bool = Field(default_factory=lambda: os.environ.get("DEBUG", "false").lower() in ("true", "1"))
    host: str = Field(default_factory=lambda: os.environ.get("HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.environ.get("PORT", "10000")))

    # Supabase Configuration
    supabase_url: Optional[str] = Field(default_factory=lambda: os.environ.get("SUPABASE_URL"))
    supabase_service_key: Optional[str] = Field(
        default_factory=lambda: os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    )

    # Auth & Inter-Service Security
    agent_api_key: str = Field(default_factory=lambda: os.environ.get("AGENT_API_KEY", "GARUDA_DEFAULT_API_KEY"))
    inter_service_secret: str = Field(default_factory=lambda: os.environ.get("INTER_SERVICE_SECRET", "GARUDA_INTER_SECRET"))

    # Downstream Microservices
    brahma_service_url: str = Field(
        default_factory=lambda: os.environ.get("BRAHMA_SERVICE_URL") or "https://garuda-brahma-service.onrender.com"
    )

    # Redis (Upstash) for Offline Telemetry Buffering
    upstash_redis_rest_url: Optional[str] = Field(default_factory=lambda: os.environ.get("UPSTASH_REDIS_REST_URL"))
    upstash_redis_rest_token: Optional[str] = Field(default_factory=lambda: os.environ.get("UPSTASH_REDIS_REST_TOKEN"))

    # Default Anomaly Thresholds
    log_threshold: float = Field(default_factory=lambda: float(os.environ.get("LOG_THRESHOLD", "1.5")))
    medium_threshold: float = Field(default_factory=lambda: float(os.environ.get("MEDIUM_THRESHOLD", "3.0")))
    critical_threshold: float = Field(default_factory=lambda: float(os.environ.get("CRITICAL_THRESHOLD", "5.0")))

    class Config:
        env_file = ".env"
        extra = "ignore"


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Singleton getter for service settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
