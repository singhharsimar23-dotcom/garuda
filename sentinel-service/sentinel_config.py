"""
GARUDA SENTINEL Service Configuration Module
Centralized configuration management for the autonomous agent brain.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class SentinelSettings(BaseSettings):
    """Runtime configuration for SENTINEL autonomous brain service."""

    environment: str = Field(default_factory=lambda: os.environ.get("ENVIRONMENT", "production"))
    debug: bool = Field(default_factory=lambda: os.environ.get("DEBUG", "false").lower() in ("true", "1"))
    host: str = Field(default_factory=lambda: os.environ.get("HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.environ.get("PORT", "8002")))

    # Supabase (Database & Realtime)
    supabase_url: Optional[str] = Field(default_factory=lambda: os.environ.get("SUPABASE_URL"))
    supabase_service_key: Optional[str] = Field(
        default_factory=lambda: os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    )

    # Inter-Service Communication
    inter_service_secret: str = Field(default_factory=lambda: os.environ.get("INTER_SERVICE_SECRET", ""))
    axiom_service_url: str = Field(
        default_factory=lambda: os.environ.get("AXIOM_SERVICE_URL", "https://garuda-axiom-service.onrender.com")
    )
    brahma_service_url: str = Field(
        default_factory=lambda: os.environ.get("BRAHMA_SERVICE_URL", "https://garuda-brahma-service.onrender.com")
    )
    dharma_service_url: str = Field(
        default_factory=lambda: os.environ.get("DHARMA_SERVICE_URL", "https://garuda-brahma-service.onrender.com")
    )
    maya_service_url: str = Field(
        default_factory=lambda: os.environ.get("MAYA_SERVICE_URL", "https://garuda-brahma-service.onrender.com")
    )
    kali_service_url: str = Field(
        default_factory=lambda: os.environ.get("KALI_SERVICE_URL", "https://garuda-brahma-service.onrender.com")
    )

    # Groq AI for Hypothesis Synthesis
    groq_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GROQ_API_KEY"))
    groq_model: str = Field(default_factory=lambda: os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"))

    # Telegram Alerting
    telegram_bot_token: Optional[str] = Field(default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN"))
    telegram_chat_id: Optional[str] = Field(default_factory=lambda: os.environ.get("TELEGRAM_CHAT_ID"))

    # Processing Rates & Thresholds
    conflict_mode: bool = Field(default_factory=lambda: os.environ.get("CONFLICT_MODE", "false").lower() in ("true", "1"))
    fusion_log_threshold: float = Field(default=1.5)
    fusion_medium_threshold: float = Field(default=3.0)
    fusion_critical_threshold: float = Field(default=5.0)

    class Config:
        env_file = ".env"
        extra = "ignore"


_settings: Optional[SentinelSettings] = None


def get_settings() -> SentinelSettings:
    global _settings
    if _settings is None:
        _settings = SentinelSettings()
    return _settings
