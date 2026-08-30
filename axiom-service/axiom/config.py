"""
AXIOM Service Configuration Module
Centralized settings management loaded securely from environment variables.
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class AxiomSettings(BaseSettings):
    """Configuration settings for AXIOM detection service."""

    environment: str = Field(default_factory=lambda: os.environ.get("ENVIRONMENT", "production"))
    debug: bool = Field(default_factory=lambda: os.environ.get("DEBUG", "false").lower() in ("true", "1"))
    host: str = Field(default_factory=lambda: os.environ.get("HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.environ.get("PORT", "8000")))

    # Database
    northflank_db_url: Optional[str] = Field(
        default_factory=lambda: os.environ.get("NORTHFLANK_DB_URL") or os.environ.get("DATABASE_URL")
    )
    db_pool_min_size: int = Field(default_factory=lambda: int(os.environ.get("DB_POOL_MIN_SIZE", "2")))
    db_pool_max_size: int = Field(default_factory=lambda: int(os.environ.get("DB_POOL_MAX_SIZE", "10")))

    # Supabase Realtime & Persistence
    supabase_url: Optional[str] = Field(default_factory=lambda: os.environ.get("SUPABASE_URL"))
    supabase_service_key: Optional[str] = Field(
        default_factory=lambda: os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    )

    # Authentication & Security
    agent_api_key: str = Field(default_factory=lambda: os.environ.get("AGENT_API_KEY", ""))
    inter_service_secret: str = Field(default_factory=lambda: os.environ.get("INTER_SERVICE_SECRET", ""))

    # Telegram Alerting
    telegram_bot_token: Optional[str] = Field(default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN"))
    telegram_chat_id: Optional[str] = Field(default_factory=lambda: os.environ.get("TELEGRAM_CHAT_ID"))

    # Groq & Gemini LLM Narrative Generation
    groq_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GROQ_API_KEY"))
    groq_preferred_model: str = Field(default_factory=lambda: os.environ.get("GROQ_PREFERRED_MODEL", "llama-3.3-70b-versatile"))
    groq_fallback_model: str = Field(default_factory=lambda: os.environ.get("GROQ_FALLBACK_MODEL", "llama-3.1-70b-versatile"))
    groq_daily_limit: int = Field(default_factory=lambda: int(os.environ.get("GROQ_DAILY_LIMIT", "5")))

    gemini_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GEMINI_API_KEY"))
    gemini_model: str = Field(default_factory=lambda: os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"))

    # Downstream Subsystems (Service 2 - BRAHMA / DHARMA)
    northflank_brahma_url: Optional[str] = Field(default_factory=lambda: os.environ.get("NORTHFLANK_BRAHMA_URL"))

    # Redis (Upstash) for Rate Limiting & Counters
    upstash_redis_rest_url: Optional[str] = Field(default_factory=lambda: os.environ.get("UPSTASH_REDIS_REST_URL"))
    upstash_redis_rest_token: Optional[str] = Field(default_factory=lambda: os.environ.get("UPSTASH_REDIS_REST_TOKEN"))

    # Default IAS Thresholds (Starting points before auto-calibration)
    default_log_threshold: float = Field(default_factory=lambda: float(os.environ.get("DEFAULT_LOG_THRESHOLD", "1.5")))
    default_medium_threshold: float = Field(default_factory=lambda: float(os.environ.get("DEFAULT_MEDIUM_THRESHOLD", "3.0")))
    default_critical_threshold: float = Field(default_factory=lambda: float(os.environ.get("DEFAULT_CRITICAL_THRESHOLD", "5.0")))
    
    # Feature Flags
    feature_flag_groq: bool = Field(default_factory=lambda: os.environ.get("FEATURE_FLAG_GROQ", "true").lower() in ("true", "1"))
    feature_flag_dharma: bool = Field(default_factory=lambda: os.environ.get("FEATURE_FLAG_DHARMA", "true").lower() in ("true", "1"))
    feature_flag_supabase_realtime: bool = Field(default_factory=lambda: os.environ.get("FEATURE_FLAG_SUPABASE_REALTIME", "true").lower() in ("true", "1"))

    class Config:
        env_file = ".env"
        extra = "ignore"


_settings_instance: Optional[AxiomSettings] = None


def get_settings() -> AxiomSettings:
    """Retrieve singleton configuration instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = AxiomSettings()
    return _settings_instance
