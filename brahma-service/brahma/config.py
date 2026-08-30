"""
BRAHMA Service Configuration Module
Centralized configuration management loaded from environment variables.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class BrahmaSettings(BaseSettings):
    """Runtime configuration for BRAHMA service."""

    environment: str = Field(default_factory=lambda: os.environ.get("ENVIRONMENT", "production"))
    debug: bool = Field(default_factory=lambda: os.environ.get("DEBUG", "false").lower() in ("true", "1"))
    host: str = Field(default_factory=lambda: os.environ.get("HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.environ.get("PORT", "8001")))

    # Database Connection
    northflank_db_url: Optional[str] = Field(
        default_factory=lambda: os.environ.get("NORTHFLANK_DB_URL") or os.environ.get("DATABASE_URL")
    )
    db_pool_min_size: int = Field(default_factory=lambda: int(os.environ.get("DB_POOL_MIN_SIZE", "2")))
    db_pool_max_size: int = Field(default_factory=lambda: int(os.environ.get("DB_POOL_MAX_SIZE", "10")))

    # Supabase (Database & Realtime)
    supabase_url: Optional[str] = Field(default_factory=lambda: os.environ.get("SUPABASE_URL"))
    supabase_service_key: Optional[str] = Field(
        default_factory=lambda: os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    )

    # Inter-Service Authentication (AXIOM <-> BRAHMA)
    inter_service_secret: str = Field(default_factory=lambda: os.environ.get("INTER_SERVICE_SECRET", ""))
    northflank_axiom_url: Optional[str] = Field(default_factory=lambda: os.environ.get("NORTHFLANK_AXIOM_URL"))

    # AI Threat Narrative & Grammar Expansion (Google Gemini & Groq)
    gemini_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GEMINI_API_KEY"))
    gemini_model: str = Field(default_factory=lambda: os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"))

    groq_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GROQ_API_KEY"))
    groq_preferred_model: str = Field(default_factory=lambda: os.environ.get("GROQ_PREFERRED_MODEL", "llama-3.3-70b-versatile"))
    groq_grammar_hourly_limit: int = Field(default_factory=lambda: int(os.environ.get("GROQ_GRAMMAR_HOURLY_LIMIT", "5")))

    # Detection & Attribution Thresholds
    grammar_expansion_entropy_threshold: float = Field(
        default_factory=lambda: float(os.environ.get("GRAMMAR_EXPANSION_ENTROPY_THRESHOLD", "2.0"))
    )
    attribution_observation_threshold: int = Field(
        default_factory=lambda: int(os.environ.get("ATTRIBUTION_OBSERVATION_THRESHOLD", "15"))
    )

    class Config:
        env_file = ".env"
        extra = "ignore"


_settings_instance: Optional[BrahmaSettings] = None


def get_settings() -> BrahmaSettings:
    """Retrieve singleton configuration instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = BrahmaSettings()
    return _settings_instance
