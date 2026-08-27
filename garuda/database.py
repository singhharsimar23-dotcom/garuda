from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from supabase import Client, create_client

from garuda.config import settings

# ==============================================================================
# Supabase Client Initialization
# ==============================================================================

_supabase_client: Optional[Client] = None


def get_supabase_client() -> Optional[Client]:
    """Retrieve or initialize the Supabase client singleton."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if settings.SUPABASE_URL and (settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY):
        url = settings.SUPABASE_URL.strip()
        key = (settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY or "").strip()
        if "your-project" in url or "your-supabase" in key or not url.startswith("http"):
            return None
        try:
            _supabase_client = create_client(url, key)
            return _supabase_client
        except Exception:
            return None

    return None


# ==============================================================================
# Pydantic Table Schema Models
# ==============================================================================


class AlertBase(BaseModel):
    domain: str
    score: int = Field(ge=0, le=100)
    signals: Dict[str, Any] = Field(default_factory=dict)
    registered_at: Optional[datetime] = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    registrar: Optional[str] = None
    hosting_ip: Optional[str] = None
    hosting_asn: Optional[int] = None
    sector: Optional[str] = None
    cluster_id: Optional[str] = None
    status: str = Field(default="pending")
    analyst_id: Optional[str] = None
    analyst_note: Optional[str] = None
    yara_rule: Optional[str] = None
    screenshot_url: Optional[str] = None
    stix_id: Optional[str] = None
    llm_narrative: Optional[str] = None


class AlertCreate(AlertBase):
    pass


class AlertInDB(AlertBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class CampaignBase(BaseModel):
    cluster_id: str
    domain_count: int = Field(default=1, ge=1)
    registrar: Optional[str] = None
    hosting_asn: Optional[int] = None
    sectors: List[str] = Field(default_factory=list)
    estimated_attack_window_days: Optional[int] = None
    confidence: str = Field(default="medium")


class CampaignCreate(CampaignBase):
    pass


class CampaignInDB(CampaignBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class WhitelistBase(BaseModel):
    domain: str
    reason: Optional[str] = None
    analyst_id: Optional[str] = None


class WhitelistCreate(WhitelistBase):
    pass


class WhitelistInDB(WhitelistBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class AuditLogBase(BaseModel):
    alert_id: Optional[UUID] = None
    action: str
    analyst_id: Optional[str] = None
    justification: str


class AuditLogCreate(AuditLogBase):
    pass


class AuditLogInDB(AuditLogBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class TensionLogBase(BaseModel):
    tension_index: float = Field(ge=0.0, le=1.0)
    conflict_mode: bool = False
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TensionLogCreate(TensionLogBase):
    pass


class TensionLogInDB(TensionLogBase):
    id: UUID = Field(default_factory=uuid4)
    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Supabase Schema DDL Definition
# ==============================================================================

INIT_SCHEMA_SQL = """
-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL,
    score INT NOT NULL CHECK (score >= 0 AND score <= 100),
    signals JSONB DEFAULT '{}'::jsonb,
    registered_at TIMESTAMPTZ,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registrar TEXT,
    hosting_ip TEXT,
    hosting_asn INT,
    sector TEXT,
    cluster_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    analyst_id TEXT,
    analyst_note TEXT,
    yara_rule TEXT,
    screenshot_url TEXT,
    stix_id TEXT,
    llm_narrative TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Campaigns Table
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id TEXT UNIQUE NOT NULL,
    domain_count INT NOT NULL DEFAULT 1,
    registrar TEXT,
    hosting_asn INT,
    sectors TEXT[] DEFAULT '{}',
    estimated_attack_window_days INT,
    confidence TEXT DEFAULT 'medium',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Whitelist Table
CREATE TABLE IF NOT EXISTS whitelist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT UNIQUE NOT NULL,
    reason TEXT,
    analyst_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit Log Table (Append-Only with RLS)
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    analyst_id TEXT,
    justification TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tension Log Table
CREATE TABLE IF NOT EXISTS tension_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tension_index FLOAT NOT NULL CHECK (tension_index >= 0.0 AND tension_index <= 1.0),
    conflict_mode BOOLEAN NOT NULL DEFAULT FALSE,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for Fast Querying
CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_cluster_id ON alerts(cluster_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_cluster_id ON campaigns(cluster_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON whitelist(domain);
CREATE INDEX IF NOT EXISTS idx_audit_log_alert_id ON audit_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_tension_log_computed_at ON tension_log(computed_at DESC);

-- Row Level Security (RLS) - Append-Only Enforced for audit_log
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'audit_log' AND policyname = 'audit_log_select_policy'
    ) THEN
        CREATE POLICY audit_log_select_policy ON audit_log FOR SELECT USING (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'audit_log' AND policyname = 'audit_log_insert_policy'
    ) THEN
        CREATE POLICY audit_log_insert_policy ON audit_log FOR INSERT WITH CHECK (true);
    END IF;

    -- Explicitly disallow UPDATE and DELETE for audit_log to enforce immutability
    IF EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'audit_log' AND policyname = 'audit_log_no_update'
    ) THEN
        DROP POLICY audit_log_no_update ON audit_log;
    END IF;
    CREATE POLICY audit_log_no_update ON audit_log FOR UPDATE USING (false);

    IF EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'audit_log' AND policyname = 'audit_log_no_delete'
    ) THEN
        DROP POLICY audit_log_no_delete ON audit_log;
    END IF;
    CREATE POLICY audit_log_no_delete ON audit_log FOR DELETE USING (false);
END
$$;
"""


async def init_database_tables() -> None:
    """Execute startup checks or schema setup if Supabase client is connected."""
    client = get_supabase_client()
    if client is None:
        # Client not configured in local environment; tables will be loaded via Docker/Postgres
        return
    # TODO: verify Supabase direct execution or RPC for table creation if necessary
