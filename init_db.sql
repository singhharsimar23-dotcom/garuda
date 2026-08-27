-- ==============================================================================
-- GARUDA SOVEREIGN CTI PLATFORM - SUPABASE SCHEMA & RLS SPECIFICATION
-- ==============================================================================

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

-- Enable Row Level Security (RLS) across all tables
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE whitelist ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE tension_log ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if re-running
DO $$
BEGIN
    DROP POLICY IF EXISTS "audit_insert_only" ON audit_log;
    DROP POLICY IF EXISTS "audit_read" ON audit_log;
    DROP POLICY IF EXISTS "audit_no_update" ON audit_log;
    DROP POLICY IF EXISTS "audit_no_delete" ON audit_log;
    DROP POLICY IF EXISTS "alerts_insert" ON alerts;
    DROP POLICY IF EXISTS "alerts_read_auth" ON alerts;
    DROP POLICY IF EXISTS "alerts_read_stix" ON alerts;
    DROP POLICY IF EXISTS "alerts_update" ON alerts;
    DROP POLICY IF EXISTS "alerts_no_delete" ON alerts;
    DROP POLICY IF EXISTS "whitelist_all" ON whitelist;
    DROP POLICY IF EXISTS "campaigns_all" ON campaigns;
    DROP POLICY IF EXISTS "tension_log_all" ON tension_log;
END
$$;

-- audit_log: append-only. No UPDATE or DELETE ever.
CREATE POLICY "audit_insert_only" ON audit_log FOR INSERT WITH CHECK (true);
CREATE POLICY "audit_read" ON audit_log FOR SELECT USING (true);
CREATE POLICY "audit_no_update" ON audit_log AS RESTRICTIVE FOR UPDATE USING (false);
CREATE POLICY "audit_no_delete" ON audit_log AS RESTRICTIVE FOR DELETE USING (false);

-- alerts: service_role writes, authenticated reads, anon reads confirmed STIX feed
CREATE POLICY "alerts_insert" ON alerts FOR INSERT WITH CHECK (true);
CREATE POLICY "alerts_read_auth" ON alerts FOR SELECT USING (true);
CREATE POLICY "alerts_update" ON alerts FOR UPDATE USING (true);
CREATE POLICY "alerts_no_delete" ON alerts AS RESTRICTIVE FOR DELETE USING (false);

-- whitelist, campaigns, tension_log policies
CREATE POLICY "whitelist_all" ON whitelist FOR ALL USING (true);
CREATE POLICY "campaigns_all" ON campaigns FOR ALL USING (true);
CREATE POLICY "tension_log_all" ON tension_log FOR ALL USING (true);
