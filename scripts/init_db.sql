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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_cluster_id ON alerts(cluster_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_cluster_id ON campaigns(cluster_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON whitelist(domain);
CREATE INDEX IF NOT EXISTS idx_audit_log_alert_id ON audit_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_tension_log_computed_at ON tension_log(computed_at DESC);

-- Enable RLS
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
