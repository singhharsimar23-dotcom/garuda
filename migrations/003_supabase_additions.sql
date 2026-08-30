-- Migration 003: Supabase Additions & Realtime Mirroring
-- Run on Supabase PostgreSQL instance

CREATE TABLE IF NOT EXISTS anomaly_alerts_mirror (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    agent_id TEXT NOT NULL,
    hostname TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ias_score REAL NOT NULL,
    anomaly_level TEXT NOT NULL,
    top_channels JSONB,
    narrative TEXT,
    status TEXT DEFAULT 'OPEN',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_mirror_time 
ON anomaly_alerts_mirror (detected_at DESC);

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT DEFAULT 'ONLINE',
    ip_address TEXT,
    active_anomaly_level TEXT DEFAULT 'CLEAN'
);

-- Enable RLS
ALTER TABLE anomaly_alerts_mirror ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_heartbeats ENABLE ROW LEVEL SECURITY;

-- Allow anonymous/authenticated read access for frontend dashboard
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'anomaly_alerts_mirror' AND policyname = 'Public Read Anomaly Mirror'
    ) THEN
        CREATE POLICY "Public Read Anomaly Mirror" ON anomaly_alerts_mirror FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'agent_heartbeats' AND policyname = 'Public Read Agent Heartbeats'
    ) THEN
        CREATE POLICY "Public Read Agent Heartbeats" ON agent_heartbeats FOR SELECT USING (true);
    END IF;
END $$;
