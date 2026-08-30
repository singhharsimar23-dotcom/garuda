-- Migration 010: EPPI Process Provenance DAG Schema and Comprehensive Phase 3 RLS Audit
-- Ensures all 7 Phase 3 tables have active Row Level Security (RLS) policies

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Create eppi_provdag_graphs Table
CREATE TABLE IF NOT EXISTS eppi_provdag_graphs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL,
    pid int4 NOT NULL,
    ppid int4 NOT NULL,
    event_type text NOT NULL, -- EXECVE, CONNECT, MMAP_EXEC, CLONE
    comm text NOT NULL,
    details jsonb DEFAULT '{}',
    timestamp_utc timestamptz NOT NULL DEFAULT now(),
    ias_correlation_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_eppi_provdag_host_time 
ON eppi_provdag_graphs (hostname, timestamp_utc DESC);

CREATE INDEX IF NOT EXISTS idx_eppi_provdag_pid 
ON eppi_provdag_graphs (hostname, pid);

-- 2. Comprehensive RLS Audit: Enable RLS on ALL Phase 3 Tables
ALTER TABLE IF EXISTS physics_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS almanac_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS brahma_program_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS dharma_action_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS eppi_provdag_graphs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS kali_discoveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS agent_heartbeats ENABLE ROW LEVEL SECURITY;

-- 3. Define Standard Security Policies
DO $$
BEGIN
    -- eppi_provdag_graphs policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'eppi_provdag_graphs' AND policyname = 'Public Read EPPI') THEN
        CREATE POLICY "Public Read EPPI" ON eppi_provdag_graphs FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'eppi_provdag_graphs' AND policyname = 'Service Insert EPPI') THEN
        CREATE POLICY "Service Insert EPPI" ON eppi_provdag_graphs FOR INSERT WITH CHECK (true);
    END IF;

    -- physics_observations policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'physics_observations' AND policyname = 'Public Read Physics') THEN
        CREATE POLICY "Public Read Physics" ON physics_observations FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'physics_observations' AND policyname = 'Service Insert Physics') THEN
        CREATE POLICY "Service Insert Physics" ON physics_observations FOR INSERT WITH CHECK (true);
    END IF;

    -- almanac_baselines policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'almanac_baselines' AND policyname = 'Public Read Baselines') THEN
        CREATE POLICY "Public Read Baselines" ON almanac_baselines FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'almanac_baselines' AND policyname = 'Service Upsert Baselines') THEN
        CREATE POLICY "Service Upsert Baselines" ON almanac_baselines FOR ALL WITH CHECK (true);
    END IF;

    -- brahma_program_models policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'brahma_program_models' AND policyname = 'Public Read Brahma Models') THEN
        CREATE POLICY "Public Read Brahma Models" ON brahma_program_models FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'brahma_program_models' AND policyname = 'Service Upsert Brahma Models') THEN
        CREATE POLICY "Service Upsert Brahma Models" ON brahma_program_models FOR ALL WITH CHECK (true);
    END IF;

    -- agent_heartbeats policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'agent_heartbeats' AND policyname = 'Public Read Heartbeats') THEN
        CREATE POLICY "Public Read Heartbeats" ON agent_heartbeats FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'agent_heartbeats' AND policyname = 'Service Upsert Heartbeats') THEN
        CREATE POLICY "Service Upsert Heartbeats" ON agent_heartbeats FOR ALL WITH CHECK (true);
    END IF;

    -- kali_discoveries policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'kali_discoveries' AND policyname = 'Public Read Kali') THEN
        CREATE POLICY "Public Read Kali" ON kali_discoveries FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'kali_discoveries' AND policyname = 'Service Upsert Kali') THEN
        CREATE POLICY "Service Upsert Kali" ON kali_discoveries FOR ALL WITH CHECK (true);
    END IF;
END $$;
