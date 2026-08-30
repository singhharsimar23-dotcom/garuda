-- ==============================================================================
-- GARUDA COMPLETE DATABASE MIGRATION (ALL-IN-ONE FOR SUPABASE SQL EDITOR)
-- Executes all Phase 1, Phase 2, and Phase 3 schemas with RLS policies
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. PHASE 1 & 2 TABLES: THREAT CLUSTERS & RPZ RULES
CREATE TABLE IF NOT EXISTS public.threat_clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id VARCHAR(64) UNIQUE NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    tactics JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'PROPOSED',
    analyst_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.rpz_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL UNIQUE,
    action VARCHAR(32) NOT NULL DEFAULT 'nxdomain',
    confidence INTEGER NOT NULL DEFAULT 80,
    threat_actor VARCHAR(64),
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    removed_at TIMESTAMPTZ,
    is_active BOOLEAN GENERATED ALWAYS AS (removed_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())) STORED
);

-- 3. PHASE 3 SCHEMA: MONITORED AGENTS
CREATE TABLE IF NOT EXISTS public.monitored_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    agent_version VARCHAR(32) NOT NULL DEFAULT '0.1.0',
    status VARCHAR(32) NOT NULL DEFAULT 'ONLINE',
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    baseline_status VARCHAR(32) NOT NULL DEFAULT 'UNTRUSTED',
    uncontaminated_event_count INTEGER NOT NULL DEFAULT 0,
    current_ias_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_anomaly_level VARCHAR(32) NOT NULL DEFAULT 'CLEAN',
    current_workload_class VARCHAR(64) NOT NULL DEFAULT 'IDLE'
);

-- 4. PHASE 3 SCHEMA: PHYSICS OBSERVATIONS
CREATE TABLE IF NOT EXISTS public.physics_observations (
    id BIGSERIAL PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL REFERENCES public.monitored_agents(agent_id) ON DELETE CASCADE,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rapl_pkg_uw DOUBLE PRECISION,
    rapl_dram_uw DOUBLE PRECISION,
    rapl_core_uw DOUBLE PRECISION,
    instructions BIGINT,
    cache_misses BIGINT,
    cycles BIGINT,
    ipc DOUBLE PRECISION,
    entropy_avail INTEGER,
    sched_run_ms_per_sec DOUBLE PRECISION,
    sched_wait_ms_per_sec DOUBLE PRECISION,
    sched_delay_ratio DOUBLE PRECISION,
    ias_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    anomaly_level VARCHAR(32) NOT NULL DEFAULT 'CLEAN',
    workload_class VARCHAR(64) NOT NULL DEFAULT 'IDLE'
);

CREATE INDEX IF NOT EXISTS idx_physics_agent_observed ON public.physics_observations (agent_id, observed_at DESC);

-- 5. PHASE 3 SCHEMA: REALTIME MIRROR TABLES
CREATE TABLE IF NOT EXISTS public.anomaly_alerts_mirror (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id VARCHAR(64) NOT NULL UNIQUE,
    agent_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ias_score DOUBLE PRECISION NOT NULL,
    anomaly_level VARCHAR(32) NOT NULL,
    top_channels JSONB,
    narrative TEXT,
    telegram_sent BOOLEAN NOT NULL DEFAULT FALSE,
    dharma_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.agent_heartbeats (
    agent_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ONLINE',
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ias_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    anomaly_level VARCHAR(32) NOT NULL DEFAULT 'CLEAN',
    metadata JSONB
);

-- 6. PHASE 3 SCHEMA: BRAHMA MODELS & DHARMA ACTION LOGS
CREATE TABLE IF NOT EXISTS public.brahma_program_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id VARCHAR(64) NOT NULL,
    grammar_version VARCHAR(32) NOT NULL,
    transition_matrix JSONB NOT NULL,
    tactic_priors JSONB NOT NULL,
    entropy_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_brahma_actor_version UNIQUE (actor_id, grammar_version)
);

CREATE TABLE IF NOT EXISTS public.dharma_action_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id VARCHAR(64) NOT NULL UNIQUE,
    agent_id VARCHAR(64) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_identifier VARCHAR(255) NOT NULL,
    tier INTEGER NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'EXECUTED',
    authorized_by VARCHAR(64),
    authorized_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rollback_state JSONB,
    evidence_bundle JSONB
);

-- 7. IMMUTABILITY TRIGGER FOR DHARMA ACTION LOG
CREATE OR REPLACE FUNCTION trg_dharma_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        RAISE EXCEPTION 'DHARMA action log is strictly immutable: DELETE operations are prohibited.';
    END IF;
    IF (TG_OP = 'UPDATE') THEN
        IF OLD.status = 'PENDING_APPROVAL' AND NEW.status IN ('APPROVED', 'REJECTED', 'EXECUTED', 'AUTO_ESCALATED') THEN
            RETURN NEW;
        ELSE
            RAISE EXCEPTION 'DHARMA action log is strictly immutable: modifying executed actions is prohibited.';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_dharma_action_log_guard ON public.dharma_action_log;
CREATE TRIGGER trg_dharma_action_log_guard
    BEFORE UPDATE OR DELETE ON public.dharma_action_log
    FOR EACH ROW EXECUTE FUNCTION trg_dharma_log_immutable();

-- 8. ROW LEVEL SECURITY (RLS) POLICIES
ALTER TABLE public.threat_clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rpz_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.monitored_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.physics_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.anomaly_alerts_mirror ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_heartbeats ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.brahma_program_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dharma_action_log ENABLE ROW LEVEL SECURITY;

-- Allow read access for authenticated & service roles
DO $$
BEGIN
    -- Public read policy for anomaly alerts mirror & heartbeats
    CREATE POLICY "Allow anon read for realtime dashboards" ON public.anomaly_alerts_mirror FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow anon read for agent heartbeats" ON public.agent_heartbeats FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow anon read for threat clusters" ON public.threat_clusters FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow anon read for rpz rules" ON public.rpz_rules FOR SELECT TO anon, authenticated USING (true);
    
    -- Service role full access
    CREATE POLICY "Service role full access on agents" ON public.monitored_agents FOR ALL TO service_role USING (true);
    CREATE POLICY "Service role full access on observations" ON public.physics_observations FOR ALL TO service_role USING (true);
    CREATE POLICY "Service role full access on brahma" ON public.brahma_program_models FOR ALL TO service_role USING (true);
    CREATE POLICY "Service role full access on dharma" ON public.dharma_action_log FOR ALL TO service_role USING (true);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- 9. SUPABASE REALTIME REPLICATION PUBLICATION
DO $$
BEGIN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.anomaly_alerts_mirror;
    ALTER PUBLICATION supabase_realtime ADD TABLE public.agent_heartbeats;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;
