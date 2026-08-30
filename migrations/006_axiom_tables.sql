-- Migration 006: AXIOM-II Telemetry, Baselines, Heartbeats and Fleet Tables
-- Idempotent DDL for Supabase / PostgreSQL

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Physics Observations
CREATE TABLE IF NOT EXISTS physics_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id uuid NOT NULL,
    hostname text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    rapl_pkg_w float8,
    rapl_dram_w float8,
    perf_instructions_ps float8,
    perf_cache_misses_ps float8,
    entropy_bits int4,
    steal_ratio float8,
    ias_score float8 NOT NULL,
    ias_uncalibrated bool NOT NULL DEFAULT true,
    workload_class text,
    channel_sigmas jsonb,
    flags text[] DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_physics_obs_host_time 
ON physics_observations (hostname, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_physics_obs_workload 
ON physics_observations (workload_class, observed_at DESC);

-- 2. Almanac Baselines
CREATE TABLE IF NOT EXISTS almanac_baselines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL,
    workload_class text NOT NULL,
    channel text NOT NULL,  -- 'rapl_pkg', 'rapl_dram', 'perf_instructions', etc
    mean float8 NOT NULL,
    std float8 NOT NULL,
    sample_count int4 NOT NULL DEFAULT 0,
    last_updated timestamptz DEFAULT now(),
    UNIQUE (hostname, workload_class, channel)
);

CREATE INDEX IF NOT EXISTS idx_almanac_baselines_lookup 
ON almanac_baselines (hostname, workload_class, channel);

-- 3. Agent Heartbeats
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id uuid NOT NULL UNIQUE,
    hostname text NOT NULL,
    last_seen timestamptz NOT NULL DEFAULT now(),
    agent_version text,
    rapl_available bool,
    perf_available bool,
    status text DEFAULT 'ACTIVE'
);

-- 4. Agent Registry (Authentication)
CREATE TABLE IF NOT EXISTS agent_registry (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id uuid NOT NULL UNIQUE,
    hostname text NOT NULL,
    api_key text NOT NULL,
    is_active bool NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_registry_key 
ON agent_registry (api_key);

-- 5. Geopolitical Tension (Conflict Mode)
CREATE TABLE IF NOT EXISTS geopolitical_tension (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tension_index float8 NOT NULL DEFAULT 0.0,
    source text DEFAULT 'MANUAL',
    recorded_at timestamptz NOT NULL DEFAULT now()
);

-- 6. Host Auto-Calibrated Thresholds
CREATE TABLE IF NOT EXISTS host_thresholds (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL UNIQUE,
    p99_ias float8 NOT NULL,
    log_threshold float8 NOT NULL,
    medium_threshold float8 NOT NULL,
    critical_threshold float8 NOT NULL,
    sample_count int4 NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- 7. Anomaly Alerts (Fleet & Host Anomaly Log)
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id text UNIQUE NOT NULL,
    hostname text NOT NULL,
    type text NOT NULL,
    alert_type text,
    ias_score float8 NOT NULL,
    confidence_source text NOT NULL DEFAULT 'PHYSICS_LAYER',
    details jsonb,
    detected_at timestamptz NOT NULL DEFAULT now()
);

-- 8. DHARMA Action Log
CREATE TABLE IF NOT EXISTS dharma_action_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id text UNIQUE NOT NULL,
    hostname text NOT NULL,
    action_type text NOT NULL,
    status text NOT NULL,
    evidence jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- 9. STIX C2 Domains for Correlation
CREATE TABLE IF NOT EXISTS stix_c2_domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain text NOT NULL,
    matched_at timestamptz NOT NULL DEFAULT now()
);
