-- ==============================================================================
-- GARUDA MASTER PRODUCTION DATABASE SCHEMA (MIGRATIONS 001 - 012)
-- 100% Idempotent, Migration-Safe & Evolution-Safe PostgreSQL DDL for Supabase
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------------------------
-- 1. AGENT REGISTRY & HEARTBEATS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_registry (
    agent_id text PRIMARY KEY,
    api_key_hash text NOT NULL DEFAULT '',
    hostname text NOT NULL DEFAULT 'unknown',
    status text NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE agent_registry ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE agent_registry ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE agent_registry ADD COLUMN IF NOT EXISTS api_key_hash text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    agent_id text PRIMARY KEY,
    hostname text NOT NULL DEFAULT 'unknown',
    last_seen timestamptz NOT NULL DEFAULT now(),
    agent_version text NOT NULL DEFAULT '0.1.0',
    rapl_available bool NOT NULL DEFAULT true,
    perf_available bool NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'ACTIVE'
);
ALTER TABLE agent_heartbeats ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE agent_heartbeats ADD COLUMN IF NOT EXISTS agent_version text NOT NULL DEFAULT '0.1.0';
ALTER TABLE agent_heartbeats ADD COLUMN IF NOT EXISTS rapl_available bool NOT NULL DEFAULT true;
ALTER TABLE agent_heartbeats ADD COLUMN IF NOT EXISTS perf_available bool NOT NULL DEFAULT true;
ALTER TABLE agent_heartbeats ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'ACTIVE';

-- ------------------------------------------------------------------------------
-- 2. HARDWARE PHYSICS OBSERVATIONS & STATISTICAL BASELINES
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS physics_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id text,
    hostname text NOT NULL DEFAULT 'unknown',
    observed_at timestamptz NOT NULL DEFAULT now(),
    rapl_pkg_w float8,
    rapl_dram_w float8,
    perf_instructions_ps float8,
    perf_cache_misses_ps float8,
    entropy_bits float8 NOT NULL DEFAULT 256.0,
    steal_ratio float8 NOT NULL DEFAULT 0.0,
    ias_score float8 NOT NULL DEFAULT 0.0,
    ias_uncalibrated bool NOT NULL DEFAULT false,
    workload_class text NOT NULL DEFAULT 'GENERAL',
    channel_sigmas jsonb DEFAULT '{}',
    flags text[] DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS rapl_pkg_w float8;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS rapl_dram_w float8;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS perf_instructions_ps float8;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS perf_cache_misses_ps float8;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS entropy_bits float8 NOT NULL DEFAULT 256.0;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS steal_ratio float8 NOT NULL DEFAULT 0.0;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS ias_score float8 NOT NULL DEFAULT 0.0;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS ias_uncalibrated bool NOT NULL DEFAULT false;
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS workload_class text NOT NULL DEFAULT 'GENERAL';
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS channel_sigmas jsonb DEFAULT '{}';
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS flags text[] DEFAULT '{}';
ALTER TABLE physics_observations ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_physics_obs_host_time 
ON physics_observations (hostname, observed_at DESC);

CREATE TABLE IF NOT EXISTS almanac_baselines (
    hostname text NOT NULL,
    workload_class text NOT NULL,
    channel text NOT NULL,
    sample_count int8 NOT NULL DEFAULT 0,
    mean float8 NOT NULL DEFAULT 0.0,
    variance float8 NOT NULL DEFAULT 1.0,
    std_dev float8 NOT NULL DEFAULT 1.0,
    m2 float8 NOT NULL DEFAULT 0.0,
    contamination_count int8 NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (hostname, workload_class, channel)
);
ALTER TABLE almanac_baselines ADD COLUMN IF NOT EXISTS sample_count int8 NOT NULL DEFAULT 0;
ALTER TABLE almanac_baselines ADD COLUMN IF NOT EXISTS mean float8 NOT NULL DEFAULT 0.0;
ALTER TABLE almanac_baselines ADD COLUMN IF NOT EXISTS variance float8 NOT NULL DEFAULT 1.0;
ALTER TABLE almanac_baselines ADD COLUMN IF NOT EXISTS std_dev float8 NOT NULL DEFAULT 1.0;
ALTER TABLE almanac_baselines ADD COLUMN IF NOT EXISTS m2 float8 NOT NULL DEFAULT 0.0;
ALTER TABLE almanac_baselines ADD COLUMN IF NOT EXISTS contamination_count int8 NOT NULL DEFAULT 0;

-- ------------------------------------------------------------------------------
-- 3. EPPI PROCESS PROVENANCE DAGS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eppi_provdag_graphs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL DEFAULT 'unknown',
    pid int4 NOT NULL DEFAULT 0,
    ppid int4 NOT NULL DEFAULT 0,
    event_type text NOT NULL DEFAULT 'EXECVE',
    comm text NOT NULL DEFAULT '',
    details jsonb DEFAULT '{}',
    timestamp_utc timestamptz NOT NULL DEFAULT now(),
    ias_correlation_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS pid int4 NOT NULL DEFAULT 0;
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS ppid int4 NOT NULL DEFAULT 0;
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS event_type text NOT NULL DEFAULT 'EXECVE';
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS comm text NOT NULL DEFAULT '';
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS details jsonb DEFAULT '{}';
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS timestamp_utc timestamptz NOT NULL DEFAULT now();
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS ias_correlation_id uuid;
ALTER TABLE eppi_provdag_graphs ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_eppi_provdag_host_time 
ON eppi_provdag_graphs (hostname, timestamp_utc DESC);

-- ------------------------------------------------------------------------------
-- 4. BRAHMA BAYESIAN MODELS & DRIFT LOGS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS brahma_program_models (
    hostname text PRIMARY KEY,
    alpha_counts float8[] NOT NULL DEFAULT '{5,5,5,5,5,5,5,5,5,5,5,5,5,5}',
    prior_counts float8[] NOT NULL DEFAULT '{5,5,5,5,5,5,5,5,5,5,5,5,5,5}',
    total_observations int4 NOT NULL DEFAULT 0,
    distinctive_channel_count int4 NOT NULL DEFAULT 0,
    attribution_status text NOT NULL DEFAULT 'ACCUMULATING EVIDENCE (0/15)',
    attributed_actor text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS hostname text;
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS alpha_counts float8[] NOT NULL DEFAULT '{5,5,5,5,5,5,5,5,5,5,5,5,5,5}';
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS prior_counts float8[] NOT NULL DEFAULT '{5,5,5,5,5,5,5,5,5,5,5,5,5,5}';
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS total_observations int4 NOT NULL DEFAULT 0;
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS distinctive_channel_count int4 NOT NULL DEFAULT 0;
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS attribution_status text NOT NULL DEFAULT 'ACCUMULATING EVIDENCE (0/15)';
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS attributed_actor text;
ALTER TABLE brahma_program_models ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS brahma_label_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL DEFAULT 'unknown',
    tactic text NOT NULL DEFAULT 'execution',
    label text NOT NULL DEFAULT 'POSITIVE',
    feature_vector jsonb DEFAULT '{}',
    evidence_ids text[] DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE brahma_label_history ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE brahma_label_history ADD COLUMN IF NOT EXISTS tactic text NOT NULL DEFAULT 'execution';
ALTER TABLE brahma_label_history ADD COLUMN IF NOT EXISTS label text NOT NULL DEFAULT 'POSITIVE';
ALTER TABLE brahma_label_history ADD COLUMN IF NOT EXISTS feature_vector jsonb DEFAULT '{}';
ALTER TABLE brahma_label_history ADD COLUMN IF NOT EXISTS evidence_ids text[] DEFAULT '{}';
ALTER TABLE brahma_label_history ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS model_drift_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tactic text NOT NULL,
    observed_rate float8 NOT NULL,
    expected_likelihood float8 NOT NULL,
    discrepancy float8 NOT NULL,
    flagged_for_review bool NOT NULL DEFAULT true,
    evaluated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE model_drift_log ADD COLUMN IF NOT EXISTS tactic text NOT NULL;
ALTER TABLE model_drift_log ADD COLUMN IF NOT EXISTS observed_rate float8 NOT NULL;
ALTER TABLE model_drift_log ADD COLUMN IF NOT EXISTS expected_likelihood float8 NOT NULL;
ALTER TABLE model_drift_log ADD COLUMN IF NOT EXISTS discrepancy float8 NOT NULL;
ALTER TABLE model_drift_log ADD COLUMN IF NOT EXISTS flagged_for_review bool NOT NULL DEFAULT true;
ALTER TABLE model_drift_log ADD COLUMN IF NOT EXISTS evaluated_at timestamptz NOT NULL DEFAULT now();

-- ------------------------------------------------------------------------------
-- 5. DHARMA IMMUTABLE ACTION AUDIT LOG
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dharma_action_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id text UNIQUE NOT NULL,
    hostname text NOT NULL DEFAULT 'unknown',
    action_type text NOT NULL DEFAULT 'PROCESS_ISOLATION',
    tier int4 NOT NULL DEFAULT 1,
    status text NOT NULL DEFAULT 'QUEUED',
    reason text NOT NULL DEFAULT '',
    target_identifier text NOT NULL DEFAULT '',
    operator_id text,
    executed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS action_id text;
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS action_type text NOT NULL DEFAULT 'PROCESS_ISOLATION';
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS tier int4 NOT NULL DEFAULT 1;
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'QUEUED';
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT '';
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS target_identifier text NOT NULL DEFAULT '';
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS operator_id text;
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS executed_at timestamptz;
ALTER TABLE dharma_action_log ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_dharma_action_host_time 
ON dharma_action_log (hostname, created_at DESC);

-- ------------------------------------------------------------------------------
-- 6. KALI NOVEL PATH DISCOVERIES & ESTIMATES
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kali_discoveries (
    discovery_id text PRIMARY KEY,
    technique_sequence text[] NOT NULL DEFAULT '{}',
    tactic_sequence text[] NOT NULL DEFAULT '{}',
    adversary_utility float8 NOT NULL DEFAULT 0.0,
    p_detection float8 NOT NULL DEFAULT 0.5,
    detection_uncalibrated bool NOT NULL DEFAULT false,
    gap_status text NOT NULL DEFAULT 'COVERED',
    hardening_recommendation text NOT NULL DEFAULT '',
    brahma_preference_score float8 NOT NULL DEFAULT 0.5,
    mcts_simulations int4 NOT NULL DEFAULT 500,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS technique_sequence text[] NOT NULL DEFAULT '{}';
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS tactic_sequence text[] NOT NULL DEFAULT '{}';
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS adversary_utility float8 NOT NULL DEFAULT 0.0;
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS p_detection float8 NOT NULL DEFAULT 0.5;
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS detection_uncalibrated bool NOT NULL DEFAULT false;
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS gap_status text NOT NULL DEFAULT 'COVERED';
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS hardening_recommendation text NOT NULL DEFAULT '';
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS brahma_preference_score float8 NOT NULL DEFAULT 0.5;
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS mcts_simulations int4 NOT NULL DEFAULT 500;
ALTER TABLE kali_discoveries ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS kali_technique_estimates (
    technique_id text PRIMARY KEY,
    p_detection float8 NOT NULL DEFAULT 0.5,
    total_simulations int4 NOT NULL DEFAULT 0,
    total_detections int4 NOT NULL DEFAULT 0,
    last_calibrated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE kali_technique_estimates ADD COLUMN IF NOT EXISTS p_detection float8 NOT NULL DEFAULT 0.5;
ALTER TABLE kali_technique_estimates ADD COLUMN IF NOT EXISTS total_simulations int4 NOT NULL DEFAULT 0;
ALTER TABLE kali_technique_estimates ADD COLUMN IF NOT EXISTS total_detections int4 NOT NULL DEFAULT 0;
ALTER TABLE kali_technique_estimates ADD COLUMN IF NOT EXISTS last_calibrated_at timestamptz NOT NULL DEFAULT now();

-- ------------------------------------------------------------------------------
-- 7. SENTINEL CAMPAIGNS, MULTI-HOST CHAINING & CALIBRATION
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS campaigns (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL DEFAULT 'unknown',
    start_at timestamptz NOT NULL DEFAULT now(),
    end_at timestamptz,
    attribution_actor text NOT NULL DEFAULT 'UNATTRIBUTED',
    attribution_status text NOT NULL DEFAULT 'ACCUMULATING EVIDENCE (0/15)',
    peak_ias float8 NOT NULL DEFAULT 0.0,
    fusion_score float8 NOT NULL DEFAULT 0.0,
    technique_sequence text[] DEFAULT '{}',
    dharma_actions_taken text[] DEFAULT '{}',
    analyst_labels text[] DEFAULT '{}',
    hypothesis text,
    next_step_prediction text,
    analyst_verdict text,
    resolution text DEFAULT 'ACTIVE',
    duration_hours float8 DEFAULT 0.0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS start_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS end_at timestamptz;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS attribution_actor text NOT NULL DEFAULT 'UNATTRIBUTED';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS attribution_status text NOT NULL DEFAULT 'ACCUMULATING EVIDENCE (0/15)';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS peak_ias float8 NOT NULL DEFAULT 0.0;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS fusion_score float8 NOT NULL DEFAULT 0.0;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS technique_sequence text[] DEFAULT '{}';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS dharma_actions_taken text[] DEFAULT '{}';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS analyst_labels text[] DEFAULT '{}';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS hypothesis text;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS next_step_prediction text;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS analyst_verdict text;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS resolution text DEFAULT 'ACTIVE';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS duration_hours float8 DEFAULT 0.0;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS multi_host_campaigns (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_a text NOT NULL DEFAULT 'host-a',
    host_b text NOT NULL DEFAULT 'host-b',
    tactic_a text NOT NULL DEFAULT 'execution',
    tactic_b text NOT NULL DEFAULT 'lateral-movement',
    joint_fusion_score float8 NOT NULL DEFAULT 0.0,
    lateral_movement_confirmed bool NOT NULL DEFAULT false,
    campaign_ids uuid[] DEFAULT '{}',
    detected_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS host_a text NOT NULL DEFAULT 'host-a';
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS host_b text NOT NULL DEFAULT 'host-b';
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS tactic_a text NOT NULL DEFAULT 'execution';
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS tactic_b text NOT NULL DEFAULT 'lateral-movement';
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS joint_fusion_score float8 NOT NULL DEFAULT 0.0;
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS lateral_movement_confirmed bool NOT NULL DEFAULT false;
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS campaign_ids uuid[] DEFAULT '{}';
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS detected_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE multi_host_campaigns ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS prediction_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id uuid REFERENCES campaigns(id) ON DELETE SET NULL,
    hostname text NOT NULL DEFAULT 'unknown',
    source_tactic text NOT NULL DEFAULT 'execution',
    predicted_tactic text NOT NULL DEFAULT 'defense-evasion',
    predicted_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    actual_tactic text,
    accurate bool,
    maya_prepositioned bool DEFAULT false,
    axiom_alert_mode bool DEFAULT false
);
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS campaign_id uuid REFERENCES campaigns(id) ON DELETE SET NULL;
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS source_tactic text NOT NULL DEFAULT 'execution';
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS predicted_tactic text NOT NULL DEFAULT 'defense-evasion';
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS predicted_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS resolved_at timestamptz;
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS actual_tactic text;
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS accurate bool;
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS maya_prepositioned bool DEFAULT false;
ALTER TABLE prediction_log ADD COLUMN IF NOT EXISTS axiom_alert_mode bool DEFAULT false;

CREATE TABLE IF NOT EXISTS host_calibration (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL UNIQUE,
    p99_clean_ias float8 NOT NULL DEFAULT 0.75,
    log_threshold float8 NOT NULL DEFAULT 1.5,
    medium_threshold float8 NOT NULL DEFAULT 3.0,
    critical_threshold float8 NOT NULL DEFAULT 6.0,
    sample_count int4 NOT NULL DEFAULT 1000,
    calibrated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE host_calibration ADD COLUMN IF NOT EXISTS p99_clean_ias float8 NOT NULL DEFAULT 0.75;
ALTER TABLE host_calibration ADD COLUMN IF NOT EXISTS log_threshold float8 NOT NULL DEFAULT 1.5;
ALTER TABLE host_calibration ADD COLUMN IF NOT EXISTS medium_threshold float8 NOT NULL DEFAULT 3.0;
ALTER TABLE host_calibration ADD COLUMN IF NOT EXISTS critical_threshold float8 NOT NULL DEFAULT 6.0;
ALTER TABLE host_calibration ADD COLUMN IF NOT EXISTS sample_count int4 NOT NULL DEFAULT 1000;
ALTER TABLE host_calibration ADD COLUMN IF NOT EXISTS calibrated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS calibration_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL DEFAULT 'unknown',
    tp_rate float8 NOT NULL DEFAULT 1.0,
    fp_rate float8 NOT NULL DEFAULT 0.0,
    fn_rate float8 NOT NULL DEFAULT 0.0,
    old_threshold float8 NOT NULL DEFAULT 3.0,
    new_threshold float8 NOT NULL DEFAULT 3.0,
    adjustment_reason text NOT NULL DEFAULT 'Initial calibration',
    evaluated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT 'unknown';
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS tp_rate float8 NOT NULL DEFAULT 1.0;
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS fp_rate float8 NOT NULL DEFAULT 0.0;
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS fn_rate float8 NOT NULL DEFAULT 0.0;
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS old_threshold float8 NOT NULL DEFAULT 3.0;
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS new_threshold float8 NOT NULL DEFAULT 3.0;
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS adjustment_reason text NOT NULL DEFAULT 'Initial calibration';
ALTER TABLE calibration_log ADD COLUMN IF NOT EXISTS evaluated_at timestamptz NOT NULL DEFAULT now();

-- ------------------------------------------------------------------------------
-- 8. COMPREHENSIVE ROW LEVEL SECURITY (RLS) POLICIES
-- ------------------------------------------------------------------------------
ALTER TABLE agent_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_heartbeats ENABLE ROW LEVEL SECURITY;
ALTER TABLE physics_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE almanac_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE eppi_provdag_graphs ENABLE ROW LEVEL SECURITY;
ALTER TABLE brahma_program_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE brahma_label_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_drift_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE dharma_action_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE kali_discoveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE kali_technique_estimates ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE multi_host_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE prediction_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_calibration ENABLE ROW LEVEL SECURITY;
ALTER TABLE calibration_log ENABLE ROW LEVEL SECURITY;

-- Idempotent RLS Access Policies
DO $$
BEGIN
    -- Public Read Policies
    DROP POLICY IF EXISTS "Public Read Agents" ON agent_registry;
    CREATE POLICY "Public Read Agents" ON agent_registry FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Heartbeats" ON agent_heartbeats;
    CREATE POLICY "Public Read Heartbeats" ON agent_heartbeats FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Physics" ON physics_observations;
    CREATE POLICY "Public Read Physics" ON physics_observations FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Baselines" ON almanac_baselines;
    CREATE POLICY "Public Read Baselines" ON almanac_baselines FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read EPPI" ON eppi_provdag_graphs;
    CREATE POLICY "Public Read EPPI" ON eppi_provdag_graphs FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Brahma Models" ON brahma_program_models;
    CREATE POLICY "Public Read Brahma Models" ON brahma_program_models FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Brahma Labels" ON brahma_label_history;
    CREATE POLICY "Public Read Brahma Labels" ON brahma_label_history FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Drift" ON model_drift_log;
    CREATE POLICY "Public Read Drift" ON model_drift_log FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Dharma" ON dharma_action_log;
    CREATE POLICY "Public Read Dharma" ON dharma_action_log FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Kali" ON kali_discoveries;
    CREATE POLICY "Public Read Kali" ON kali_discoveries FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Kali Estimates" ON kali_technique_estimates;
    CREATE POLICY "Public Read Kali Estimates" ON kali_technique_estimates FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Campaigns" ON campaigns;
    CREATE POLICY "Public Read Campaigns" ON campaigns FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read MultiHost" ON multi_host_campaigns;
    CREATE POLICY "Public Read MultiHost" ON multi_host_campaigns FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Prediction" ON prediction_log;
    CREATE POLICY "Public Read Prediction" ON prediction_log FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Host Calibration" ON host_calibration;
    CREATE POLICY "Public Read Host Calibration" ON host_calibration FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public Read Calibration" ON calibration_log;
    CREATE POLICY "Public Read Calibration" ON calibration_log FOR SELECT USING (true);

    -- Service Upsert Policies
    DROP POLICY IF EXISTS "Service Upsert Agents" ON agent_registry;
    CREATE POLICY "Service Upsert Agents" ON agent_registry FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Heartbeats" ON agent_heartbeats;
    CREATE POLICY "Service Upsert Heartbeats" ON agent_heartbeats FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Insert Physics" ON physics_observations;
    CREATE POLICY "Service Insert Physics" ON physics_observations FOR INSERT WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Baselines" ON almanac_baselines;
    CREATE POLICY "Service Upsert Baselines" ON almanac_baselines FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Insert EPPI" ON eppi_provdag_graphs;
    CREATE POLICY "Service Insert EPPI" ON eppi_provdag_graphs FOR INSERT WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Brahma Models" ON brahma_program_models;
    CREATE POLICY "Service Upsert Brahma Models" ON brahma_program_models FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Insert Brahma Labels" ON brahma_label_history;
    CREATE POLICY "Service Insert Brahma Labels" ON brahma_label_history FOR INSERT WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Insert Drift" ON model_drift_log;
    CREATE POLICY "Service Insert Drift" ON model_drift_log FOR INSERT WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Insert Dharma" ON dharma_action_log;
    CREATE POLICY "Service Insert Dharma" ON dharma_action_log FOR INSERT WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Kali" ON kali_discoveries;
    CREATE POLICY "Service Upsert Kali" ON kali_discoveries FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Kali Estimates" ON kali_technique_estimates;
    CREATE POLICY "Service Upsert Kali Estimates" ON kali_technique_estimates FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Campaigns" ON campaigns;
    CREATE POLICY "Service Upsert Campaigns" ON campaigns FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert MultiHost" ON multi_host_campaigns;
    CREATE POLICY "Service Upsert MultiHost" ON multi_host_campaigns FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Prediction" ON prediction_log;
    CREATE POLICY "Service Upsert Prediction" ON prediction_log FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Host Calibration" ON host_calibration;
    CREATE POLICY "Service Upsert Host Calibration" ON host_calibration FOR ALL WITH CHECK (true);

    DROP POLICY IF EXISTS "Service Upsert Calibration" ON calibration_log;
    CREATE POLICY "Service Upsert Calibration" ON calibration_log FOR ALL WITH CHECK (true);
END $$;
