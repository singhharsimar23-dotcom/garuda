-- Migration 002: Physics Observations and Baselines
-- Idempotent DDL for Northflank PostgreSQL

CREATE TABLE IF NOT EXISTS physics_observations (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    rapl_pkg_uw REAL,
    rapl_dram_uw REAL,
    rapl_core_uw REAL,
    instructions BIGINT,
    cache_misses BIGINT,
    cycles BIGINT,
    ipc REAL,
    entropy_avail INT,
    sched_run_ms REAL,
    sched_wait_ms REAL,
    sched_delay_ratio REAL,
    workload_class TEXT DEFAULT 'IDLE',
    ias_score REAL,
    anomaly_level TEXT DEFAULT 'CLEAN',
    baseline_qualified BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (agent_id) REFERENCES monitored_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_physics_obs_agent_time 
ON physics_observations (agent_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_physics_obs_baseline_qual 
ON physics_observations (agent_id, baseline_qualified, observed_at DESC);

CREATE TABLE IF NOT EXISTS almanac_baselines (
    agent_id TEXT NOT NULL,
    workload_class TEXT NOT NULL,
    mu_json JSONB NOT NULL,
    sigma_json JSONB NOT NULL,
    threshold_json JSONB NOT NULL,
    observation_count INT DEFAULT 0,
    trust_established BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, workload_class),
    FOREIGN KEY (agent_id) REFERENCES monitored_agents(agent_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tpm_snapshots (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pcr_json JSONB NOT NULL,
    is_baseline BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (agent_id) REFERENCES monitored_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tpm_snapshots_agent_time 
ON tpm_snapshots (agent_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    agent_id TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ias_score REAL NOT NULL,
    anomaly_level TEXT NOT NULL,
    top_channels JSONB,
    narrative TEXT,
    telegram_sent BOOLEAN DEFAULT FALSE,
    dharma_triggered BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (agent_id) REFERENCES monitored_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_agent_time 
ON anomaly_alerts (agent_id, detected_at DESC);
