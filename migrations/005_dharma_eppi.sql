-- Migration 005: DHARMA Autonomous Response & EPPI Provenance
-- Idempotent DDL for Production PostgreSQL

CREATE TABLE IF NOT EXISTS dharma_action_log (
    id BIGSERIAL PRIMARY KEY,
    action_id TEXT UNIQUE NOT NULL,
    action_type TEXT NOT NULL,
    tier INT NOT NULL,
    target TEXT NOT NULL,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_status_before TEXT DEFAULT 'ONLINE',
    brahma_posterior_before JSONB,
    ias_score_before REAL DEFAULT 0.0,
    rollback_available BOOLEAN DEFAULT TRUE,
    rollback_state JSONB,
    operator_id TEXT,
    approved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dharma_action_time ON dharma_action_log (executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_dharma_action_type ON dharma_action_log (action_type);

-- Trigger function enforcing append-only immutability (blocks UPDATE and DELETE)
CREATE OR REPLACE FUNCTION block_dharma_log_modifications()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'dharma_action_log is append-only. Modification and deletion prohibited.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_dharma_log_immutable ON dharma_action_log;
CREATE TRIGGER trg_dharma_log_immutable
BEFORE UPDATE OR DELETE ON dharma_action_log
FOR EACH ROW EXECUTE FUNCTION block_dharma_log_modifications();

-- EPPI PROVDAG Graphs Table
CREATE TABLE IF NOT EXISTS eppi_provdag_graphs (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    anomaly_alert_id TEXT,
    graph_json JSONB NOT NULL,
    root_entry_pid INT,
    anomalous_nodes_count INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_eppi_provdag_agent ON eppi_provdag_graphs (agent_id, created_at DESC);

-- MAYA Deception Assets Table
CREATE TABLE IF NOT EXISTS maya_deception_assets (
    id BIGSERIAL PRIMARY KEY,
    asset_id TEXT UNIQUE NOT NULL,
    asset_type TEXT NOT NULL,
    canary_path TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    triggered BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_maya_assets_agent ON maya_deception_assets (agent_id);

-- VISHNU Host Quarantine & Subversion State Table
CREATE TABLE IF NOT EXISTS vishnu_host_state (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT UNIQUE NOT NULL,
    state_json JSONB NOT NULL,
    quarantine_status TEXT DEFAULT 'ACTIVE',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
