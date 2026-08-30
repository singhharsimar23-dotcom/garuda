-- Migration 004: BRAHMA Program Models & Kill Chain State
-- Idempotent DDL for Production PostgreSQL

CREATE TABLE IF NOT EXISTS brahma_program_models (
    agent_id TEXT PRIMARY KEY,
    actor_id TEXT DEFAULT 'UNATTRIBUTED',
    kill_chain_tactic TEXT DEFAULT 'UNKNOWN',
    posterior_json JSONB NOT NULL,
    observation_count INT DEFAULT 0,
    entropy_bits REAL DEFAULT 0.0,
    predicted_next_tactic TEXT,
    confidence REAL DEFAULT 0.0,
    convergence_status TEXT DEFAULT 'INSUFFICIENT_DATA',
    grammar_rules_json JSONB,
    last_anomaly_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_brahma_models_actor 
ON brahma_program_models (actor_id);

CREATE INDEX IF NOT EXISTS idx_brahma_models_status 
ON brahma_program_models (convergence_status);

CREATE INDEX IF NOT EXISTS idx_brahma_models_updated 
ON brahma_program_models (updated_at DESC);

CREATE TABLE IF NOT EXISTS brahma_ttp_intel (
    id BIGSERIAL PRIMARY KEY,
    actor_name TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    frequency_weight REAL DEFAULT 1.0,
    source TEXT NOT NULL DEFAULT 'MITRE_ATTACK',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_brahma_ttp_actor 
ON brahma_ttp_intel (actor_name, tactic);
