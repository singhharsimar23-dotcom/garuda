-- Migration 007: Real BRAHMA Program Models Schema
-- Strict Dirichlet-Multinomial Bayesian storage without confidence percentages

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS brahma_program_models (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL UNIQUE,
    actor text NOT NULL DEFAULT 'APT36 (Transparent Tribe)',
    observation_count int4 NOT NULL DEFAULT 0,
    alpha_counts float8[] NOT NULL,
    tactic_names text[] NOT NULL,
    attribution_status text NOT NULL DEFAULT 'ACCUMULATING EVIDENCE (0/15 minimum)',
    evidence_summary jsonb DEFAULT '{}',
    last_updated timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_brahma_models_hostname 
ON brahma_program_models (hostname);

CREATE INDEX IF NOT EXISTS idx_brahma_models_attribution 
ON brahma_program_models (attribution_status);
