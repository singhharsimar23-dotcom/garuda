-- Migration 009: Real KALI Discoveries Schema for Autonomous Novel Path Synthesis (ANPS)
-- Stores real MCTS simulation results over MITRE ATT&CK technique graph

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS kali_discoveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    discovery_id text UNIQUE NOT NULL,
    technique_sequence text[] NOT NULL,
    tactic_sequence text[] NOT NULL,
    adversary_utility float8 NOT NULL,
    p_detection float8 NOT NULL,
    detection_uncalibrated bool NOT NULL DEFAULT false,
    gap_status text NOT NULL,
    hardening_recommendation text NOT NULL,
    brahma_preference_score float8 DEFAULT 1.0,
    mcts_simulations int4 DEFAULT 500,
    generated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kali_discoveries_disc_id 
ON kali_discoveries (discovery_id);

CREATE INDEX IF NOT EXISTS idx_kali_discoveries_gap_status 
ON kali_discoveries (gap_status);

CREATE INDEX IF NOT EXISTS idx_kali_discoveries_utility 
ON kali_discoveries (adversary_utility DESC);
