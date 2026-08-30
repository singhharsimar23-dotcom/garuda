-- Migration 011: SENTINEL Autonomous Agent Brain Schema
-- Tables for Campaign Tracking, Multi-Host Chaining, Predictive Pre-positioning, and Calibration Logs

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Active & Historical Campaigns
CREATE TABLE IF NOT EXISTS campaigns (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL,
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
    resolution text DEFAULT 'ACTIVE', -- ACTIVE, RESOLVED_CLEAN, RESOLVED_CONTAINED, PERSISTENT_CAMPAIGN
    duration_hours float8 DEFAULT 0.0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_campaigns_host ON campaigns (hostname);
CREATE INDEX IF NOT EXISTS idx_campaigns_resolution ON campaigns (resolution);
CREATE INDEX IF NOT EXISTS idx_campaigns_start ON campaigns (start_at DESC);

-- 2. Multi-Host Campaigns (Cross-Host Kill Chain)
CREATE TABLE IF NOT EXISTS multi_host_campaigns (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_a text NOT NULL,
    host_b text NOT NULL,
    tactic_a text NOT NULL,
    tactic_b text NOT NULL,
    joint_fusion_score float8 NOT NULL DEFAULT 0.0,
    lateral_movement_confirmed bool NOT NULL DEFAULT false,
    campaign_ids uuid[] DEFAULT '{}',
    detected_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- 3. Predictive Pre-positioning Log
CREATE TABLE IF NOT EXISTS prediction_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id uuid REFERENCES campaigns(id) ON DELETE SET NULL,
    hostname text NOT NULL,
    source_tactic text NOT NULL,
    predicted_tactic text NOT NULL,
    predicted_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    actual_tactic text,
    accurate bool,
    maya_prepositioned bool DEFAULT false,
    axiom_alert_mode bool DEFAULT false
);

-- 4. Self-Calibration Log
CREATE TABLE IF NOT EXISTS calibration_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL,
    tp_rate float8 NOT NULL,
    fp_rate float8 NOT NULL,
    fn_rate float8 NOT NULL,
    old_threshold float8 NOT NULL,
    new_threshold float8 NOT NULL,
    adjustment_reason text NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now()
);

-- Enable RLS on all new tables
ALTER TABLE IF EXISTS campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS multi_host_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS prediction_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS calibration_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'campaigns' AND policyname = 'Public Read Campaigns') THEN
        CREATE POLICY "Public Read Campaigns" ON campaigns FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'campaigns' AND policyname = 'Service Upsert Campaigns') THEN
        CREATE POLICY "Service Upsert Campaigns" ON campaigns FOR ALL WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'multi_host_campaigns' AND policyname = 'Public Read MultiHost') THEN
        CREATE POLICY "Public Read MultiHost" ON multi_host_campaigns FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'multi_host_campaigns' AND policyname = 'Service Upsert MultiHost') THEN
        CREATE POLICY "Service Upsert MultiHost" ON multi_host_campaigns FOR ALL WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'prediction_log' AND policyname = 'Public Read Prediction') THEN
        CREATE POLICY "Public Read Prediction" ON prediction_log FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'prediction_log' AND policyname = 'Service Upsert Prediction') THEN
        CREATE POLICY "Service Upsert Prediction" ON prediction_log FOR ALL WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'calibration_log' AND policyname = 'Public Read Calibration') THEN
        CREATE POLICY "Public Read Calibration" ON calibration_log FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'calibration_log' AND policyname = 'Service Upsert Calibration') THEN
        CREATE POLICY "Service Upsert Calibration" ON calibration_log FOR ALL WITH CHECK (true);
    END IF;
END $$;
