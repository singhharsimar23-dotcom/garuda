-- Migration 012: Online Learning, Drift Monitoring & Continuous Calibration Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. BRAHMA Ground Truth Label History
CREATE TABLE IF NOT EXISTS brahma_label_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL,
    tactic text NOT NULL,
    label text NOT NULL, -- POSITIVE, NEGATIVE
    feature_vector jsonb DEFAULT '{}',
    evidence_ids text[] DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_brahma_label_host ON brahma_label_history (hostname, created_at DESC);

-- 2. Model Drift Monitoring Log
CREATE TABLE IF NOT EXISTS model_drift_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tactic text NOT NULL,
    observed_rate float8 NOT NULL,
    expected_likelihood float8 NOT NULL,
    discrepancy float8 NOT NULL,
    flagged_for_review bool NOT NULL DEFAULT true,
    evaluated_at timestamptz NOT NULL DEFAULT now()
);

-- 3. AXIOM-II Online Host Calibration (p99 Empirical Tuning)
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

-- 4. KALI Online Technique Detection Estimates (Beta Prior Updates)
CREATE TABLE IF NOT EXISTS kali_technique_estimates (
    technique_id text PRIMARY KEY,
    p_detection float8 NOT NULL,
    total_simulations int4 NOT NULL DEFAULT 0,
    total_detections int4 NOT NULL DEFAULT 0,
    last_calibrated_at timestamptz NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE IF EXISTS brahma_label_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS model_drift_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS host_calibration ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS kali_technique_estimates ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'brahma_label_history' AND policyname = 'Public Read Brahma Labels') THEN
        CREATE POLICY "Public Read Brahma Labels" ON brahma_label_history FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'brahma_label_history' AND policyname = 'Service Insert Brahma Labels') THEN
        CREATE POLICY "Service Insert Brahma Labels" ON brahma_label_history FOR INSERT WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'model_drift_log' AND policyname = 'Public Read Drift') THEN
        CREATE POLICY "Public Read Drift" ON model_drift_log FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'model_drift_log' AND policyname = 'Service Insert Drift') THEN
        CREATE POLICY "Service Insert Drift" ON model_drift_log FOR INSERT WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'host_calibration' AND policyname = 'Public Read Host Calibration') THEN
        CREATE POLICY "Public Read Host Calibration" ON host_calibration FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'host_calibration' AND policyname = 'Service Upsert Host Calibration') THEN
        CREATE POLICY "Service Upsert Host Calibration" ON host_calibration FOR ALL WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'kali_technique_estimates' AND policyname = 'Public Read Kali Estimates') THEN
        CREATE POLICY "Public Read Kali Estimates" ON kali_technique_estimates FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'kali_technique_estimates' AND policyname = 'Service Upsert Kali Estimates') THEN
        CREATE POLICY "Service Upsert Kali Estimates" ON kali_technique_estimates FOR ALL WITH CHECK (true);
    END IF;
END $$;
