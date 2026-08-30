-- Migration 008: DHARMA Action Log Table & Immutable Append-Only RLS Policies
-- Enforces immutable append-only audit trail: SELECT & INSERT permitted; UPDATE & DELETE strictly DENIED

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS dharma_action_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id text NOT NULL,
    action_type text NOT NULL, -- DNS_SINKHOLE, PROCESS_ISOLATION, FILE_QUARANTINE, NETWORK_ISOLATION
    tier int NOT NULL,        -- 0, 1, 2, 3
    hostname text NOT NULL,
    target text NOT NULL,     -- PID, domain, filepath, or CIDR
    ias_score_at_trigger float8,
    ioc_evidence jsonb DEFAULT '{}',
    physics_evidence jsonb DEFAULT '{}',
    status text NOT NULL,     -- QUEUED, APPROVED, REJECTED, EXECUTED, FAILED, STALE_PID, ALREADY_APPLIED
    operator_id text,
    approved_at timestamptz,
    executed_at timestamptz,
    execution_detail jsonb DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dharma_action_log_action_id 
ON dharma_action_log (action_id);

CREATE INDEX IF NOT EXISTS idx_dharma_action_log_host_time 
ON dharma_action_log (hostname, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_dharma_action_log_status 
ON dharma_action_log (status);

-- Enable RLS
ALTER TABLE dharma_action_log ENABLE ROW LEVEL SECURITY;

-- 1. Read access
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'dharma_action_log' AND policyname = 'Public Read Dharma Actions'
    ) THEN
        CREATE POLICY "Public Read Dharma Actions" ON dharma_action_log FOR SELECT USING (true);
    END IF;
END $$;

-- 2. Insert access (service_role or authenticated)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'dharma_action_log' AND policyname = 'Service Insert Dharma Actions'
    ) THEN
        CREATE POLICY "Service Insert Dharma Actions" ON dharma_action_log FOR INSERT WITH CHECK (true);
    END IF;
END $$;

-- 3. Strict Denial of UPDATE and DELETE (Immutable Append-Only Audit Trail)
-- By omitting UPDATE and DELETE policies or using false conditions, all mutations to existing rows are rejected.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'dharma_action_log' AND policyname = 'Deny Updates Dharma Actions'
    ) THEN
        CREATE POLICY "Deny Updates Dharma Actions" ON dharma_action_log FOR UPDATE USING (false);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'dharma_action_log' AND policyname = 'Deny Deletes Dharma Actions'
    ) THEN
        CREATE POLICY "Deny Deletes Dharma Actions" ON dharma_action_log FOR DELETE USING (false);
    END IF;
END $$;
