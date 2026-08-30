-- Migration 013: GARUDA-HUNT tables
-- Run in Supabase SQL Editor
-- Session O: Active Intelligence Collection Engine

-- 1. STIX Objects Table (ensure table and all columns exist)
CREATE TABLE IF NOT EXISTS stix_objects (
    id              text PRIMARY KEY,
    type            text NOT NULL DEFAULT 'indicator',
    spec_version    text NOT NULL DEFAULT '2.1',
    created         timestamptz DEFAULT now(),
    modified        timestamptz DEFAULT now(),
    created_at      timestamptz DEFAULT now(),
    name            text,
    pattern         text,
    pattern_type    text DEFAULT 'stix',
    valid_from      timestamptz DEFAULT now(),
    ioc_value       text,
    ioc_type        text,
    malware_family  text,
    source          text,
    confidence      integer DEFAULT 70,
    raw_indicator   jsonb DEFAULT '{}'::jsonb,
    raw             jsonb DEFAULT '{}'::jsonb,
    revoked         boolean DEFAULT false
);

-- Defensively ensure all required columns exist on stix_objects
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS created timestamptz DEFAULT now();
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS modified timestamptz DEFAULT now();
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS ioc_value text;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS ioc_type text;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS malware_family text;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS source text;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS confidence integer DEFAULT 70;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS pattern text;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS pattern_type text DEFAULT 'stix';
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS valid_from timestamptz DEFAULT now();
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS raw_indicator jsonb DEFAULT '{}'::jsonb;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS raw jsonb DEFAULT '{}'::jsonb;
ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS revoked boolean DEFAULT false;

-- stix_objects indexes
CREATE INDEX IF NOT EXISTS idx_stix_ioc_value ON stix_objects(ioc_value);
CREATE INDEX IF NOT EXISTS idx_stix_ioc_type ON stix_objects(ioc_type);
CREATE INDEX IF NOT EXISTS idx_stix_source ON stix_objects(source);
CREATE INDEX IF NOT EXISTS idx_stix_created_at ON stix_objects(created_at DESC);

-- 2. Domain Lifecycle Tracking Table
CREATE TABLE IF NOT EXISTS domain_lifecycle (
    id              uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    domain          text NOT NULL UNIQUE,
    stix_id         text,
    current_stage   text NOT NULL DEFAULT 'CERT_ISSUED',
    cert_logged_at  timestamptz,
    resolved_ip     text,
    http_checked_at timestamptz,
    mx_checked_at   timestamptz,
    last_checked_at timestamptz DEFAULT now(),
    created_at      timestamptz DEFAULT now()
);

ALTER TABLE domain_lifecycle ADD COLUMN IF NOT EXISTS stix_id text;
ALTER TABLE domain_lifecycle ADD COLUMN IF NOT EXISTS current_stage text NOT NULL DEFAULT 'CERT_ISSUED';
ALTER TABLE domain_lifecycle ADD COLUMN IF NOT EXISTS cert_logged_at timestamptz;
ALTER TABLE domain_lifecycle ADD COLUMN IF NOT EXISTS resolved_ip text;
ALTER TABLE domain_lifecycle ADD COLUMN IF NOT EXISTS last_checked_at timestamptz DEFAULT now();
ALTER TABLE domain_lifecycle ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_domain_lifecycle_stage
    ON domain_lifecycle(current_stage, last_checked_at DESC);

-- 3. SITREP Persistence Table (Decouples frontend from UTNE service uptime)
CREATE TABLE IF NOT EXISTS garuda_sitrep (
    id                    uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    sitrep_text           text NOT NULL,
    generated_at          timestamptz DEFAULT now(),
    ct_hit_count          integer DEFAULT 0,
    active_campaign_count integer DEFAULT 0,
    source                text DEFAULT 'SENTINEL'
);

ALTER TABLE garuda_sitrep ADD COLUMN IF NOT EXISTS sitrep_text text;
ALTER TABLE garuda_sitrep ADD COLUMN IF NOT EXISTS generated_at timestamptz DEFAULT now();
ALTER TABLE garuda_sitrep ADD COLUMN IF NOT EXISTS source text DEFAULT 'SENTINEL';
ALTER TABLE garuda_sitrep ADD COLUMN IF NOT EXISTS ct_hit_count integer DEFAULT 0;
ALTER TABLE garuda_sitrep ADD COLUMN IF NOT EXISTS active_campaign_count integer DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_garuda_sitrep_generated
    ON garuda_sitrep(generated_at DESC);

-- 4. Row Level Security (RLS) Policies
ALTER TABLE stix_objects ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "stix_objects_all_service" ON stix_objects;
CREATE POLICY "stix_objects_all_service" ON stix_objects
    FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "stix_objects_anon_select" ON stix_objects;
CREATE POLICY "stix_objects_anon_select" ON stix_objects
    FOR SELECT TO anon USING (true);

ALTER TABLE domain_lifecycle ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "domain_lifecycle_service" ON domain_lifecycle;
CREATE POLICY "domain_lifecycle_service" ON domain_lifecycle
    FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "domain_lifecycle_anon" ON domain_lifecycle;
CREATE POLICY "domain_lifecycle_anon" ON domain_lifecycle
    FOR SELECT TO anon USING (true);

ALTER TABLE garuda_sitrep ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "garuda_sitrep_service" ON garuda_sitrep;
CREATE POLICY "garuda_sitrep_service" ON garuda_sitrep
    FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "garuda_sitrep_anon" ON garuda_sitrep;
CREATE POLICY "garuda_sitrep_anon" ON garuda_sitrep
    FOR SELECT TO anon USING (true);

-- 5. Supabase Realtime publication (safe if already added)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' 
        AND schemaname = 'public' 
        AND tablename = 'garuda_sitrep'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE garuda_sitrep;
    END IF;
END $$;
