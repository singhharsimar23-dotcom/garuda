-- ==============================================================================
-- GARUDA SESSIONS 8-15 SUPABASE MIGRATION SCRIPT
-- Copy and paste this entire block directly into your Supabase SQL Editor and click "Run".
-- ==============================================================================

-- 1. TAXII SUBSCRIBERS TABLE
CREATE TABLE IF NOT EXISTS subscribers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_cn TEXT NOT NULL,
    organization TEXT NOT NULL,
    authorized_collections TEXT[] DEFAULT '{}',
    ip_allowlist TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_poll_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(cert_cn)
);
ALTER TABLE subscribers ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN DROP POLICY IF EXISTS "subscribers_all" ON subscribers; END $$;
CREATE POLICY "subscribers_all" ON subscribers FOR ALL USING (true);


-- 2. BGP RPKI REST MONITOR (Session 8)
CREATE TABLE IF NOT EXISTS bgp_watchlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix TEXT NOT NULL UNIQUE,
    expected_asn INT NOT NULL,
    org_label TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    seeded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bgp_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix TEXT NOT NULL,
    expected_asn INT,
    observed_asn INT,
    rpki_status TEXT,
    signal_count INT DEFAULT 1,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    analyst_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_bgp_incidents_detected ON bgp_incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_bgp_incidents_prefix ON bgp_incidents(prefix);
CREATE INDEX IF NOT EXISTS idx_bgp_watchlist_active ON bgp_watchlist(active);

ALTER TABLE bgp_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_watchlist ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN 
    DROP POLICY IF EXISTS "bgp_incidents_all" ON bgp_incidents;
    DROP POLICY IF EXISTS "bgp_watchlist_all" ON bgp_watchlist;
END $$;
CREATE POLICY "bgp_incidents_all" ON bgp_incidents FOR ALL USING (true);
CREATE POLICY "bgp_watchlist_all" ON bgp_watchlist FOR ALL USING (true);


-- 3. ORB NETWORK TRACKER (Session 9)
CREATE TABLE IF NOT EXISTS orb_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip TEXT UNIQUE NOT NULL,
    asn INT,
    country TEXT,
    product TEXT,
    firmware_version TEXT,
    open_ports INT[],
    known_cves TEXT[],
    orb_score INT DEFAULT 0,
    triggered_signals TEXT[],
    targeting_indian_defence BOOLEAN DEFAULT false,
    confidence_label TEXT,
    anchor_asns_found INT[],
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_confirmed TIMESTAMPTZ DEFAULT NOW(),
    analyst_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_orb_nodes_score ON orb_nodes(orb_score DESC);
CREATE INDEX IF NOT EXISTS idx_orb_nodes_targeting ON orb_nodes(targeting_indian_defence);
CREATE INDEX IF NOT EXISTS idx_orb_nodes_last_confirmed ON orb_nodes(last_confirmed DESC);

ALTER TABLE orb_nodes ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN DROP POLICY IF EXISTS "orb_nodes_all" ON orb_nodes; END $$;
CREATE POLICY "orb_nodes_all" ON orb_nodes FOR ALL USING (true);


-- 4. MALWARE HUNT ENGINE (Session 10)
CREATE TABLE IF NOT EXISTS compiler_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sample_hash TEXT UNIQUE NOT NULL,
    threat_actor TEXT,
    campaign TEXT,
    compile_timestamp INT,
    compile_hour_utc INT,
    compile_tz_hypothesis TEXT,
    compile_weekday INT,
    linker_major INT,
    linker_minor INT,
    pdb_path TEXT,
    section_entropy JSONB,
    rich_header_hash TEXT,
    import_hash TEXT,
    source TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ssh_key_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint TEXT NOT NULL,
    ip TEXT NOT NULL,
    asn INT,
    org TEXT,
    key_type TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(fingerprint, ip)
);

CREATE INDEX IF NOT EXISTS idx_compiler_fingerprints_threat_actor ON compiler_fingerprints(threat_actor);
CREATE INDEX IF NOT EXISTS idx_compiler_fingerprints_import_hash ON compiler_fingerprints(import_hash);
CREATE INDEX IF NOT EXISTS idx_ssh_key_observations_fingerprint ON ssh_key_observations(fingerprint);
CREATE INDEX IF NOT EXISTS idx_ssh_key_observations_ip ON ssh_key_observations(ip);

ALTER TABLE compiler_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_key_observations ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN 
    DROP POLICY IF EXISTS "compiler_fingerprints_all" ON compiler_fingerprints;
    DROP POLICY IF EXISTS "ssh_key_observations_all" ON ssh_key_observations;
END $$;
CREATE POLICY "compiler_fingerprints_all" ON compiler_fingerprints FOR ALL USING (true);
CREATE POLICY "ssh_key_observations_all" ON ssh_key_observations FOR ALL USING (true);


-- 5. PREDICTIVE DOMAIN PRE-REGISTRATION (Session 12)
CREATE TABLE IF NOT EXISTS predictive_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT UNIQUE NOT NULL,
    prediction_score FLOAT,
    narrative_keywords TEXT[],
    cluster_context TEXT,
    predicted_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'candidate',
    registered_at TIMESTAMPTZ,
    registration_cost_usd FLOAT DEFAULT 4.99,
    analyst_approved_by TEXT,
    analyst_justification TEXT,
    first_queried_at TIMESTAMPTZ,
    fire_count INT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_predictive_domains_status ON predictive_domains(status);
CREATE INDEX IF NOT EXISTS idx_predictive_domains_score ON predictive_domains(prediction_score DESC);
CREATE INDEX IF NOT EXISTS idx_predictive_domains_registered ON predictive_domains(registered_at DESC);

ALTER TABLE predictive_domains ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN DROP POLICY IF EXISTS "predictive_domains_all" ON predictive_domains; END $$;
CREATE POLICY "predictive_domains_all" ON predictive_domains FOR ALL USING (true);


-- 6. ANY.RUN SANDBOX ANALYSIS (Session 13)
CREATE TABLE IF NOT EXISTS sandbox_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    task_id TEXT UNIQUE,
    submitted_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    verdict TEXT,
    c2_domains TEXT[],
    c2_ips TEXT[],
    mitre_techniques TEXT[],
    dropped_hashes TEXT[],
    report_url TEXT,
    is_boss_linux BOOLEAN DEFAULT false,
    raw_result_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_sandbox_analyses_domain ON sandbox_analyses(domain);
CREATE INDEX IF NOT EXISTS idx_sandbox_analyses_task_id ON sandbox_analyses(task_id);

ALTER TABLE sandbox_analyses ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN DROP POLICY IF EXISTS "sandbox_analyses_all" ON sandbox_analyses; END $$;
CREATE POLICY "sandbox_analyses_all" ON sandbox_analyses FOR ALL USING (true);


-- 7. CANARY DOCUMENT FACTORY (Session 14)
CREATE TABLE IF NOT EXISTS canary_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token TEXT UNIQUE NOT NULL,
    token_type TEXT NOT NULL,
    memo TEXT,
    document_theme TEXT,
    sector TEXT,
    webhook_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    fire_count INT DEFAULT 0,
    last_fired_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS canary_fires (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES canary_tokens(id) ON DELETE CASCADE,
    fired_at TIMESTAMPTZ DEFAULT NOW(),
    src_ip TEXT,
    src_asn INT,
    src_org TEXT,
    useragent TEXT,
    score INT DEFAULT 0,
    alert_dispatched BOOLEAN DEFAULT false,
    analyst_note TEXT
);

CREATE TABLE IF NOT EXISTS persona_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence FLOAT,
    source TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_type, value, source)
);

CREATE INDEX IF NOT EXISTS idx_canary_tokens_token ON canary_tokens(token);
CREATE INDEX IF NOT EXISTS idx_canary_fires_token_id ON canary_fires(token_id);
CREATE INDEX IF NOT EXISTS idx_canary_fires_src_ip ON canary_fires(src_ip);
CREATE INDEX IF NOT EXISTS idx_persona_nodes_value ON persona_nodes(value);

ALTER TABLE canary_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE canary_fires ENABLE ROW LEVEL SECURITY;
ALTER TABLE persona_nodes ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN 
    DROP POLICY IF EXISTS "canary_tokens_all" ON canary_tokens;
    DROP POLICY IF EXISTS "canary_fires_all" ON canary_fires;
    DROP POLICY IF EXISTS "persona_nodes_all" ON persona_nodes;
END $$;
CREATE POLICY "canary_tokens_all" ON canary_tokens FOR ALL USING (true);
CREATE POLICY "canary_fires_all" ON canary_fires FOR ALL USING (true);
CREATE POLICY "persona_nodes_all" ON persona_nodes FOR ALL USING (true);


-- 8. ALERTS TABLE EXTENSIONS (Sessions 11 & 15)
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_state TEXT DEFAULT 'active';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_updated_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_ip TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_asn INT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS public_disclosure_date DATE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rag_attribution JSONB;

CREATE INDEX IF NOT EXISTS idx_alerts_lifecycle_state ON alerts(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_alerts_lifecycle_updated ON alerts(lifecycle_updated_at DESC);
