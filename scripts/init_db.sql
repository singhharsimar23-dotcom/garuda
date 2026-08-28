-- ==============================================================================
-- GARUDA SOVEREIGN CTI PLATFORM - SUPABASE SCHEMA & RLS SPECIFICATION
-- ==============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL,
    score INT NOT NULL CHECK (score >= 0 AND score <= 100),
    signals JSONB DEFAULT '{}'::jsonb,
    registered_at TIMESTAMPTZ,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registrar TEXT,
    hosting_ip TEXT,
    hosting_asn INT,
    sector TEXT,
    cluster_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    analyst_id TEXT,
    analyst_note TEXT,
    yara_rule TEXT,
    screenshot_url TEXT,
    stix_id TEXT,
    llm_narrative TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Campaigns Table
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id TEXT UNIQUE NOT NULL,
    domain_count INT NOT NULL DEFAULT 1,
    registrar TEXT,
    hosting_asn INT,
    sectors TEXT[] DEFAULT '{}',
    estimated_attack_window_days INT,
    confidence TEXT DEFAULT 'medium',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Whitelist Table
CREATE TABLE IF NOT EXISTS whitelist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT UNIQUE NOT NULL,
    reason TEXT,
    analyst_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit Log Table (Append-Only with RLS)
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    analyst_id TEXT,
    justification TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tension Log Table
CREATE TABLE IF NOT EXISTS tension_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tension_index FLOAT NOT NULL CHECK (tension_index >= 0.0 AND tension_index <= 1.0),
    conflict_mode BOOLEAN NOT NULL DEFAULT FALSE,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- TAXII 2.1 & STIX 2.1 ENGINE TABLES
-- ==============================================================================

-- TAXII Collections Table
CREATE TABLE IF NOT EXISTS taxii_collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT UNIQUE NOT NULL,         -- 'high-confidence', 'all-iocs', 'nic-sector', etc.
    title TEXT NOT NULL,
    description TEXT,
    can_read BOOLEAN DEFAULT true,
    can_write BOOLEAN DEFAULT false,   -- read-only feed for external consumers
    media_types TEXT[] DEFAULT ARRAY['application/stix+json;version=2.1']
);

-- STIX Objects Table
CREATE TABLE IF NOT EXISTS stix_objects (
    id TEXT PRIMARY KEY,               -- e.g. 'indicator--<uuid>'
    type TEXT NOT NULL,                -- 'indicator' | 'malware' | 'threat-actor' | 'campaign' | 'report' | 'relationship'
    spec_version TEXT NOT NULL DEFAULT '2.1',
    created TIMESTAMPTZ NOT NULL,
    modified TIMESTAMPTZ NOT NULL,
    collection_id UUID NOT NULL REFERENCES taxii_collections(id) ON DELETE CASCADE,
    confidence INT,                    -- populated via lib/ioc_confidence
    india_context JSONB,               -- custom STIX extension object
    raw JSONB NOT NULL,                -- full STIX object as serialized by stix2 lib
    revoked BOOLEAN DEFAULT false
);

-- TAXII Subscribers (Subscription-gated API-Key Auth)
CREATE TABLE IF NOT EXISTS taxii_subscribers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    allowed_collections TEXT[] DEFAULT ARRAY['*'],
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- TAXII Access Audit Log
CREATE TABLE IF NOT EXISTS taxii_access_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id UUID REFERENCES taxii_subscribers(id) ON DELETE SET NULL,
    collection_id UUID REFERENCES taxii_collections(id) ON DELETE SET NULL,
    endpoint TEXT NOT NULL,
    objects_returned INT DEFAULT 0,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address TEXT,
    user_agent TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_cluster_id ON alerts(cluster_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_cluster_id ON campaigns(cluster_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON whitelist(domain);
CREATE INDEX IF NOT EXISTS idx_audit_log_alert_id ON audit_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_tension_log_computed_at ON tension_log(computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_stix_objects_collection_modified ON stix_objects(collection_id, modified);
CREATE INDEX IF NOT EXISTS idx_stix_objects_type ON stix_objects(type);
CREATE INDEX IF NOT EXISTS idx_taxii_collections_slug ON taxii_collections(slug);
CREATE INDEX IF NOT EXISTS idx_taxii_subscribers_api_key ON taxii_subscribers(api_key);
CREATE INDEX IF NOT EXISTS idx_taxii_access_log_timestamp ON taxii_access_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_taxii_access_log_subscriber ON taxii_access_log(subscriber_id);

-- Seed TAXII Collections
INSERT INTO taxii_collections (slug, title, description, can_read, can_write, media_types)
VALUES 
    ('high-confidence', 'High Confidence IOCs', 'Analyst-verified and high-confidence (>70) threat indicators targeting Indian national cyberspace.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('all-iocs', 'All Detected Threat IOCs', 'Complete feed of all automated & analyst-reviewed indicators detected by GARUDA sensor arrays.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('nic-sector', 'NIC & Government IT Sector', 'Threat intelligence targeting National Informatics Centre, Gov.in, and state portal infrastructure.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('drdo-defence', 'DRDO & Defence Research Sector', 'Targeted espionage and infrastructure spoofing indicators against Indian Defence R&D establishments.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('military-hq', 'Military HQ & Armed Forces Sector', 'Threat indicators targeting Tri-Services headquarters, command networks, and defence personnel.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('generic-government', 'Generic Public Administration Sector', 'Threat intelligence covering municipal, PSU, state secretariat, and civil service digital assets.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('apt36-cluster', 'APT36 / Transparent Tribe Cluster', 'Clustered campaign intelligence tracking APT36 infrastructure patterns and state-sponsored espionage.', true, false, ARRAY['application/stix+json;version=2.1'])
ON CONFLICT (slug) DO NOTHING;

-- ==============================================================================
-- ROW LEVEL SECURITY: TAXII / STIX tables
-- ==============================================================================

ALTER TABLE taxii_collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxii_subscribers ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxii_access_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "taxii_collections_read" ON taxii_collections;
    DROP POLICY IF EXISTS "taxii_collections_write" ON taxii_collections;
    DROP POLICY IF EXISTS "stix_objects_read" ON stix_objects;
    DROP POLICY IF EXISTS "stix_objects_write" ON stix_objects;
    DROP POLICY IF EXISTS "taxii_subscribers_service_only" ON taxii_subscribers;
    DROP POLICY IF EXISTS "taxii_access_log_insert" ON taxii_access_log;
    DROP POLICY IF EXISTS "taxii_access_log_service_read" ON taxii_access_log;
END
$$;

-- taxii_collections and stix_objects: publicly readable (published TAXII feeds)
CREATE POLICY "taxii_collections_read" ON taxii_collections FOR SELECT USING (true);
CREATE POLICY "taxii_collections_write" ON taxii_collections FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "stix_objects_read" ON stix_objects FOR SELECT USING (true);
CREATE POLICY "stix_objects_write" ON stix_objects FOR ALL USING (auth.role() = 'service_role');
-- taxii_subscribers: contains plaintext API keys — NEVER readable by anon role
CREATE POLICY "taxii_subscribers_service_only" ON taxii_subscribers FOR ALL USING (auth.role() = 'service_role');
-- taxii_access_log: backend inserts only; reads restricted to service_role
CREATE POLICY "taxii_access_log_insert" ON taxii_access_log FOR INSERT WITH CHECK (true);
CREATE POLICY "taxii_access_log_service_read" ON taxii_access_log FOR SELECT USING (auth.role() = 'service_role');


-- ==============================================================================

CREATE TABLE IF NOT EXISTS monitored_asn_ranges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_name    TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    asn         TEXT,
    source      TEXT NOT NULL,
    verified_on DATE NOT NULL,
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS easm_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asn_range_id        UUID REFERENCES monitored_asn_ranges(id) ON DELETE SET NULL,
    ip                  INET NOT NULL,
    port                INT,
    service             TEXT,
    product_fingerprint TEXT,
    scan_source         TEXT NOT NULL DEFAULT 'shodan',
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS cve_kev_matches (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    easm_finding_id             UUID NOT NULL REFERENCES easm_findings(id) ON DELETE CASCADE,
    cve_id                      TEXT NOT NULL,
    kev_date_added              DATE,
    known_ransomware_use        BOOLEAN NOT NULL DEFAULT false,
    threat_actor_correlation_id UUID,
    days_since_actor_exploitation INT,
    severity_computed           TEXT NOT NULL,
    alert_sent                  BOOLEAN NOT NULL DEFAULT false,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (easm_finding_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_monitored_asn_ranges_org ON monitored_asn_ranges(org_name);
CREATE INDEX IF NOT EXISTS idx_easm_findings_ip ON easm_findings(ip);
CREATE INDEX IF NOT EXISTS idx_easm_findings_status ON easm_findings(status);
CREATE INDEX IF NOT EXISTS idx_easm_findings_range_id ON easm_findings(asn_range_id);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_cve_id ON cve_kev_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_finding ON cve_kev_matches(easm_finding_id);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_ransomware ON cve_kev_matches(known_ransomware_use);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_created ON cve_kev_matches(created_at DESC);

ALTER TABLE monitored_asn_ranges ENABLE ROW LEVEL SECURITY;
ALTER TABLE easm_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_kev_matches ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "monitored_asn_ranges_all" ON monitored_asn_ranges;
    DROP POLICY IF EXISTS "easm_findings_all" ON easm_findings;
    DROP POLICY IF EXISTS "cve_kev_matches_all" ON cve_kev_matches;
END
$$;

CREATE POLICY "monitored_asn_ranges_all" ON monitored_asn_ranges FOR ALL USING (true);
CREATE POLICY "easm_findings_all" ON easm_findings FOR ALL USING (true);
CREATE POLICY "cve_kev_matches_all" ON cve_kev_matches FOR ALL USING (true);

-- ==============================================================================
-- SESSION 4: RESPONSE POLICY ZONE (RPZ) DNS PROTECTION ENGINE
-- ==============================================================================

CREATE TABLE IF NOT EXISTS rpz_entries (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain                TEXT NOT NULL UNIQUE,
    action                TEXT NOT NULL DEFAULT 'nxdomain',
    source_stix_object_id TEXT REFERENCES stix_objects(id) ON DELETE SET NULL,
    confidence            INT NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    added_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at            TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_rpz_entries_domain ON rpz_entries(domain);
CREATE INDEX IF NOT EXISTS idx_rpz_entries_active ON rpz_entries(removed_at) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_rpz_entries_confidence ON rpz_entries(confidence);

ALTER TABLE rpz_entries ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "rpz_entries_all" ON rpz_entries;
END
$$;

CREATE POLICY "rpz_entries_all" ON rpz_entries FOR ALL USING (true);

-- ==============================================================================
-- SESSION 5: PASSIVE DNS CORRELATION ENGINE
-- ==============================================================================

CREATE TABLE IF NOT EXISTS monitored_defence_ips (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip          INET NOT NULL UNIQUE,
    org_name    TEXT NOT NULL,
    source      TEXT NOT NULL,
    verified_on DATE NOT NULL,
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS passive_dns_observations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    defence_ip_id       UUID REFERENCES monitored_defence_ips(id) ON DELETE CASCADE,
    queried_domain      TEXT NOT NULL,
    resolved_via        TEXT NOT NULL,
    matches_known_c2    BOOLEAN DEFAULT false,
    stix_indicator_id   TEXT REFERENCES stix_objects(id) ON DELETE SET NULL,
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_response        JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_monitored_defence_ips_ip ON monitored_defence_ips(ip);
CREATE INDEX IF NOT EXISTS idx_monitored_defence_ips_org ON monitored_defence_ips(org_name);
CREATE INDEX IF NOT EXISTS idx_pdns_obs_domain ON passive_dns_observations(queried_domain);
CREATE INDEX IF NOT EXISTS idx_pdns_obs_defence_ip ON passive_dns_observations(defence_ip_id);

ALTER TABLE monitored_defence_ips ENABLE ROW LEVEL SECURITY;
ALTER TABLE passive_dns_observations ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "monitored_defence_ips_all" ON monitored_defence_ips;
    DROP POLICY IF EXISTS "passive_dns_observations_all" ON passive_dns_observations;
END
$$;

CREATE POLICY "monitored_defence_ips_all" ON monitored_defence_ips FOR ALL USING (true);
CREATE POLICY "passive_dns_observations_all" ON passive_dns_observations FOR ALL USING (true);

-- ==============================================================================
-- SESSION 6: OPERATOR CLUSTERS & CAMPAIGN FINGERPRINTING ENGINE
-- ==============================================================================

CREATE TABLE IF NOT EXISTS operator_clusters (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label          TEXT NOT NULL UNIQUE,
    first_observed DATE NOT NULL,
    notes          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS campaign_infrastructure_fingerprints (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id                 UUID REFERENCES operator_clusters(id) ON DELETE SET NULL,
    domain                     TEXT NOT NULL UNIQUE,
    registrar                  TEXT,
    registrar_account_pattern  TEXT,
    nameserver_sequence        TEXT[],
    hosting_asn                TEXT,
    cert_issued_at             TIMESTAMPTZ,
    geopolitical_event_ref     UUID,
    lure_theme                 TEXT,
    target_sector              TEXT,
    cves_used                  TEXT[],
    stix_indicator_id          TEXT REFERENCES stix_objects(id) ON DELETE SET NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cluster_review_queue (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_id       UUID NOT NULL REFERENCES campaign_infrastructure_fingerprints(id) ON DELETE CASCADE,
    suggested_cluster_id UUID NOT NULL REFERENCES operator_clusters(id) ON DELETE CASCADE,
    similarity_score     FLOAT NOT NULL CHECK (similarity_score >= 0.0 AND similarity_score <= 1.0),
    matched_signals      JSONB NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending',
    analyst_id           TEXT,
    reviewed_at          TIMESTAMPTZ,
    justification        TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (fingerprint_id, suggested_cluster_id)
);

CREATE INDEX IF NOT EXISTS idx_operator_clusters_label ON operator_clusters(label);
CREATE INDEX IF NOT EXISTS idx_camp_fingerprints_domain ON campaign_infrastructure_fingerprints(domain);
CREATE INDEX IF NOT EXISTS idx_camp_fingerprints_cluster ON campaign_infrastructure_fingerprints(cluster_id);
CREATE INDEX IF NOT EXISTS idx_cluster_review_status ON cluster_review_queue(status);

ALTER TABLE operator_clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_infrastructure_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE cluster_review_queue ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "operator_clusters_all" ON operator_clusters;
    DROP POLICY IF EXISTS "campaign_infrastructure_fingerprints_all" ON campaign_infrastructure_fingerprints;
    DROP POLICY IF EXISTS "cluster_review_queue_all" ON cluster_review_queue;
END
$$;

CREATE POLICY "operator_clusters_all" ON operator_clusters FOR ALL USING (true);
CREATE POLICY "campaign_infrastructure_fingerprints_all" ON campaign_infrastructure_fingerprints FOR ALL USING (true);
CREATE POLICY "cluster_review_queue_all" ON cluster_review_queue FOR ALL USING (true);
