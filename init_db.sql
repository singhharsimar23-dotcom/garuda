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
    rag_attribution JSONB,
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
    api_key TEXT UNIQUE NOT NULL,      -- e.g. hex-encoded 32-byte secret
    allowed_collections TEXT[] DEFAULT ARRAY['*'], -- collection slugs or '*'
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- TAXII Access Audit Log (Usage & Metric Tracking)
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

-- ==============================================================================
-- INDEXES
-- ==============================================================================
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

-- ==============================================================================
-- SEED TAXII COLLECTIONS
-- ==============================================================================
INSERT INTO taxii_collections (slug, title, description, can_read, can_write, media_types)
VALUES 
    ('high-confidence', 'High Confidence IOCs', 'Analyst-verified and high-confidence (>70) threat indicators targeting Indian national cyberspace.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('all-iocs', 'All Detected Threat IOCs', 'Complete feed of all automated & analyst-reviewed indicators detected by GARUDA sensor arrays.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('nic-sector', 'NIC & Government IT Sector', 'Threat intelligence targeting National Informatics Centre, Gov.in, and state portal infrastructure.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('drdo-defence', 'DRDO & Defence Research Sector', 'Targeted espionage and infrastructure spoofing indicators against Indian Defence R&D establishments.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('military-hq', 'Military HQ & Armed Forces Sector', 'Threat indicators targeting Tri-Services headquarters, command networks, and defence personnel.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('generic-government', 'Generic Public Administration Sector', 'Threat intelligence covering municipal, PSU, state secretariat, and civil service digital assets.', true, false, ARRAY['application/stix+json;version=2.1']),
    ('apt36-cluster', 'APT36 / Transparent Tribe Cluster', 'Clustered campaign intelligence tracking APT36 infrastructure patterns and state-sponsored espionage.', true, false, ARRAY['application/stix+json;version=2.1'])
ON CONFLICT (slug) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    can_read = EXCLUDED.can_read,
    can_write = EXCLUDED.can_write,
    media_types = EXCLUDED.media_types;

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE whitelist ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE tension_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxii_collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxii_subscribers ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxii_access_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "audit_insert_only" ON audit_log;
    DROP POLICY IF EXISTS "audit_read" ON audit_log;
    DROP POLICY IF EXISTS "audit_no_update" ON audit_log;
    DROP POLICY IF EXISTS "audit_no_delete" ON audit_log;
    DROP POLICY IF EXISTS "alerts_insert" ON alerts;
    DROP POLICY IF EXISTS "alerts_read_auth" ON alerts;
    DROP POLICY IF EXISTS "alerts_read_stix" ON alerts;
    DROP POLICY IF EXISTS "alerts_update" ON alerts;
    DROP POLICY IF EXISTS "alerts_no_delete" ON alerts;
    DROP POLICY IF EXISTS "whitelist_all" ON whitelist;
    DROP POLICY IF EXISTS "campaigns_all" ON campaigns;
    DROP POLICY IF EXISTS "tension_log_all" ON tension_log;
    DROP POLICY IF EXISTS "taxii_collections_read" ON taxii_collections;
    DROP POLICY IF EXISTS "taxii_collections_write" ON taxii_collections;
    DROP POLICY IF EXISTS "stix_objects_read" ON stix_objects;
    DROP POLICY IF EXISTS "stix_objects_write" ON stix_objects;
    DROP POLICY IF EXISTS "taxii_subscribers_service_only" ON taxii_subscribers;
    DROP POLICY IF EXISTS "taxii_access_log_insert" ON taxii_access_log;
    DROP POLICY IF EXISTS "taxii_access_log_service_read" ON taxii_access_log;
END
$$;

-- audit_log: append-only. No UPDATE or DELETE ever.
CREATE POLICY "audit_insert_only" ON audit_log FOR INSERT WITH CHECK (true);
CREATE POLICY "audit_read" ON audit_log FOR SELECT USING (true);
CREATE POLICY "audit_no_update" ON audit_log AS RESTRICTIVE FOR UPDATE USING (false);
CREATE POLICY "audit_no_delete" ON audit_log AS RESTRICTIVE FOR DELETE USING (false);

-- alerts
CREATE POLICY "alerts_insert" ON alerts FOR INSERT WITH CHECK (true);
CREATE POLICY "alerts_read_auth" ON alerts FOR SELECT USING (true);
CREATE POLICY "alerts_update" ON alerts FOR UPDATE USING (true);
CREATE POLICY "alerts_no_delete" ON alerts AS RESTRICTIVE FOR DELETE USING (false);

-- whitelist, campaigns, tension_log policies
CREATE POLICY "whitelist_all" ON whitelist FOR ALL USING (true);
CREATE POLICY "campaigns_all" ON campaigns FOR ALL USING (true);
CREATE POLICY "tension_log_all" ON tension_log FOR ALL USING (true);

-- TAXII Policies: public/authorized feeds
-- taxii_collections and stix_objects: publicly readable (these are the published TAXII feeds)
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
-- SESSION 3: EASM & CVE CORRELATION TABLES
-- ==============================================================================

-- Monitored ASN / CIDR ranges for Indian defence & critical infrastructure.
-- ZERO seed rows — every row MUST have a source field pointing to a real,
-- verifiable registry record (APNIC/IRINN Whois, government publication, etc.)
-- Never populate this table from model training-data "knowledge".
CREATE TABLE IF NOT EXISTS monitored_asn_ranges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_name    TEXT NOT NULL,          -- 'DRDO', 'HAL', 'BEL', 'NIC', 'ISRO', 'AFCERT', etc.
    cidr        TEXT NOT NULL,          -- e.g. '59.160.0.0/16'
    asn         TEXT,                   -- e.g. 'AS18209'
    source      TEXT NOT NULL,          -- documented provenance — REQUIRED, never guessed
    verified_on DATE NOT NULL,          -- date analyst last confirmed the range is still valid
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Attack surface findings: one row per (ip, service) discovered by Shodan/Censys scan.
-- Updated on every scan; status tracks remediation lifecycle.
CREATE TABLE IF NOT EXISTS easm_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asn_range_id        UUID REFERENCES monitored_asn_ranges(id) ON DELETE SET NULL,
    ip                  INET NOT NULL,
    port                INT,
    service             TEXT,           -- 'rdp', 'citrix-adc', 'fortigate-mgmt', 'ssh', etc.
    product_fingerprint TEXT,           -- raw banner / product string from Shodan/Censys
    scan_source         TEXT NOT NULL DEFAULT 'shodan',   -- 'shodan' | 'censys'
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              TEXT NOT NULL DEFAULT 'open'      -- 'open' | 'patched' | 'false_positive'
);

-- CVE-to-finding correlation: one row per (easm_finding, CVE) pair.
-- kev_date_added and known_ransomware_use come directly from CISA KEV — not derived.
-- severity_computed uses a documented, testable function (see garuda/detection/cpe_match.py).
-- threat_actor_correlation_id is a forward FK to operator_clusters (Session 5 — NULL until then).
CREATE TABLE IF NOT EXISTS cve_kev_matches (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    easm_finding_id             UUID NOT NULL REFERENCES easm_findings(id) ON DELETE CASCADE,
    cve_id                      TEXT NOT NULL,
    kev_date_added              DATE,           -- NULL if CVE not in CISA KEV at match time
    known_ransomware_use        BOOLEAN NOT NULL DEFAULT false,   -- from KEV knownRansomwareUseName field
    threat_actor_correlation_id UUID,           -- FK to operator_clusters.id (Session 5) — NULL for now
    days_since_actor_exploitation INT,          -- computed at insert time; NULL if no actor correlation yet
    severity_computed           TEXT NOT NULL,  -- 'critical' | 'high' | 'medium' | 'low'
    alert_sent                  BOOLEAN NOT NULL DEFAULT false,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (easm_finding_id, cve_id)            -- one match row per (finding, CVE) pair
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_monitored_asn_ranges_org ON monitored_asn_ranges(org_name);
CREATE INDEX IF NOT EXISTS idx_easm_findings_ip ON easm_findings(ip);
CREATE INDEX IF NOT EXISTS idx_easm_findings_status ON easm_findings(status);
CREATE INDEX IF NOT EXISTS idx_easm_findings_range_id ON easm_findings(asn_range_id);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_cve_id ON cve_kev_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_finding ON cve_kev_matches(easm_finding_id);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_ransomware ON cve_kev_matches(known_ransomware_use);
CREATE INDEX IF NOT EXISTS idx_cve_kev_matches_created ON cve_kev_matches(created_at DESC);

-- RLS
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

-- rpz_entries: DNS RPZ triggers for subscriber recursive resolvers.
-- Confidence threshold (>= 80) strictly enforced to avoid breaking legitimate traffic.
-- Soft-deleted via removed_at for auditability.
CREATE TABLE IF NOT EXISTS rpz_entries (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain                TEXT NOT NULL UNIQUE,
    action                TEXT NOT NULL DEFAULT 'nxdomain', -- 'nxdomain' | 'passthru'
    source_stix_object_id TEXT REFERENCES stix_objects(id) ON DELETE SET NULL,
    confidence            INT NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    added_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at            TIMESTAMPTZ                       -- NULL = active, set = soft-deleted
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

-- monitored_defence_ips: Documented Indian defence and government IP addresses/ranges.
-- Zero seed rows — every row MUST have a verified source (APNIC/IRINN registry record).
CREATE TABLE IF NOT EXISTS monitored_defence_ips (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip          INET NOT NULL UNIQUE,
    org_name    TEXT NOT NULL,
    source      TEXT NOT NULL,             -- documented provenance only, NEVER guess
    verified_on DATE NOT NULL,
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- passive_dns_observations: Historical domain-to-IP resolution intersections.
-- Reflects domain-resolution history (infrastructure overlap), NOT workstation queries.
CREATE TABLE IF NOT EXISTS passive_dns_observations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    defence_ip_id       UUID REFERENCES monitored_defence_ips(id) ON DELETE CASCADE,
    queried_domain      TEXT NOT NULL,
    resolved_via        TEXT NOT NULL,       -- 'robtex' | 'virustotal' | 'hackertarget'
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

-- operator_clusters: Strategic adversary operator grouping.
-- Zero seed rows — clusters emerge from accumulated verifiable evidence only.
CREATE TABLE IF NOT EXISTS operator_clusters (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label          TEXT NOT NULL UNIQUE,      -- internal working label e.g. 'cluster-a-nic-mod'
    first_observed DATE NOT NULL,
    notes          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- campaign_infrastructure_fingerprints: Technical signatures of threat infrastructure.
-- cluster_id starts NULL (unclustered) until enough similarity overlap is confirmed.
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

-- cluster_review_queue: Two-step human-in-the-loop attribution review.
-- Candidate matches above threshold are staged here for analyst approval.
CREATE TABLE IF NOT EXISTS cluster_review_queue (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_id       UUID NOT NULL REFERENCES campaign_infrastructure_fingerprints(id) ON DELETE CASCADE,
    suggested_cluster_id UUID NOT NULL REFERENCES operator_clusters(id) ON DELETE CASCADE,
    similarity_score     FLOAT NOT NULL CHECK (similarity_score >= 0.0 AND similarity_score <= 1.0),
    matched_signals      JSONB NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'approved' | 'rejected'
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

-- ==============================================================================
-- SESSION 8: BGP RPKI REST MONITOR
-- ==============================================================================

CREATE TABLE IF NOT EXISTS bgp_watchlist (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix       TEXT NOT NULL UNIQUE,
    expected_asn INT NOT NULL,
    org_label    TEXT,
    active       BOOLEAN NOT NULL DEFAULT true,
    seeded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bgp_incidents (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix       TEXT NOT NULL,
    expected_asn INT,
    observed_asn INT,
    rpki_status  TEXT,
    signal_count INT DEFAULT 1,
    detected_at  TIMESTAMPTZ DEFAULT NOW(),
    resolved_at  TIMESTAMPTZ,
    analyst_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_bgp_incidents_detected ON bgp_incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_bgp_incidents_prefix ON bgp_incidents(prefix);
CREATE INDEX IF NOT EXISTS idx_bgp_watchlist_active ON bgp_watchlist(active);

ALTER TABLE bgp_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_watchlist ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "bgp_incidents_all" ON bgp_incidents;
    DROP POLICY IF EXISTS "bgp_watchlist_all" ON bgp_watchlist;
END
$$;

CREATE POLICY "bgp_incidents_all" ON bgp_incidents FOR ALL USING (true);
CREATE POLICY "bgp_watchlist_all" ON bgp_watchlist FOR ALL USING (true);

-- ==============================================================================
-- SESSION 9: ORB NETWORK TRACKER
-- ==============================================================================

CREATE TABLE IF NOT EXISTS orb_nodes (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip                        TEXT UNIQUE NOT NULL,
    asn                       INT,
    country                   TEXT,
    product                   TEXT,
    firmware_version          TEXT,
    open_ports                INT[],
    known_cves                TEXT[],
    orb_score                 INT DEFAULT 0,
    triggered_signals         TEXT[],
    targeting_indian_defence  BOOLEAN DEFAULT false,
    confidence_label          TEXT,
    anchor_asns_found         INT[],
    first_seen                TIMESTAMPTZ DEFAULT NOW(),
    last_confirmed            TIMESTAMPTZ DEFAULT NOW(),
    analyst_note              TEXT
);

CREATE INDEX IF NOT EXISTS idx_orb_nodes_score ON orb_nodes(orb_score DESC);
CREATE INDEX IF NOT EXISTS idx_orb_nodes_targeting ON orb_nodes(targeting_indian_defence);
CREATE INDEX IF NOT EXISTS idx_orb_nodes_last_confirmed ON orb_nodes(last_confirmed DESC);

ALTER TABLE orb_nodes ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "orb_nodes_all" ON orb_nodes;
END
$$;

CREATE POLICY "orb_nodes_all" ON orb_nodes FOR ALL USING (true);

-- ==============================================================================
-- SESSION 12: PREDICTIVE DOMAIN PRE-REGISTRATION (APT36 HONEYPOT DISRUPTION)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS predictive_domains (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain                  TEXT UNIQUE NOT NULL,
    prediction_score        FLOAT,
    narrative_keywords      TEXT[],
    cluster_context         TEXT,
    predicted_at            TIMESTAMPTZ DEFAULT NOW(),
    status                  TEXT DEFAULT 'candidate',
        -- candidate / registered / abandoned / taken_by_apt / expired
    registered_at           TIMESTAMPTZ,
    registration_cost_usd   FLOAT DEFAULT 4.99,
    analyst_approved_by     TEXT,
    analyst_justification   TEXT,
    first_queried_at        TIMESTAMPTZ,
    fire_count              INT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_predictive_domains_status ON predictive_domains(status);
CREATE INDEX IF NOT EXISTS idx_predictive_domains_score ON predictive_domains(prediction_score DESC);
CREATE INDEX IF NOT EXISTS idx_predictive_domains_registered ON predictive_domains(registered_at DESC);

ALTER TABLE predictive_domains ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "predictive_domains_all" ON predictive_domains;
END
$$;

CREATE POLICY "predictive_domains_all" ON predictive_domains FOR ALL USING (true);

-- ==============================================================================
-- SESSION 10: MALWARE HUNT ENGINE
-- ==============================================================================

CREATE TABLE IF NOT EXISTS compiler_fingerprints (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sample_hash text UNIQUE NOT NULL,
    threat_actor text,
    campaign text,
    compile_timestamp int,
    compile_hour_utc int,
    compile_tz_hypothesis text,
    compile_weekday int,
    linker_major int,
    linker_minor int,
    pdb_path text,
    section_entropy jsonb,
    rich_header_hash text,
    import_hash text,
    source text,
    first_seen timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ssh_key_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint text NOT NULL,
    ip text NOT NULL,
    asn int,
    org text,
    key_type text,
    first_seen timestamptz DEFAULT now(),
    last_seen timestamptz DEFAULT now(),
    UNIQUE(fingerprint, ip)
);

CREATE INDEX IF NOT EXISTS idx_compiler_fingerprints_threat_actor ON compiler_fingerprints(threat_actor);
CREATE INDEX IF NOT EXISTS idx_compiler_fingerprints_import_hash ON compiler_fingerprints(import_hash);
CREATE INDEX IF NOT EXISTS idx_ssh_key_observations_fingerprint ON ssh_key_observations(fingerprint);
CREATE INDEX IF NOT EXISTS idx_ssh_key_observations_ip ON ssh_key_observations(ip);

ALTER TABLE compiler_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_key_observations ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "compiler_fingerprints_all" ON compiler_fingerprints;
    DROP POLICY IF EXISTS "ssh_key_observations_all" ON ssh_key_observations;
END
$$;

CREATE POLICY "compiler_fingerprints_all" ON compiler_fingerprints FOR ALL USING (true);
CREATE POLICY "ssh_key_observations_all" ON ssh_key_observations FOR ALL USING (true);

-- ==============================================================================
-- SESSION 13: ANY.RUN SANDBOX ANALYSIS
-- ==============================================================================

CREATE TABLE IF NOT EXISTS sandbox_analyses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        UUID REFERENCES alerts(id),
    domain          TEXT NOT NULL,
    task_id         TEXT UNIQUE,
    submitted_at    TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    verdict         TEXT,
    c2_domains      TEXT[],
    c2_ips          TEXT[],
    mitre_techniques TEXT[],
    dropped_hashes  TEXT[],
    report_url      TEXT,
    is_boss_linux   BOOLEAN DEFAULT false,
    raw_result_url  TEXT
);

CREATE INDEX IF NOT EXISTS idx_sandbox_analyses_domain ON sandbox_analyses(domain);
CREATE INDEX IF NOT EXISTS idx_sandbox_analyses_task_id ON sandbox_analyses(task_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_analyses_alert_id ON sandbox_analyses(alert_id);

ALTER TABLE sandbox_analyses ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "sandbox_analyses_all" ON sandbox_analyses;
END
$$;

CREATE POLICY "sandbox_analyses_all" ON sandbox_analyses FOR ALL USING (true);

-- ==============================================================================
-- SESSION 14: CANARY DOCUMENT FACTORY
-- ==============================================================================

CREATE TABLE IF NOT EXISTS canary_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token           TEXT UNIQUE NOT NULL,
    token_type      TEXT NOT NULL,
    memo            TEXT,
    document_theme  TEXT,
    sector          TEXT,
    webhook_url     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    fire_count      INT DEFAULT 0,
    last_fired_at   TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS canary_fires (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id            UUID REFERENCES canary_tokens(id),
    fired_at            TIMESTAMPTZ DEFAULT NOW(),
    src_ip              TEXT,
    src_asn             INT,
    src_org             TEXT,
    useragent           TEXT,
    score               INT DEFAULT 0,
    alert_dispatched    BOOLEAN DEFAULT false,
    analyst_note        TEXT
);

CREATE TABLE IF NOT EXISTS persona_nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_type   TEXT NOT NULL,
    value       TEXT NOT NULL,
    confidence  FLOAT,
    source      TEXT,
    metadata    JSONB DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_type, value, source)
);

CREATE INDEX IF NOT EXISTS idx_canary_tokens_token ON canary_tokens(token);
CREATE INDEX IF NOT EXISTS idx_canary_fires_token_id ON canary_fires(token_id);
CREATE INDEX IF NOT EXISTS idx_canary_fires_src_ip ON canary_fires(src_ip);
CREATE INDEX IF NOT EXISTS idx_persona_nodes_value ON persona_nodes(value);

ALTER TABLE canary_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE canary_fires ENABLE ROW LEVEL SECURITY;
ALTER TABLE persona_nodes ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "canary_tokens_all" ON canary_tokens;
    DROP POLICY IF EXISTS "canary_fires_all" ON canary_fires;
    DROP POLICY IF EXISTS "persona_nodes_all" ON persona_nodes;
END
$$;

CREATE POLICY "canary_tokens_all" ON canary_tokens FOR ALL USING (true);
CREATE POLICY "canary_fires_all" ON canary_fires FOR ALL USING (true);
CREATE POLICY "persona_nodes_all" ON persona_nodes FOR ALL USING (true);

-- ==============================================================================
-- SESSION 15: CAMPAIGN LIFECYCLE TRACKER
-- ==============================================================================

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_state text DEFAULT 'active';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_updated_at timestamptz;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_ip text;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS lifecycle_asn int;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS public_disclosure_date date;

CREATE INDEX IF NOT EXISTS idx_alerts_lifecycle_state ON alerts(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_alerts_lifecycle_updated ON alerts(lifecycle_updated_at DESC);
