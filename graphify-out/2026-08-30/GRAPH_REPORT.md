# Graph Report - garuda  (2026-08-30)

## Corpus Check
- 366 files · ~153,162 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 3208 nodes · 6081 edges · 213 communities (175 shown, 38 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 148 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `302665de`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- reasoner.py
- lifecycle/tracker.py
- webhook.py
- trigger.py
- taxii.py
- api.js
- easm.py
- clusters.py
- detect_mode
- Intelligence.jsx
- pdns.py
- models.py
- engine.py
- cluster.py
- init_db.sql
- routes/alerts.py
- agent_main_usb.py
- is_own_honeypot
- TestCpeMatchFunction
- bgp.py
- TestCisaKevFetch
- malware_hunt.py
- score_candidate
- devDependencies
- dependencies
- garuda/collector.py
- get_supabase_client
- registrar.py
- scripts/init_db.sql
- garuda/config.py
- intelligence/__init__.py
- hijack_detector.py
- DeceptionLedger
- dashboard.py
- AxiomSettings
- tension_index.py
- ssh_tracker.py
- routers/telemetry.py
- ias_computer.py
- stix_export.py
- get_cached_json
- get_db_pool
- App.jsx
- orb/tracker.py
- ingest_telemetry
- malware_hunt/corpus_builder.py
- test_refactor_kill_list.py
- KillChainTracker
- RAPLReader
- ripe_stat.py
- TestReaderDegradation
- Sidebar.jsx
- predictive.py
- domain_generator.py
- update.py
- axiom/db/__init__.py
- rpz_generator.py
- garuda_analyst.py
- fingerprint_matches_cve
- migration_sessions_8_to_15.sql
- LocalAlmanac
- agent_main.py
- predictive/__init__.py
- test_all_env_integrations.py
- TestRpkiSignals
- .__init__
- cisa_kev.py
- brahma.py
- tier0_executor.py
- extract_compiler_fingerprint
- test_malware_hunt.py
- PerfReader
- TestGarudaAPI
- cloudflare-worker/package.json
- frontend/package.json
- TelemetryBatcher
- TPMReader
- EPPILoader
- get_announced_prefixes
- effectiveness.py
- bayesian_updater.py
- test_e2e_integration.py
- TestCorpusMatching
- ErrorBoundary
- StatusBar.jsx
- trigger_background_collection
- validate_rpz_eligibility
- state_machine.py
- MultiDimensionalLinearPowerWorkloadModel
- ProvenanceProcessor
- EPPILoader
- InfraGraph.jsx
- get_sandbox_analyses
- .get_recent_actions
- .oxlintrc.json
- 3 USB Deployment Modes
- monitored_agents
- React + Vite
- run_migrations.py
- package.json
- certstream_monitor.py
- 003_supabase_additions.sql
- rules/graphify.md
- health_check.py
- Any
- ThreatMap.jsx
- routes/analyst.py
- scrape_ispr_statements
- workflows/graphify.md
- vercel.json
- react
- STIXCompiler
- axiom/__init__.py
- react-hot-toast
- react-router-dom
- zustand
- jsdom
- @testing-library/jest-dom
- @types/react-dom
- garuda/__init__.py
- attribution/__init__.py
- bgp/__init__.py
- easm/__init__.py
- modules/__init__.py
- lifecycle/__init__.py
- malware_hunt/__init__.py
- orb/__init__.py
- APTnotesParser
- api.py
- garuda_agent/__init__.py
- MitreIngester
- OTXPuller
- BudgetLimiter
- utne/__init__.py
- PlanCache
- get_active_rpz_entries
- score_orb_probability
- brahma/services/__init__.py
- pipeline_main.py
- receive_telegram_webhook
- CISAPuller
- MalwareBazaarPuller
- TestMitreIngester
- cleanup.py
- test_bgp.py
- TestOrbSweepIntegration
- TestBrahmaEndpoints
- .test_sensor_intensification_via_supabase
- .test_rollback_state_computed
- OperatorQA
- CloudflareDNS
- Any
- 004_brahma.sql
- TestCandidateTldFilter
- brahma/__init__.py
- data-pipeline/__init__.py
- .get_all_pending_actions
- dharma.py
- rate_limiter.py
- .get_status
- .test_sla_enforcement
- rpz.py
- assemble_score
- ._extract_evidence_iocs
- 005_dharma_eppi.sql
- .send_command
- brahma_grammar_push.py
- get_sitrep
- run_first_boot_setup
- OfflineIASComputer
- Demonstration Timeline (10 Minutes)
- build_ioc_graph
- fetch_boss_samples
- TestAirGappedIAS
- TestRpzApiEndpoints
- upsert_rpz_entry
- test_orb.py
- Technical Abstract
- process_domain
- get_registrar_via_rdap
- AlmanacService
- Any
- Zero-Host-Install Physics-Layer Intrusion Detection for Sovereign & Air-Gapped Networks
- get_all_rpz_entries
- iDEX DISC Portal Submission — Problem Statement
- Sovereign Defense & Enterprise Licensing Schedule
- Sovereign Pre-Attack Cyber Threat Intelligence & Physics-Layer Endpoint Defense
- load_nic_domains
- enrich_threat_indicators
- TestRpzZoneFileSyntax
- RegisterDomainRequest
- GarudaActiveLearner
- fetch_all_agent_posteriors
- _resolve_ip
- MockFuzz
- .delete_plan
- .test_03_tier1_authorization_and_rollback
- .test_04_brahma_bayesian_convergence
- .test_02_critical_anomaly_and_response_cascade
- garuda_usb_agent/__init__.py
- build_image.sh
- partition_setup.sh
- sign.sh

## God Nodes (most connected - your core abstractions)
1. `get_supabase_client()` - 143 edges
2. `react` - 46 edges
3. `get_cached_json()` - 41 edges
4. `set_cached_json()` - 41 edges
5. `process_domain()` - 30 edges
6. `PlanCache` - 22 edges
7. `RollbackManager` - 20 edges
8. `GarudaAgent` - 20 edges
9. `run_collection()` - 20 edges
10. `AxiomSettings` - 19 edges

## Surprising Connections (you probably didn't know these)
- `TestIASComputer` --uses--> `AnomalyLevel`  [INFERRED]
  tests/test_ias_computer.py → axiom-service/axiom/models/telemetry.py
- `TestEndToEndPhase3Pipeline` --uses--> `ChannelObservation`  [INFERRED]
  tests/test_e2e_integration.py → axiom-service/axiom/models/telemetry.py
- `TestIASComputer` --uses--> `AlmanacService`  [INFERRED]
  tests/test_ias_computer.py → axiom-service/axiom/services/almanac_service.py
- `TestBayesianUpdater` --uses--> `BayesianUpdater`  [INFERRED]
  tests/test_bayesian_updater.py → brahma-service/brahma/services/bayesian_updater.py
- `TestEndToEndPhase3Pipeline` --uses--> `BayesianUpdater`  [INFERRED]
  tests/test_e2e_integration.py → brahma-service/brahma/services/bayesian_updater.py

## Import Cycles
- None detected.

## Communities (213 total, 38 thin omitted)

### Community 0 - "reasoner.py"
Cohesion: 0.05
Nodes (58): ingest_all(), ingest_cisa_advisories(), ingest_garuda_confirmed_alerts(), ingest_mitre_attck_apt36(), ingest_otx_pulses(), _main(), _parse_args(), QdrantClient (+50 more)

### Community 1 - "lifecycle/tracker.py"
Cohesion: 0.06
Nodes (49): check_lifecycle(), _detect_cluster_burns(), _detect_parking(), _dispatch_cluster_burn_alert(), _dispatch_transferred_alert(), _fetch_ip_asn(), _fetch_sweep_candidates(), _get_supabase_client() (+41 more)

### Community 2 - "webhook.py"
Cohesion: 0.07
Nodes (36): Exception, canary_webhook_endpoint(), _get_supabase_client(), Any, post, Request, Canary webhook endpoint — thin FastAPI wrapper., Public webhook for canarytokens.org document fires. (+28 more)

### Community 3 - "trigger.py"
Cohesion: 0.07
Nodes (43): _auth_headers(), _dig(), extract_iocs(), _extract_status(), poll_results(), Any, ANY.RUN sandbox API client. VERIFY: Check https://any.run/api-documentation/…, Extract analysis status from response — field names may vary. (+35 more)

### Community 4 - "taxii.py"
Cohesion: 0.08
Nodes (48): delete, create_subscriber(), CreateSubscriberRequest, delete_subscriber(), _extract_api_key(), _get_base_url(), list_access_logs(), list_subscribers() (+40 more)

### Community 5 - "api.js"
Cohesion: 0.13
Nodes (31): AlertTable(), ScoreBreakdown(), SIGNAL_LABELS, StatCard(), apiGet(), apiPost(), confirmAlert(), getAlert() (+23 more)

### Community 6 - "easm.py"
Cohesion: 0.09
Nodes (40): _classify_shodan_service(), export_easm_stix_bundle(), _fetch_monitored_ranges(), _fetch_open_findings(), get_easm_finding_detail(), get_easm_orgs(), _get_supabase_client(), _insert_kev_match() (+32 more)

### Community 7 - "clusters.py"
Cohesion: 0.05
Nodes (65): alias_list_clusters(), alias_list_fingerprints(), alias_list_queue(), assign_attribution_endpoint(), AssignAttributionRequest, create_cluster_endpoint(), CreateClusterRequest, decide_attribution_endpoint() (+57 more)

### Community 8 - "detect_mode"
Cohesion: 0.13
Nodes (17): OperatingMode, patch, Acceptance Tests for USB Agent Mode Detector, Test suite for USB runtime mode detection., When running with reachable cloud endpoint, mode is ALONGSIDE., When cloud endpoint is unreachable or missing, mode defaults to AIRGAPPED., When host OS is not active and running from USB, mode is BOOTABLE., TestModeDetector (+9 more)

### Community 9 - "Intelligence.jsx"
Cohesion: 0.10
Nodes (30): ConfidencePill(), confidenceTier(), CopyField(), ContextMenu(), DataTable(), EmptyState(), ScoreBadge(), SectionHeader() (+22 more)

### Community 10 - "pdns.py"
Cohesion: 0.06
Nodes (42): CorrelateDomainRequest, get_alert_pdns_matches(), list_defence_ips(), list_pdns_observations(), BaseModel, get, post, GARUDA — Passive DNS Correlation & Defence IP Management Endpoints (+34 more)

### Community 11 - "models.py"
Cohesion: 0.16
Nodes (17): AuditLogEntry, CampaignListResponse, CampaignResponse, ConfirmAlertRequest, BaseModel, Request payload for whitelisting a domain., Correlated APT36 attack campaign cluster., List of all active campaign clusters. (+9 more)

### Community 12 - "engine.py"
Cohesion: 0.21
Nodes (16): detect_homoglyph(), normalize_domain(), Normalize domain name using NFKD decomposition, confusable translation, and…, Detect presence of internationalized unicode homoglyphs or lookalike spoofing…, check_hosting_asn(), Query IP geolocation/ASN data and detect if hosting ASN matches APT36 hosting…, GARUDA Detection Engine Package., compute_similarity() (+8 more)

### Community 13 - "cluster.py"
Cohesion: 0.18
Nodes (15): detect_campaigns(), encode_features(), _encode_registrar(), _encode_sector(), _encode_subnet24(), _encode_time_bucket(), estimate_attack_window(), Any (+7 more)

### Community 14 - "init_db.sql"
Cohesion: 0.11
Nodes (28): alerts, audit_log, bgp_incidents, bgp_watchlist, campaign_infrastructure_fingerprints, campaigns, canary_fires, canary_tokens (+20 more)

### Community 15 - "routes/alerts.py"
Cohesion: 0.18
Nodes (17): AlertListResponse, AlertResponse, Paginated collection of threat alerts., Pydantic model representing a single enriched threat alert., _format_alert_dict(), get_alert_detail(), get_alert_graph(), get_alert_yara_rule() (+9 more)

### Community 16 - "agent_main_usb.py"
Cohesion: 0.17
Nodes (12): GARUDA USB Agent Main Orchestrator Coordinates multi-mode physical execution…, Main execution loop for GARUDA USB Agent., USBAgentRunner, CloudSynchronizer, GARUDA USB Cloud Synchronization Engine Syncs offline observations and alerts…, Manages synchronization between local SQLite / alert files and remote AXIOM…, Uploads local alert JSON files to cloud and deletes synced files., load_usb_config() (+4 more)

### Community 17 - "is_own_honeypot"
Cohesion: 0.11
Nodes (22): DataQualityError, Any, ValueError, GARUDA Data Quality & Truth Guards (PART 5) Enforces strict input validation…, Raised when incoming data fails quality or provenance verification., Validate alert before database insertion. Raises DataQualityError if data…, Validate SSH SHA256 fingerprint format. Real format: SHA256:[A-Za-z0-9+/]{43}=…, STIX objects must have a backing alert. No orphaned STIX objects allowed. (+14 more)

### Community 18 - "TestCpeMatchFunction"
Cohesion: 0.10
Nodes (12): _fake_kev_entry(), Pure unit tests for fingerprint_matches_cve() and compute_severity(). No…, Raw FortiGate banner should match a FortiOS KEV entry., Explicit CPE URI should trigger Rule 1 (CPE component match)., Matching must be case-insensitive., Apache httpd banner must NOT match a FortiGate KEV entry., Empty or None fingerprint must always return False., Missing KEV vendor/product fields must return False. (+4 more)

### Community 19 - "bgp.py"
Cohesion: 0.13
Nodes (23): bgp_check(), bgp_incidents(), bgp_seed(), bgp_status(), _get_supabase_client(), Any, get, post (+15 more)

### Community 20 - "TestCisaKevFetch"
Cohesion: 0.22
Nodes (6): Every KEV entry must have the five fields we rely on., Test that fetch_kev_catalog() normalises entries and returns a list., Row count from the async fetch must equal the raw JSON count. This is the spec-…, Fetches the real CISA KEV JSON and validates its structure. Automatically…, KEV has been >1000 entries since 2023 — a lower count signals a broken feed., TestCisaKevFetch

### Community 21 - "malware_hunt.py"
Cohesion: 0.16
Nodes (18): analyze_malware_sample(), _analyze_pe_bytes(), AnalyzeHashRequest, _fetch_vt_file_metadata(), Any, BaseModel, post, Request (+10 more)

### Community 22 - "score_candidate"
Cohesion: 0.13
Nodes (12): filter_available_candidates(), Filter to unregistered domains via DNS NXDOMAIN check (free, no WhoisFreaks)., Score domain for pre-registration priority (0.0–1.0). +0.3 top-3 TLD (.space,…, score_candidate(), patch, GARUDA Session 12 Acceptance Tests — Predictive Domain Pre-Registration Tests…, Score high-confidence .space domains with NIC similarity; penalize random .xyz., DNS NXDOMAIN check filters available vs taken domains. (+4 more)

### Community 23 - "devDependencies"
Cohesion: 0.10
Nodes (21): autoprefixer, devDependencies, autoprefixer, postcss, tailwindcss, @testing-library/react, @types/d3, @types/leaflet (+13 more)

### Community 24 - "dependencies"
Cohesion: 0.10
Nodes (21): chart.js, clsx, d3, dependencies, chart.js, clsx, d3, leaflet (+13 more)

### Community 25 - "garuda/collector.py"
Cohesion: 0.16
Nodes (16): check_and_add_set(), Check if a member exists in a Redis set. If not present, add it. Returns True…, Any, Orchestrate multi-source threat intelligence ingestion and scoring pipeline.…, run_collection(), force_collect(), GARUDA — Real CT Log Ingestion Trigger (PART 2.1) Queries crt.sh Certificate…, fetch_new_certs() (+8 more)

### Community 26 - "get_supabase_client"
Cohesion: 0.04
Nodes (76): Client, get_alert_audit_trail(), get, Retrieve the immutable append-only audit trail entries associated with an alert., AlertBase, AlertCreate, AlertInDB, AuditLogBase (+68 more)

### Community 27 - "registrar.py"
Cohesion: 0.14
Nodes (22): count_predictive_registrations_this_month(), insert_predictive_domain_audit(), Insert or update a predictive domain candidate/registration record., Count domains registered in the current calendar month., Append audit log entry for predictive domain registration., upsert_predictive_domain(), _auth_body(), check_availability_porkbun() (+14 more)

### Community 28 - "scripts/init_db.sql"
Cohesion: 0.16
Nodes (20): alerts, audit_log, campaign_infrastructure_fingerprints, campaigns, cluster_review_queue, compiler_fingerprints, cve_kev_matches, easm_findings (+12 more)

### Community 29 - "garuda/config.py"
Cohesion: 0.11
Nodes (24): Vercel Serverless Function entry point for GARUDA API., create_app(), lifespan(), FastAPI, Application lifespan manager for startup telemetry loading and shutdown hooks., FastAPI Application Factory., fetch_cloudflare_dns_logs(), handle_canary_token_trigger() (+16 more)

### Community 30 - "intelligence/__init__.py"
Cohesion: 0.09
Nodes (27): _dictionary_coverage(), extract_dga_features(), _extract_stem(), _get_model(), _load_resources(), _max_consonant_cluster(), predict_dga(), Load or initialize pre-trained XGBoost DGA classifier. (+19 more)

### Community 31 - "hijack_detector.py"
Cohesion: 0.16
Nodes (19): _dispatch_bgp_alert(), _evaluate_signals(), _get_supabase_client(), _load_watchlist(), main(), BGP hijack detection via RPKI validation + BGP update anomaly signals. RPKI…, Insert incident row into bgp_incidents; returns incident id., Load watchlist from Supabase bgp_watchlist, falling back to in-memory list. (+11 more)

### Community 32 - "DeceptionLedger"
Cohesion: 0.05
Nodes (41): DeceptionLedger, Any, MAYA Deception Ledger Seed-deterministic generation module ensuring consistent…, Manages deterministic deception seeds and asset tracking. Key in Redis:…, Derives a deterministic integer seed from compartment and entity name:…, Persists deception asset metadata to ledger., Retrieves asset from ledger., Increments access count when a canary file or document is opened. (+33 more)

### Community 33 - "dashboard.py"
Cohesion: 0.21
Nodes (20): _build_persona_graph(), get_attribution_graph(), _lifecycle_alerts(), lifecycle_summary(), list_orb_nodes(), list_predictive_domains(), list_sandbox_analyses(), list_ssh_observations() (+12 more)

### Community 34 - "AxiomSettings"
Cohesion: 0.09
Nodes (34): AxiomSettings, Config, get_settings(), AXIOM Service Configuration Module Centralized settings management loaded…, Configuration settings for AXIOM detection service., Retrieve singleton configuration instance., create_app(), lifespan() (+26 more)

### Community 35 - "tension_index.py"
Cohesion: 0.12
Nodes (23): get_api_quotas(), get_collection_activity_history(), get_dashboard_statistics(), get_system_api_limits(), get_system_health_detail(), get, Retrieve detailed operational subsystem health statuses and events., Retrieve real-time SOC dashboard telemetry directly from Supabase database. (+15 more)

### Community 36 - "ssh_tracker.py"
Cohesion: 0.15
Nodes (18): collect_ssh_fingerprints(), detect_ssh_anomalies(), _extract_ssh_fingerprints(), _fetch_shodan_host(), _get_supabase_client(), _load_apt_ssh_keys(), persist_ssh_observations(), Any (+10 more)

### Community 37 - "routers/telemetry.py"
Cohesion: 0.09
Nodes (35): AnomalyAlertRecord, AnomalyEvent, ProvenanceRequest, ProvenanceResponse, BaseModel, Anomaly and Provenance Pydantic Schemas, Event model representing a detected physical anomaly., Database entity representation of an anomaly alert. (+27 more)

### Community 38 - "ias_computer.py"
Cohesion: 0.09
Nodes (24): Almanac Baseline Lifecycle Service Coordinates baseline persistence, memory…, calibrate_thresholds(), compute_gaussian_kl(), compute_ias(), _extract_channel_values(), Any, Instruction/Anomaly Score (IAS) Computer Computes Gaussian Kullback-Leibler…, Updates baseline Gaussian parameters (mu, sigma) via Exponential Moving Average… (+16 more)

### Community 39 - "stix_export.py"
Cohesion: 0.07
Nodes (38): Bundle, get_single_alert_stix(), get_stix_threat_feed(), get, Response, Export all analyst-confirmed IOCs as a standardized STIX 2.1 JSON Bundle.…, Generate and retrieve a dedicated STIX 2.1 Bundle for an individual alert., get_taxii_collections() (+30 more)

### Community 40 - "get_cached_json"
Cohesion: 0.08
Nodes (50): generate_cache_key(), get_cached_json(), get_redis_client(), Any, Retrieve or initialize the Upstash Async Redis client., Generate a cache key using the standard pattern 'garuda:{source}:{query_hash}'., Retrieve cached JSON data by key., Store data in cache as JSON with a specified TTL in seconds (default: 1800). (+42 more)

### Community 41 - "get_db_pool"
Cohesion: 0.12
Nodes (22): get_settings(), BRAHMA Service Configuration Module Centralized configuration management loaded…, Retrieve singleton configuration instance., BRAHMA Database Layer, close_db_pool(), get_db_pool(), init_db_pool(), BRAHMA Database Pool Module Asyncpg connection pool with exponential backoff… (+14 more)

### Community 42 - "App.jsx"
Cohesion: 0.26
Nodes (6): GlobalSearch(), getStixFeed(), runRetrohunt(), supabase, Retrohunt(), StixFeed()

### Community 43 - "orb/tracker.py"
Cohesion: 0.11
Nodes (28): confidence_label_from_score(), get_defence_prefixes_cached(), _product_matches_soho(), Map score to confidence label., Check if InternetDB/Shodan product data matches SOHO keywords., Load and cache Indian defence BGP prefixes for targeting checks., _check_otx_ioc(), _dispatch_orb_alert() (+20 more)

### Community 44 - "ingest_telemetry"
Cohesion: 0.11
Nodes (25): check_tables_exist(), get_almanac_baseline(), get_clean_baseline_observations(), insert_anomaly_alert(), insert_physics_observations_bulk(), insert_tpm_snapshot(), Any, Typed Database Query Layer for AXIOM Service Ensures table existence checks,… (+17 more)

### Community 45 - "malware_hunt/corpus_builder.py"
Cohesion: 0.19
Nodes (18): ArgumentParser, _build_cli(), build_corpus_from_malwarebazaar(), _download_sample_pe(), _fingerprint_row(), _get_supabase_client(), _main(), _match_fields_between() (+10 more)

### Community 46 - "test_refactor_kill_list.py"
Cohesion: 0.15
Nodes (11): Aggregated real-time SOC metrics and threat posture telemetry., StatsResponse, generate_canary_alert_copy(), Generate calibrated alert copy for canary token triggers. CRITICAL ATTRIBUTION…, GARUDA Session 7 Acceptance Tests — Kill-List Refactor & Methodological…, Acceptance Criteria: Quality metrics must be dynamic, computable numbers (e.g.…, Acceptance Criteria: Netflow exfiltration and classified tap modules must NOT…, Acceptance Criteria: Canary token triggers output access timestamp ('campaign… (+3 more)

### Community 47 - "KillChainTracker"
Cohesion: 0.10
Nodes (15): KillChainTracker, Kill Chain Tracker Service Maintains Bayesian posterior over MITRE ATT&CK kill-…, Tracks adversary tactic progression using a discrete probability distribution…, Ensures probabilities sum to exactly 1.0., Computes Shannon entropy in bits: H = -sum(p * log2(p))., Returns the Maximum A Posteriori (MAP) tactic., Predicts the most probable next tactic based on transition graph., Determines actor attribution, convergence status, and confidence. Strictly… (+7 more)

### Community 48 - "RAPLReader"
Cohesion: 0.10
Nodes (16): RAPLReader, RAPL (Running Average Power Limit) Hardware Power Reader Supports Intel RAPL…, Read max_energy_range_uj from sysfs if available, otherwise default to 2^32., Reads energy in μJ and calculates power in μW over the elapsed time interval.…, Read combined CPU package power consumption in μW., Reads hardware energy counters from sysfs and calculates power consumption in…, Read combined DRAM power consumption in μW., Read combined CPU core power consumption in μW. (+8 more)

### Community 49 - "ripe_stat.py"
Cohesion: 0.21
Nodes (15): AnnouncedPrefixEntry, AnnouncedPrefixesData, BgpUpdateAttrs, BgpUpdateEntry, BgpUpdatesData, BgpUpdatesResponse, BaseModel, _rate_limit() (+7 more)

### Community 50 - "TestReaderDegradation"
Cohesion: 0.08
Nodes (17): EntropyReader, Kernel Entropy Pool Reader Reads /proc/sys/kernel/random/entropy_avail to…, Reads the available system entropy bits from Linux sysctl /proc interface., Returns available entropy bits (usually between 0 and 4096). Returns None if…, Local Almanac Storage & Offline Telemetry Buffer Stores offline telemetry…, Linux Kernel Scheduler Statistics Reader Parses /proc/schedstat to measure CPU…, Tracks kernel scheduler run delay, execution time, and timeslices. High run…, Reads /proc/schedstat and computes rates: - run_time_ms_per_sec: CPU running… (+9 more)

### Community 51 - "Sidebar.jsx"
Cohesion: 0.15
Nodes (5): PANELS, RAIL, Sidebar(), getTensionLabel(), TensionGauge()

### Community 52 - "predictive.py"
Cohesion: 0.23
Nodes (12): predictive_analyze(), predictive_register(), Any, post, GARUDA — Predictive Domain Pre-Registration API (Session 12) POST…, Analyst-approved domain registration via Porkbun. REQUIRED: analyst_id and…, Run the full prediction pipeline and return scored domain candidates. Auth:…, _verify_admin_token() (+4 more)

### Community 53 - "domain_generator.py"
Cohesion: 0.21
Nodes (14): _dns_available(), _fallback_candidates(), filter_valid_apt36_tlds(), generate_candidate_domains(), _matches_historical_apt36_pattern(), _normalize_domain(), _parse_llm_domains(), Any (+6 more)

### Community 54 - "update.py"
Cohesion: 0.12
Nodes (22): BrahmaSettings, Config, Runtime configuration for BRAHMA service., post, Grammar Expansion Router Allows explicit triggers for behavioral grammar…, Synthesizes expanded grammar rules for off-pattern adversary execution., trigger_grammar_expansion(), BRAHMA API Routers Package (+14 more)

### Community 55 - "axiom/db/__init__.py"
Cohesion: 0.13
Nodes (16): close_db_pool(), get_db_pool(), init_db_pool(), Asyncpg Database Connection Pool Management Enforces connection pooling (min=2,…, Initializes asyncpg connection pool with exponential backoff retry logic., Returns the active asyncpg connection pool or None., Gracefully terminates all pool connections., health_check() (+8 more)

### Community 56 - "rpz_generator.py"
Cohesion: 0.23
Nodes (12): compute_zone_serial(), generate_active_rpz_zone(), publish_domain_to_rpz(), Any, datetime, GARUDA — Response Policy Zone (RPZ) DNS Defense Engine Generates RFC-conformant…, Compute standard BIND zone serial number in YYYYMMDDNN format. Example:…, Render a list of RPZ entries into a fully conformant BIND 9 Response Policy… (+4 more)

### Community 57 - "garuda_analyst.py"
Cohesion: 0.16
Nodes (13): Acceptance Tests for Offline Air-Gapped IAS Scoring, PDF Reporting, and STIX…, main(), GARUDA Air-Gapped Analyst Workstation CLI Extracts offline physical alerts and…, Executes air-gapped triage pipeline over USB mount., run_analyst_pipeline(), generate_pdf_report(), Any, Air-Gapped PDF Report Generator Produces executive PDF reports using reportlab… (+5 more)

### Community 58 - "fingerprint_matches_cve"
Cohesion: 0.10
Nodes (19): compute_severity(), _extract_cpe_components(), fingerprint_matches_cve(), Any, GARUDA — CPE / Product Fingerprint Matching for EASM × KEV Correlation This…, Compute a severity tier string for a cve_kev_matches row. Priority order: 1.…, Lower-case and split text into alpha-numeric tokens, filtering empties., Parse a CPE URI from fingerprint and return (vendor, product). Returns None if… (+11 more)

### Community 59 - "migration_sessions_8_to_15.sql"
Cohesion: 0.17
Nodes (12): alerts, bgp_incidents, bgp_watchlist, canary_fires, canary_tokens, compiler_fingerprints, orb_nodes, persona_nodes (+4 more)

### Community 60 - "LocalAlmanac"
Cohesion: 0.18
Nodes (9): Connection, LocalAlmanac, Any, Mark a buffered batch as successfully synchronized., Purge synchronized or expired records older than max_age_days., Manages local SQLite database for buffering telemetry during network partitions…, Initialize required SQLite tables., Buffer unsent telemetry batch to SQLite. (+1 more)

### Community 61 - "agent_main.py"
Cohesion: 0.19
Nodes (8): GarudaAgent, main(), Any, GARUDA Host Agent Main Loop & Orchestrator Continuously samples host physical…, Processes server response from AXIOM (e.g. updating poll interval or…, Starts the telemetry collection loop., Main agent orchestration service., Samples all active telemetry channels and returns a unified observation record.

### Community 62 - "predictive/__init__.py"
Cohesion: 0.22
Nodes (11): GARUDA predictive domain pre-registration (Session 12)., extract_target_keywords_from_narrative(), _fetch_gdelt_ispr(), _fetch_ispr_rss(), get_ispr_narrative(), ISPR narrative vocabulary extraction for APT36 domain prediction. Two free…, Fetch ISPR recent article titles and summaries. Primary:…, Map narrative vocabulary to GARUDA TIER_1 patterns APT36 would spoof. Pure… (+3 more)

### Community 63 - "test_all_env_integrations.py"
Cohesion: 0.28
Nodes (12): main(), GARUDA — Comprehensive Environment & API Integration Diagnostic Tests every…, test_cloudflare_api(), test_live_data_ingestion(), test_qdrant(), test_shodan(), test_supabase(), test_telegram_bot() (+4 more)

### Community 64 - "TestRpkiSignals"
Cohesion: 0.19
Nodes (7): patch, unknown' RPKI status → no alert, advisory only., RPKI status drives alert severity correctly., RIPE returns 'valid' + expected ASN → no alert., RIPE returns 'invalid' → HIGH alert dispatched., Invalid RPKI + unexpected ASN → CRITICAL., TestRpkiSignals

### Community 65 - ".__init__"
Cohesion: 0.14
Nodes (11): Register signal handlers for termination and on-demand integrity triggers., AgentConfig, BaseSettings, Config, get_config(), GARUDA Agent Configuration Module Loads configuration from environment…, Agent runtime configuration., Retrieve active configuration instance. (+3 more)

### Community 66 - "cisa_kev.py"
Cohesion: 0.18
Nodes (13): fetch_kev_catalog(), get_kev_entry_by_cve(), KevSyncResult, _normalise_entry(), Any, datetime, GARUDA — CISA Known Exploited Vulnerabilities (KEV) Catalog Source Fetches and…, Fetch the CISA KEV catalog. Returns (entries, was_refreshed). Args:… (+5 more)

### Community 67 - "brahma.py"
Cohesion: 0.15
Nodes (19): AdversaryAssessmentResponse, BrahmaUpdateRequest, BrahmaUpdateResponse, GrammarExpansionRequest, GrammarExpansionResponse, BaseModel, BRAHMA Pydantic Data Models Schemas for adversary modeling, Bayesian kill-chain…, Payload received from AXIOM upon anomaly detection. (+11 more)

### Community 68 - "tier0_executor.py"
Cohesion: 0.20
Nodes (7): DHARMA Action Log Repository Manages append-only execution history for all…, Agent Commander Subsystem Publishes real-time command directives to monitored…, Cloudflare DNS Sinkhole Client Automates DNS redirection of confirmed malicious…, Upstash Redis Plan Cache & State Manager Caches pre-computed containment plans,…, Rollback Manager Subsystem Pre-computes and executes safe rollbacks for all…, DHARMA Tier 0 Autonomous Executor Executes deterministic, low-risk containment…, Acceptance Tests for DHARMA Autonomous Response Engine (Tier 0 & Tier 1)

### Community 69 - "extract_compiler_fingerprint"
Cohesion: 0.32
Nodes (11): _decode_pe_string(), extract_compiler_fingerprint(), _extract_pdb_path(), _import_hash(), Any, Compiler fingerprint extraction from PE binaries. Uses pefile for PE parsing.…, MD5 of sorted DLL:function import strings. Safe for ordinal-only imports., Extract build environment fingerprint from PE binary. Validate MZ header BEFORE… (+3 more)

### Community 70 - "test_malware_hunt.py"
Cohesion: 0.14
Nodes (10): _compile_tz_hypothesis(), Map compile hour (UTC) to weak timezone hypothesis label., _load_fixture(), _mock_pe(), GARUDA Session 10 Acceptance Tests — Malware Hunt Engine Tests cover PE header…, SSH fingerprint collection and anomaly detection., Build a MagicMock pefile.PE instance with required attributes., PE compiler fingerprint extraction tests. (+2 more)

### Community 71 - "PerfReader"
Cohesion: 0.22
Nodes (6): PerfReader, Hardware Performance Counter Reader Uses perf_event_open syscall or `perf stat`…, Execute `perf stat` in CSV mode to retrieve aggregate metrics., Samples hardware performance counters: instructions, cache misses, cycles, IPC., Verify paranoid level, root permissions, and available measurement backends., Samples hardware counters and returns instructions, cache misses, cycles, and…

### Community 72 - "TestGarudaAPI"
Cohesion: 0.04
Nodes (18): HTTPAdapter, TestClient, patch, TestGarudaAPI, TestCanaryWebhookEndpoint, API endpoint acceptance tests for /api/v1/clusters/*., TestClusterApiEndpoints, API endpoint acceptance tests for /api/v1/pdns/*. (+10 more)

### Community 73 - "cloudflare-worker/package.json"
Cohesion: 0.18
Nodes (10): description, devDependencies, wrangler, main, name, scripts, deploy, dev (+2 more)

### Community 74 - "frontend/package.json"
Cohesion: 0.18
Nodes (10): name, private, scripts, build, dev, preview, test, test:watch (+2 more)

### Community 75 - "TelemetryBatcher"
Cohesion: 0.29
Nodes (7): Any, Attempts to synchronize cached offline batches when connectivity is available., Batches telemetry observations and handles resilient transmission to AXIOM…, Appends a reading to the in-memory buffer. If buffer size >= batch_size,…, Dispatches all buffered readings to AXIOM service., Sends a single batch payload to AXIOM endpoint with retry logic. Uses standard…, TelemetryBatcher

### Community 76 - "TPMReader"
Cohesion: 0.20
Nodes (6): Interacts with TPM 2.0 hardware via tpm2_pcrread to measure platform integrity., Executes tpm2_pcrread and returns a mapping of PCR indices to their SHA256 hex…, Parses YAML-like or text output from tpm2_pcrread. Standard format: 0 :…, TPMReader, When tpm2_pcrread is not installed, reader disables gracefully., TPMReader parses standard tpm2_pcrread output.

### Community 77 - "EPPILoader"
Cohesion: 0.07
Nodes (22): EPPILoader, Any, EPPI eBPF Loader & Ring Buffer Poller Selects matching kernel eBPF object,…, Simulates buffer overflow metric tracking for unit testing., Injects mock kernel events for testing., Polls events from the 256KB ring buffer., Manages loading of pre-compiled eBPF kprobes and polling of the 256KB execution…, Determines host kernel major and minor version. (+14 more)

### Community 78 - "get_announced_prefixes"
Cohesion: 0.24
Nodes (9): get_announced_prefixes(), Get all BGP-announced prefixes for an ASN. GET…, get_defence_scan_targets(), get_live_defence_prefixes(), Any, EASM collector — live BGP-announced prefixes for Indian defence ASNs. Replaces…, Fetch live BGP-announced prefixes for each ASN in INDIAN_DEFENCE_ASNS. Returns…, Build scan targets for EASM: live BGP prefixes for defence ASNs. Used by EASM… (+1 more)

### Community 79 - "effectiveness.py"
Cohesion: 0.36
Nodes (8): date, compute_lead_time_metrics(), _parse_date(), _parse_datetime(), Any, datetime, Lifecycle effectiveness metrics — lead time and burn cadence analysis. Computes…, Compute lead-time and burn-cadence metrics from confirmed alerts.…

### Community 80 - "bayesian_updater.py"
Cohesion: 0.14
Nodes (16): get_brahma_model(), insert_ttp_intel_bulk(), Any, Typed Database Queries for BRAHMA Service Manages persistence of adversary…, Bulk inserts TTP threat intelligence records., Retrieves active adversary model for an agent., Upserts adversary state model into PostgreSQL., upsert_brahma_model() (+8 more)

### Community 81 - "test_e2e_integration.py"
Cohesion: 0.08
Nodes (22): ANPSBatchRunner, Any, KALI ANPS (Autonomous Novel Path Synthesis) Batch Runner Generates candidate…, Runs weekly automated red-team candidate path synthesis., Synthesizes candidate attack paths and computes utility + detection metrics.…, evaluate_path_coverage(), KALI Deterministic Coverage Evaluator Calculates estimated detection…, Computes estimated detection probability P(detection) in range [0.0, 1.0].… (+14 more)

### Community 83 - "ErrorBoundary"
Cohesion: 0.22
Nodes (3): App(), ErrorBoundary, queryClient

### Community 84 - "StatusBar.jsx"
Cohesion: 0.24
Nodes (5): SERVICES, StatusBar(), tensionColor(), STATUS_MAP, StatusDot()

### Community 85 - "trigger_background_collection"
Cohesion: 0.29
Nodes (9): Any, BackgroundTasks, get, post, Request, Vercel Cron target. Returns 200 immediately and dispatches collection run to…, Ingest a real-time domain candidate from the Cloudflare Edge Worker., receive_edge_candidate() (+1 more)

### Community 86 - "validate_rpz_eligibility"
Cohesion: 0.19
Nodes (10): is_domain_protected(), Check if a domain is part of protected Indian sovereign or educational…, Verify if a domain meets all quality and safety criteria for RPZ publication.…, validate_rpz_eligibility(), Unit tests for RPZ publication eligibility, threshold gating, and safety., Acceptance Criteria: RPZ publish threshold strictly gated at confidence >= 80.…, Acceptance Criteria: Domains ending in .gov.in, .nic.in, .mil.in, .res.in are…, Allowlist/override passthru actions ARE permitted for legitimate domains to… (+2 more)

### Community 87 - "state_machine.py"
Cohesion: 0.27
Nodes (9): _compute_lead_time(), _determine_state(), GARUDA Lifecycle State Machine (FIX-13) Daily DNS-resolve based lifecycle state…, Resolve domain to IP. Returns None on NXDOMAIN/timeout., Determine lifecycle state from current DNS resolution., Days between GARUDA detection and now (used when domain dies)., Run daily to progress all confirmed/pending alerts through lifecycle states.…, _resolve_domain() (+1 more)

### Community 88 - "MultiDimensionalLinearPowerWorkloadModel"
Cohesion: 0.20
Nodes (6): MultiDimensionalLinearPowerWorkloadModel, ndarray, Multi-Dimensional Linear Power-Workload Model (MDLPWM) Uses Ridge Regression to…, Fits and evaluates linear ridge regression models relating IPC, cache misses,…, Fit Ridge regression model: y ~ X. X columns: [1 (bias), IPC, CacheMissRate,…, Predicts expected package power in uW.

### Community 89 - "ProvenanceProcessor"
Cohesion: 0.09
Nodes (14): ProvenanceProcessor, Any, PROVDAG Execution Provenance & Physical Fusion Processor Builds execution…, Identifies the root entry point process by walking DAG ancestors from anomalous…, Processes kernel provenance events and fuses them with microarchitectural RAPL…, Adds EPPI kernel events to the provenance DAG. Handles FORK, EXEC, CONNECT, and…, Tags each PROVDAG process node with RAPL power observations within a ±500ms…, Acceptance Tests for EPPI PROVDAG & Physical Power Fusion (+6 more)

### Community 90 - "EPPILoader"
Cohesion: 0.18
Nodes (7): EPPILoader, Any, EPPI (Execution Provenance and Physical Invariants) eBPF Loader Applies kernel…, Manages loading of pre-compiled eBPF CO-RE bytecode for process execution…, Gates eBPF execution based on Linux kernel release version. Requires >= 5.4 for…, Polls events from the eBPF perf buffer / ring buffer. Returns a list of parsed…, Kernels older than 5.4 must disable EPPI kprobes.

### Community 91 - "InfraGraph.jsx"
Cohesion: 0.22
Nodes (4): InfraGraph(), InfraGraphErrorBoundary, LEGEND_ITEMS, NODE_COLORS

### Community 92 - "get_sandbox_analyses"
Cohesion: 0.25
Nodes (9): get_compiler_fingerprints(), get_sandbox_analyses(), get_sandbox_results(), get_ssh_key_reuse(), get, Fetch recent sandbox results for tracked APT samples from MalwareBazaar & local…, Fetch grouped SSH key observations showing cross-infrastructure reuse., Fetch dynamic sandbox execution reports. (+1 more)

### Community 93 - ".get_recent_actions"
Cohesion: 0.33
Nodes (3): Any, Inserts an immutable execution record into dharma_action_log., Retrieves recent action logs.

### Community 94 - ".oxlintrc.json"
Cohesion: 0.25
Nodes (7): plugins, rules, react/only-export-components, react/rules-of-hooks, $schema, oxc, warn

### Community 95 - "3 USB Deployment Modes"
Cohesion: 0.29
Nodes (6): 3 USB Deployment Modes, GARUDA Host Telemetry Agent (`garuda-agent`), Mode 1: Dropped Daemon Service (Standard Networked Endpoint), Mode 2: Standalone USB Live Triage (Incident Response Forensics), Mode 3: Air-Gapped Offline Collector (Classified / Non-Networked SCADA), Monitored Channels

### Community 96 - "monitored_agents"
Cohesion: 0.43
Nodes (5): monitored_agents, almanac_baselines, anomaly_alerts, physics_observations, tpm_snapshots

### Community 97 - "React + Vite"
Cohesion: 0.50
Nodes (3): Expanding the Oxlint configuration, React Compiler, React + Vite

### Community 98 - "run_migrations.py"
Cohesion: 0.50
Nodes (3): Idempotent Migration Runner for GARUDA Northflank & Supabase PostgreSQL…, Executes all .sql files in migrations directory against the target database., run_migrations()

### Community 99 - "package.json"
Cohesion: 0.33
Nodes (5): name, private, scripts, build, version

### Community 100 - "certstream_monitor.py"
Cohesion: 0.47
Nodes (4): callback(), dispatch_domain(), domain_matches(), GARUDA CertStream CT Log Monitor Runs for ~5 minutes in GitHub Actions, filters…

### Community 103 - "health_check.py"
Cohesion: 0.32
Nodes (7): check_service(), Daily Health Check & Alerting Script (Cron Job 2) Probes all 3 microservices…, Pings a service health endpoint., Dispatches Telegram alert to operator chat., Runs health check over all 3 services., run_health_check(), send_telegram_alert()

### Community 104 - "Any"
Cohesion: 0.33
Nodes (3): Any, Pre-computes deterministic rollback state for an action before execution., Executes pre-computed rollback instructions.

### Community 105 - "ThreatMap.jsx"
Cohesion: 0.60
Nodes (4): getAttackerGeo(), getTargetHubId(), STRATEGIC_HUBS, ThreatMap()

### Community 106 - "routes/analyst.py"
Cohesion: 0.06
Nodes (50): ConfirmAlertResponse, Request payload for analyst alert rejection / false positive triage., Response payload returned upon analyst confirmation., RejectAlertRequest, add_whitelist_domain(), confirm_threat_alert(), Any, BackgroundTasks (+42 more)

### Community 107 - "scrape_ispr_statements"
Cohesion: 0.40
Nodes (4): Any, ISPR (Inter-Services Public Relations) Press Releases Scraper. Collects public…, Scrape recent public defense press releases., scrape_ispr_statements()

### Community 109 - "vercel.json"
Cohesion: 0.50
Nodes (3): buildCommand, crons, rewrites

### Community 110 - "react"
Cohesion: 0.12
Nodes (15): SOURCE_LABELS, EmptyState(), AuthorizationQueue(), INITIAL_PENDING_ACTIONS, KaliInsights(), MOCK_KALI_DISCOVERIES, INITIAL_AGENTS, PhysicsMonitor() (+7 more)

### Community 111 - "STIXCompiler"
Cohesion: 0.18
Nodes (11): _get_utc_now_iso(), main(), Any, STIX 2.1 Threat Intelligence Compiler Converts ingested ATT&CK TTPs, APTnotes…, Aggregates multi-source feeds into a single unified list of STIX 2.1 objects., Inserts compiled STIX objects into Supabase stix_objects table., Compiles raw multi-source intelligence into standardized STIX 2.1 JSON bundles., Creates a STIX 2.1 threat-actor object. (+3 more)

### Community 134 - "APTnotesParser"
Cohesion: 0.15
Nodes (10): APTnotesParser, main(), Any, APTnotes Threat Report Parser Clones the APTnotes repository, filters for APT36…, Parses all filtered reports and extracts aggregated indicators., Parses and extracts threat intelligence from APTnotes PDF repository., Shallow clones the APTnotes data repository if not present., Finds PDF reports matching APT36, Transparent Tribe, SideCopy, or C-Major. (+2 more)

### Community 135 - "api.py"
Cohesion: 0.17
Nodes (14): create_stix_package(), BaseModel, post, query_sitrep(), QueryRequest, UTNE Service API (Koyeb Deployment) FastAPI application serving real-time…, Answers operator natural language questions., Compiles CERT-In STIX 2.1 attribution package. (+6 more)

### Community 138 - "MitreIngester"
Cohesion: 0.21
Nodes (9): main(), MitreIngester, Any, MITRE ATT&CK Ingestion Module Downloads official Enterprise ATT&CK JSON bundle…, Resolves all attack-pattern techniques linked to the group via 'uses'…, Convenience runner extracting all APT36 (Transparent Tribe) & SideCopy…, Ingests and parses MITRE ATT&CK STIX bundle without hardcoded STIX identifiers., Loads the Enterprise ATT&CK bundle from cache, remote URL, or offline fallback… (+1 more)

### Community 139 - "OTXPuller"
Cohesion: 0.20
Nodes (9): main(), OTXPuller, Any, AlienVault OTX Threat Intelligence Puller Queries AlienVault OTX REST API for…, Pulls pulses and indicators for APT36 and SideCopy., Fetches threat intelligence pulses and IOCs from AlienVault OTX., Executes HTTP GET request against OTX with rate limiting and retry handling., Searches pulses matching actor query. (+1 more)

### Community 140 - "BudgetLimiter"
Cohesion: 0.16
Nodes (10): Synthesizes CTI sitreps and threat narratives with Anti-Hallucination Charter…, UTNESynthesizer, BudgetLimiter, Tracks and enforces API quotas using Upstash Redis or local memory counter., Test suite for UTNE executive sitreps, Rule 8 honesty, and rate limiting., Rule 8 Honesty: When observations < 15, sitrep must output 'ATTRIBUTION…, Every anomalous claim in the sitrep must cite an evidence node (e.g. NODE-…, When daily budget is reached (24/day for sitreps), rate limiter returns… (+2 more)

### Community 141 - "utne/__init__.py"
Cohesion: 0.22
Nodes (6): UTNE (Unified Threat Narrative Engine) Package, Any, UTNE Sitrep Evidence Aggregator Gathers telemetry, BRAHMA assessments, DHARMA…, Assembles evidence from distributed microservices and databases., Compiles live evidence bundle from active data sources., SitrepBuilder

### Community 142 - "PlanCache"
Cohesion: 0.18
Nodes (22): authorize_action(), handle_critical_anomaly_trigger(), Processes operator approval or rejection for a Tier 1 action., Executes automated Tier 0 actions (Intensification + Canary + Sinkhole) and…, ActionLogRepository, Appends action records to PostgreSQL dharma_action_log table., AgentCommander, Dispatches containment and configuration commands to monitored agents. (+14 more)

### Community 143 - "get_active_rpz_entries"
Cohesion: 0.18
Nodes (12): Request, Scheduled RPZ synchronization and lifecycle maintenance cron (runs every 15…, Verify standard Bearer <CRON_SECRET> header., Serve the active GARUDA Response Policy Zone (RPZ) flat zone file. Subscribing…, run_rpz_sync_and_expiry(), serve_rpz_zone(), _verify_cron_secret(), expire_stale_rpz_entries() (+4 more)

### Community 144 - "score_orb_probability"
Cohesion: 0.23
Nodes (7): _ip_in_defence_prefixes(), _ports_include_orb_suspect(), ORB signal scoring — probability-based, not definitive attribution. What we CAN…, Score probability that an IP is an ORB relay node. Returns (score,…, score_orb_probability(), Pure unit tests for score_orb_probability — fully offline., TestOrbSignals

### Community 145 - "brahma/services/__init__.py"
Cohesion: 0.21
Nodes (7): BRAHMA Services Package, IntelLoader, Threat Intelligence Loader Loads and indexes APT36 and SideCopy TTP data from…, Manages active threat intelligence indices for adversary attribution…, load_maml_priors(), MAML & Empirical Prior Initializer Initializes adversary tactic priors using…, Loads MAML trained prior weights from pickle artifact or falls back to…

### Community 146 - "pipeline_main.py"
Cohesion: 0.20
Nodes (8): BrahmaUploader, Any, BRAHMA Threat Intel Uploader Module Transmits compiled MITRE ATT&CK TTP…, Uploads compiled threat intelligence priors to BRAHMA Service 2., Sends HTTP POST to BRAHMA /api/v1/brahma/update-intel endpoint., GARUDA Threat Intelligence Pipeline Orchestrator Entry point for GitHub Actions…, Executes the complete multi-source threat intelligence ingestion pipeline., run_pipeline()

### Community 147 - "receive_telegram_webhook"
Cohesion: 0.33
Nodes (6): Any, BackgroundTasks, post, Request, Handle incoming Telegram Bot webhook updates. Responds with HTTP 200 OK…, receive_telegram_webhook()

### Community 148 - "CISAPuller"
Cohesion: 0.24
Nodes (7): CISAPuller, main(), Any, CISA Known Exploited Vulnerabilities (KEV) Ingestion Module Fetches and parses…, Ingests and filters CISA Known Exploited Vulnerabilities catalog., Retrieves the KEV catalog from CISA official endpoint or fallback fixture., Filters KEV catalog for target CVEs or weaponized document formats (WinRAR,…

### Community 149 - "MalwareBazaarPuller"
Cohesion: 0.24
Nodes (7): main(), MalwareBazaarPuller, Any, MalwareBazaar APT36 & SideCopy Sample Ingestion Module Queries abuse.ch…, Fetches malware sample telemetry and SHA256 hashes from MalwareBazaar., Executes form-encoded POST query to MalwareBazaar., Pulls samples for APT36 and SideCopy signatures.

### Community 150 - "TestMitreIngester"
Cohesion: 0.18
Nodes (6): Acceptance Tests for MITRE ATT&CK Ingestion, Test suite for dynamic MITRE ATT&CK alias resolution and technique extraction., ATT&CK bundle must resolve APT36 group via 'Transparent Tribe' alias without…, Techniques are extracted dynamically from STIX 'uses' relationships., mitre_ingester.py source code must not contain hardcoded STIX UUIDs., TestMitreIngester

### Community 151 - "cleanup.py"
Cohesion: 0.50
Nodes (3): Database Retention & Vacuum Cleanup Maintenance Script (Cron Job 1) Prunes…, Executes retention cleanup on PostgreSQL., run_cleanup()

### Community 152 - "test_bgp.py"
Cohesion: 0.17
Nodes (10): AnnouncedPrefixesResponse, RpkiValidationResponse, _load_fixture(), GARUDA Session 8 Acceptance Tests — BGP RPKI REST Monitor Tests cover RPKI…, RULE 4: API down / rate-limited / garbage response., No websockets package or ris-live WebSocket endpoint in Python source., Mock RIPE response → correct CIDR list returned., TestAnnouncedPrefixesParsing (+2 more)

### Community 153 - "TestOrbSweepIntegration"
Cohesion: 0.24
Nodes (6): patch, Integration tests with mocked external APIs., Score=65 → upsert to orb_nodes, no alert., Score=85 AND targeting_indian_defence → alert dispatched., No information available' → skip, no crash., TestOrbSweepIntegration

### Community 154 - "TestBrahmaEndpoints"
Cohesion: 0.22
Nodes (5): Test suite for BRAHMA FastAPI endpoints., POST /api/v1/brahma/update must reject requests without valid X-Inter-Service-…, GET /api/v1/brahma/assessment/{agent_id} on a fresh agent returns…, Valid authenticated update successfully processes event and returns prediction., TestBrahmaEndpoints

### Community 157 - "OperatorQA"
Cohesion: 0.25
Nodes (5): OperatorQA, Any, UTNE Operator Q&A Interface Provides natural language querying over active CTI…, Answers operator intelligence questions grounded strictly in local evidence., Processes operator question. Enforces 500-char input limit and rate-limiting.

### Community 158 - "CloudflareDNS"
Cohesion: 0.22
Nodes (6): CloudflareDNS, Any, Interacts with Cloudflare API to sinkhole verified C2 domains. Strictly gated:…, Gating check: verifies that the domain is explicitly tagged as a MALICIOUS C2…, Points target domain to 127.0.0.1 in Cloudflare DNS., DNS sinkhole must reject unverified domains not present in threat intel.

### Community 159 - "Any"
Cohesion: 0.29
Nodes (4): Any, Checks for expired or unanswered Tier 1 actions and triggers escalation., Queues a process isolation action awaiting operator authorization., Processes operator approval or rejection for a pending Tier 1 action.

### Community 164 - ".get_all_pending_actions"
Cohesion: 0.29
Nodes (4): Any, Sets a key-value record with TTL., Retrieves a cached plan if not expired., Lists all active non-expired pending actions.

### Community 165 - "dharma.py"
Cohesion: 0.19
Nodes (12): AuthorizeActionRequest, CriticalAnomalyTriggerRequest, get_pending_actions(), BaseModel, get, post, DHARMA Autonomous Containment & Authorization Router Exposes endpoints for…, Returns all active Tier 1 actions awaiting operator authorization. (+4 more)

### Community 166 - "rate_limiter.py"
Cohesion: 0.40
Nodes (3): UTNE AI Synthesizer & Narrative Engine Generates honest, verifiable executive…, Groq & Gemini Rate Limiter & Budget Tracker Tracks daily and hourly…, Acceptance Tests for UTNE Narrative Engine & Honesty Constraints

### Community 167 - ".get_status"
Cohesion: 0.33
Nodes (4): _get_current_day(), Any, Checks if the request is within daily budget. Returns: (is_allowed,…, Returns current daily usage summary.

### Community 169 - "rpz.py"
Cohesion: 0.24
Nodes (11): publish_rpz_rule(), PublishRPZRequest, BaseModel, post, GARUDA — Response Policy Zone (RPZ) DNS Feed API Serves RFC-conformant BIND…, Publish a threat domain to the sovereign RPZ feed. Enforces minimum confidence…, Analyst-initiated removal of RPZ entry with mandatory justification., remove_rpz_entry_by_id() (+3 more)

### Community 170 - "assemble_score"
Cohesion: 0.17
Nodes (7): check_registrar_fingerprint(), Evaluate registrar against known APT36 / Transparent Tribe infrastructure…, assemble_score(), Any, Assemble multi-vector threat intelligence signals into a normalized composite…, patch, TestGarudaDetection

### Community 171 - "._extract_evidence_iocs"
Cohesion: 0.40
Nodes (3): Any, Extracts all legitimate known IOCs present in the evidence bundle., Generates an hourly executive SITREP based strictly on the provided evidence…

### Community 172 - "005_dharma_eppi.sql"
Cohesion: 0.33
Nodes (6): block_dharma_log_modifications(), dharma_action_log, eppi_provdag_graphs, maya_deception_assets, trg_dharma_log_immutable, vishnu_host_state

### Community 175 - "brahma_grammar_push.py"
Cohesion: 0.50
Nodes (3): push_candidate_rules_to_brahma(), KALI BRAHMA Grammar Push Module Pushes newly discovered candidate attack…, Transmits candidate grammar rules to BRAHMA.

### Community 176 - "get_sitrep"
Cohesion: 0.50
Nodes (4): get_sitrep(), health(), get, Generates live operational situation report.

### Community 177 - "run_first_boot_setup"
Cohesion: 0.23
Nodes (10): Starts 1Hz sampling loop., generate_agent_id(), initialize_luks_storage(), GARUDA USB Agent First-Boot Setup Script Executes cryptographic signature…, Executes first-boot sequence., Verifies GPG Ed25519 signature of the read-only squashfs root., Generates deterministic agent identifier: sha256(hostname +…, Initializes local data directories and SQLite database. (+2 more)

### Community 178 - "OfflineIASComputer"
Cohesion: 0.21
Nodes (8): compute_gaussian_kl(), OfflineIASComputer, Any, Offline IAS Computer for Air-Gapped Operation Executes deterministic Gaussian…, Saves alert JSON to event_queue directory for air-gapped analyst collection., Computes Gaussian KL divergence D_KL(N(mu1, sigma1^2) || N(mu2, sigma2^2))., Computes IAS scores offline against SQLite baseline without cloud connectivity., Evaluates physical observation. If observation_count < 1000: strictly enforces…

### Community 179 - "Demonstration Timeline (10 Minutes)"
Cohesion: 0.18
Nodes (10): Demonstration Timeline (10 Minutes), GARUDA Proof-of-Concept: 10-Minute Live Demonstration Script, Minute 00:00 - 01:30 | Zero-Host-Install Plug & Play Activation, Minute 01:30 - 03:30 | Physical Microarchitectural Baselining, Minute 03:30 - 05:30 | Simulated APT36 C2 Beacon & Physics Spike, Minute 05:30 - 07:00 | BRAHMA Bayesian Kill-Chain Tracker, Minute 07:00 - 08:30 | DHARMA Tier 0/1 Autonomous Response, Minute 08:30 - 09:30 | UTNE Executive SITREP Narrative (+2 more)

### Community 180 - "build_ioc_graph"
Cohesion: 0.18
Nodes (10): build_ioc_graph(), _compute_registrant_hash(), _pivot_pdns_nameservers(), Any, Construct an interconnected threat infrastructure graph across 4 pivot…, Pivot 3: Extract nameservers via CIRCL PDNS and find co-located domains., Pivot 4: Compute normalized hash of registrar and creation month., Any (+2 more)

### Community 181 - "fetch_boss_samples"
Cohesion: 0.20
Nodes (7): fetch_boss_samples(), Any, AsyncClient, _query_tag(), Query MalwareBazaar API for samples matching a specific tag. Args: client:…, Fetch and deduplicate recent APT36 and Transparent Tribe malware samples from…, TestGarudaSources

### Community 182 - "TestAirGappedIAS"
Cohesion: 0.18
Nodes (6): Test suite for offline IAS parity, safety gates, and analyst report generation., When observation count < 1000, all evaluations return 'BASELINING — NO ALERTS…, When calibrated (>= 1000 events), offline IAS detects physical divergence., Generates PDF forensic report from offline alert array without throwing…, Exporting alerts produces a valid STIX 2.1 JSON bundle structure., TestAirGappedIAS

### Community 183 - "TestRpzApiEndpoints"
Cohesion: 0.18
Nodes (6): Acceptance tests for RPZ HTTP API endpoints and Vercel crons., Acceptance Criteria: GET /rpz/zone serves flat BIND zone file with Content-Type…, GET /api/v1/rpz/entries returns structured JSON., POST /api/rpz/sync requires valid CRON_SECRET., POST /api/rpz/publish rejects low confidence and protected domains., TestRpzApiEndpoints

### Community 184 - "upsert_rpz_entry"
Cohesion: 0.22
Nodes (6): Publish or update a DNS RPZ trigger entry. Confidence must be >= 80 (enforced…, upsert_rpz_entry(), Validates soft-deletion, audit retention, and 90-day automatic roll-off., Active entries are retrieved; upserts update existing records., Acceptance Criteria: Deleting an entry sets removed_at (soft-delete). It is…, TestRpzLifecycleAndSoftDelete

### Community 185 - "test_orb.py"
Cohesion: 0.24
Nodes (7): InternetDbResponse, BaseModel, Pydantic validator for Shodan InternetDB responses., _load_fixture(), GARUDA Session 9 Acceptance Tests — ORB Network Tracker Tests cover SOHO…, Fixture validation for InternetDB responses., TestInternetDbFixture

### Community 186 - "Technical Abstract"
Cohesion: 0.22
Nodes (8): 1. Problem Statement (100 words), 2. Technological Innovation (200 words), 3. Deployment & Sovereign Architecture (150 words), 4. Empirical Validation & Results (150 words), 5. Project Team & Sovereignty Commitment, Innovations for Defence Excellence (iDEX) — DISC Application, Project Title, Technical Abstract

### Community 187 - "process_domain"
Cohesion: 0.25
Nodes (9): _calculate_domain_age(), _fetch_whois_data(), _is_whitelisted(), process_domain(), Any, Calculate age of domain in days from creation timestamp., Process, evaluate, score, and alert on a candidate domain through the full…, Check if domain is explicitly whitelisted in the Supabase database. (+1 more)

### Community 188 - "get_registrar_via_rdap"
Cohesion: 0.31
Nodes (8): _compute_age_days(), _empty_result(), enrich_alert_registrar(), get_registrar_via_rdap(), GARUDA RDAP Registrar Enrichment (FIX-05) Fetches registrar, creation date, and…, Fetch RDAP data and update the alert record immediately after insertion. Call…, Fetch registrar info using IANA RDAP — no API key, no rate limit. Returns: {…, Compute domain age in days from ISO creation date string.

### Community 189 - "AlmanacService"
Cohesion: 0.32
Nodes (5): AlmanacService, Any, Manages Gaussian baseline statistics and calibration state for monitored agents., Retrieves active baseline from cache or database., Updates baseline EMA if observation is clean (ias_score < log_threshold).…

### Community 190 - "Any"
Cohesion: 0.29
Nodes (4): Any, Sinkholes verified malicious C2 domain to 127.0.0.1., Commands the agent to intensify physical and kernel polling to 10Hz., Deploys shadow canary credentials to detect unauthorized lateral file access.

### Community 191 - "Zero-Host-Install Physics-Layer Intrusion Detection for Sovereign & Air-Gapped Networks"
Cohesion: 0.29
Nodes (6): Executive Overview, GARUDA Tactical USB Defense Agent, Key Technical Capabilities, Technical Specifications, Three Operational Modes, Zero-Host-Install Physics-Layer Intrusion Detection for Sovereign & Air-Gapped Networks

### Community 192 - "get_all_rpz_entries"
Cohesion: 0.33
Nodes (7): get_rpz_entry(), list_rpz_entries(), get, List RPZ rules with metadata, confidence scores, and lifecycle status., Retrieve single RPZ entry with STIX indicator correlation., get_all_rpz_entries(), Retrieve all RPZ entries including soft-deleted ones for forensic audit trail.

### Community 193 - "iDEX DISC Portal Submission — Problem Statement"
Cohesion: 0.33
Nodes (5): Challenge Domain, Challenge Title, Context & Operational Gap, iDEX DISC Portal Submission — Problem Statement, Proposed Solution: Project GARUDA

### Community 194 - "Sovereign Defense & Enterprise Licensing Schedule"
Cohesion: 0.33
Nodes (5): 1. Hardware Tactical Appliance (USB Edition), 2. SaaS & Central Platform Subscriptions (Per-Endpoint / Annual), 3. Professional Services & Sovereign Integration, GARUDA Commercial Pricing Matrix, Sovereign Defense & Enterprise Licensing Schedule

### Community 195 - "Sovereign Pre-Attack Cyber Threat Intelligence & Physics-Layer Endpoint Defense"
Cohesion: 0.33
Nodes (5): Core Platform Capabilities, Deployment Options, GARUDA Enterprise Defense Platform, Platform Architecture, Sovereign Pre-Attack Cyber Threat Intelligence & Physics-Layer Endpoint Defense

### Community 196 - "load_nic_domains"
Cohesion: 0.33
Nodes (6): _load_defaults(), _load_local_ground_truth(), load_nic_domains(), Initial population of default ground truth on startup., Load curated NIC/Gov domains from data/nic_domains.json., Load, fetch, merge, and deduplicate Indian Government & NIC domains into module…

### Community 197 - "enrich_threat_indicators"
Cohesion: 0.53
Nodes (6): enrich_threat_indicators(), _otx_safe(), Any, Enrich high-priority candidate domains with graceful degradation on…, _shodan_safe(), _vt_safe()

### Community 198 - "TestRpzZoneFileSyntax"
Cohesion: 0.33
Nodes (4): Validates RFC-compliant BIND 9 zone file generation., Zone serial must follow YYYYMMDDNN format (e.g. 2026082701)., Acceptance Criteria: Generated zone file follows standard BIND 9 RPZ syntax: -…, TestRpzZoneFileSyntax

### Community 199 - "RegisterDomainRequest"
Cohesion: 0.50
Nodes (3): BaseModel, field_validator, RegisterDomainRequest

### Community 201 - "fetch_all_agent_posteriors"
Cohesion: 0.40
Nodes (4): fetch_all_agent_posteriors(), Any, KALI Threat State Synchronizer Pulls live adversary posteriors from BRAHMA…, Retrieves current kill-chain distributions for active agents.

### Community 202 - "_resolve_ip"
Cohesion: 0.50
Nodes (4): _is_valid_domain(), Validate domain syntax and recognized TLD structure before DNS lookup., Resolve A record using dnspython within an async thread pool., _resolve_ip()

## Knowledge Gaps
- **146 isolated node(s):** `Config`, `Config`, `name`, `version`, `description` (+141 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **38 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `BaseSettings` connect `.__init__` to `AxiomSettings`, `update.py`?**
  _High betweenness centrality (0.305) - this node is a cross-community bridge._
- **Why does `Settings` connect `.__init__` to `garuda/config.py`?**
  _High betweenness centrality (0.275) - this node is a cross-community bridge._
- **Why does `BrahmaSettings` connect `update.py` to `.__init__`, `get_db_pool`, `dharma.py`, `PlanCache`?**
  _High betweenness centrality (0.142) - this node is a cross-community bridge._
- **What connects `Config`, `Config`, `name` to the rest of the system?**
  _146 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `reasoner.py` be split into smaller, more focused modules?**
  _Cohesion score 0.05271629778672032 - nodes in this community are weakly interconnected._
- **Should `lifecycle/tracker.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06487434248977206 - nodes in this community are weakly interconnected._
- **Should `webhook.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06823529411764706 - nodes in this community are weakly interconnected._