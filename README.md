# GARUDA: Cyber-Physical Threat Intelligence and Autonomous Containment Architecture

GARUDA is a high-assurance cyber-physical threat detection and automated response platform engineered for strategic installations, defense networks, and critical national infrastructure. The system combines microarchitectural side-channel telemetry, kernel-level causality tracking, Bayesian adversary modeling, and proactive infrastructure monitoring to detect advanced persistent threat (APT) activity across external and internal attack surfaces.

---

## Architectural Overview

Modern state-sponsored threat actors increasingly employ living-off-the-land techniques, in-memory execution, process hollowing, and legitimate cloud services (Discord, Slack, Supabase, Firebase) for command-and-control (C2). These vectors frequently bypass conventional endpoint detection and response (EDR) agents that rely on userland API hooks, file signatures, or static domain blocklists.

GARUDA addresses this gap through a multi-layer detection architecture:

1. **Hardware-Level Side-Channel Telemetry (AXIOM)**: Captures non-bypassable microarchitectural side-channel signals (CPU package and DRAM power dissipation via RAPL, L3 cache eviction bursts, and scheduler runqueue steal time) to detect memory scraping and process injection regardless of userland obfuscation.
2. **Kernel Process Provenance Identification (EPPI)**: Uses eBPF kprobes (`execve`, `mmap`, `tcp_connect`, `clone`) to correlate process lineage, detect executable memory mapping transitions, and classify cloud-hosted C2 channels.
3. **Active Infrastructure Intelligence (SENTINEL)**: Continuously polls Certificate Transparency (CT) logs for targeted lookalike infrastructure, executes automated multi-source enrichment (Shodan InternetDB, RIPE Stat, ip-api, URLScan), and tracks domain weaponization across a 5-stage lifecycle state machine.
4. **Probabilistic Attribution & Strategy Modeling (BRAHMA & KALI)**: Applies online recursive Bayesian updates across the 14 MITRE ATT&CK tactics with strict attribution gating, while using Monte Carlo Tree Search (MCTS) to model potential attacker trajectories against physical detection baselines.
5. **Deterministic Containment Grid (DHARMA)**: Executes policy-gated containment actions, including DNS RPZ sinkholing and non-destructive process freezing via SSH `SIGSTOP` to preserve volatile memory state for post-incident digital forensics.

```
+-----------------------------------------------------------------------------------+
|                              GARUDA SYSTEM TOPOLOGY                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ External Attack Surface ]              [ Monitored Host Infrastructure ]       |
|  * Certificate Transparency Logs          * eBPF Kernel Kprobes (EPPI)            |
|  * Abuse.ch Feeds (MalwareBazaar/TF)      * Hardware RAPL / Perf Counters (AXIOM) |
|  * ASN / IP / WHOIS Intelligence          * Volatile Memory Baseline Models       |
|              |                                           |                        |
|              v                                           v                        |
|  +-----------------------+               +--------------------------------+       |
|  | SENTINEL Hunt Engine  |               | AXIOM Telemetry Ingestion Mesh |       |
|  | (15m Polling & Enrich)|               | (10Hz Ring Buffer Telemetry)   |       |
|  +-----------------------+               +--------------------------------+       |
|              |                                           |                        |
|              +-------------------+   +-------------------+                        |
|                                  |   |                                            |
|                                  v   v                                            |
|                  +-----------------------------------+                            |
|                  | BRAHMA Bayesian Attribution Engine|                            |
|                  | & KALI Adversarial MCTS Engine    |                            |
|                  +-----------------------------------+                            |
|                                    |                                              |
|                                    v                                              |
|                  +-----------------------------------+                            |
|                  | DHARMA Tiered Containment Grid    |                            |
|                  | (DNS Sinkhole / SIGSTOP Freeze)   |                            |
|                  +-----------------------------------+                            |
|                                    |                                              |
|                                    v                                              |
|                  +-----------------------------------+                            |
|                  | UTNE SITREP & TAXII 2.1 Feeds     |                            |
|                  +-----------------------------------+                            |
+-----------------------------------------------------------------------------------+
```

---

## Core Subsystems

### 1. AXIOM: Microarchitectural Side-Channel Analysis
- **Power Dissipation Metrics**: Samples Running Average Power Limit (RAPL) package and DRAM energy channels to identify high-density cryptographic loops and staging workloads.
- **Cache Divergence**: Monitors hardware performance counter anomalies (L3 cache miss divergence) characteristic of linear memory scraping (e.g., LSASS dumping via `T1003.001`) and process hollowing (`T1055.012`).
- **Baseline Calibration**: Enforces a minimum sample threshold ($N \ge 1,000$) to construct unpolluted Gaussian baseline profiles, computing Integrated Anomaly Scores (IAS) via Kullback-Leibler divergence.

### 2. EPPI: Kernel Process Provenance & Cloud C2 Detection
- **eBPF Instrumentation**: Attaches non-invasive kprobes to kernel entry points to monitor process creation and memory protection flags (`PROT_EXEC`).
- **Cloud C2 Classification**: Inspects destination addresses and Server Name Indication (SNI) metadata during `tcp_connect` events to identify malicious use of legitimate SaaS endpoints (Discord webhooks, Slack API, Supabase, Firebase).
- **Fallback Verification**: Implements local caching of confirmed threat actor infrastructure to ensure sub-millisecond evaluation without blocking kernel ring buffers.

### 3. SENTINEL: Active Infrastructure Hunting & Lifecycle Engine
- **Persistent CT Polling**: Automated, query-optimized crt.sh ingestion targeting high-risk defense and government lookalike domain patterns.
- **Multi-Source Enrichment**: Parallel non-blocking lookups via Shodan InternetDB, RIPE Stat, ip-api, and URLScan search indices.
- **Convergence Scoring**: Evaluates candidate infrastructure using a multi-factor weighting formula:
  $$\text{Score} = 10 \times \left(0.40 \cdot S_{\text{keyword}} + 0.25 \cdot S_{\text{ports}} + 0.20 \cdot S_{\text{ASN}} + 0.15 \cdot S_{\text{URLScan}}\right)$$
- **Lifecycle State Machine**: Tracks domain progression across sequential infrastructure operationalization stages:
  $$\text{CERT\_ISSUED} \longrightarrow \text{DNS\_RESOLVING} \longrightarrow \text{HTTP\_LIVE} \longrightarrow \text{MX\_CONFIGURED} \longrightarrow \text{WEAPONIZED}$$

### 4. BRAHMA & KALI: Adversary Modeling & Predictive Simulation
- **Dirichlet-Multinomial Bayesian Updates**: Models adversary progression across all 14 MITRE ATT&CK tactics, incorporating calibrated historical prior distributions.
- **Attribution Gating**: Strictly prevents speculative attribution by requiring physical anomaly corroboration and minimum observation thresholds ($N \ge 15$).
- **MCTS Path Synthesis (KALI)**: Runs Monte Carlo Tree Search simulations across threat transition graphs to identify defensive gaps, evaluating path utility against calibrated detection probabilities.

### 5. DHARMA: Deterministic Containment & Preservation
- **Non-Destructive Process Freezing**: Issues remote `SIGSTOP` signals to compromised processes over hardened SSH channels, halting execution while keeping registers and heap contents intact for memory analysis.
- **Automated DNS Sinkholing**: Deploys immediate Response Policy Zone (RPZ) updates and upstream Cloudflare DNS modifications for weaponized domains.
- **Audit Immutability**: All containment actions and operator authorizations are written to an append-only audit log enforced by database-level Row-Level Security (RLS).

---

## Data Standards and External Interoperability

- **STIX 2.1 Specification**: Generates standards-compliant indicator objects with confidence scoring, kill chain phases, and evidentiary references.
- **TAXII 2.1 Feeds**: Provides authenticated collections for inter-agency intelligence sharing and integration with external SIEM/SOAR platforms.
- **DNS RPZ Format**: Exports active blocklists in standard BIND Response Policy Zone format for perimeter gateway ingestion.

---

## Technical Stack

| Layer | Technologies |
| :--- | :--- |
| **Kernel & Agent** | C (eBPF / BCC), Python 3.10+, Linux Kernel 5.15+ |
| **Backend Services** | Python, FastAPI, AsyncIO, HTTPX, NetworkX, NumPy |
| **Adversary Modeling** | Bayesian Dirichlet-Multinomial Estimators, Monte Carlo Tree Search |
| **Database & Realtime** | PostgreSQL, Supabase Realtime, PostgREST, Row-Level Security (RLS) |
| **Frontend Console** | React 18, Vite, Tailwind CSS, Lucide Icons |

---

## Repository Structure

```
garuda/
├── brahma-service/          # Adversary kill chain modeling & KALI MCTS engine
│   ├── brahma/              # Bayesian tactic attribution service
│   └── kali/                # Adversarial path synthesis & graph algorithms
├── garuda-agent/            # Bare-metal host monitoring daemon
│   └── garuda_agent/        # eBPF kprobes, RAPL reader, scheduler telemetry
├── sentinel-service/        # Active threat intelligence & CT collector
│   ├── hunt/                # crt.sh collector, enrichment, domain lifecycle
│   └── fixtures/            # Validated threat intelligence API responses
├── frontend/                # Tactical operational console (React/Vite)
├── migrations/              # Database schema migrations & RLS policies
└── tests/                   # Regression and integration test suites
```

---

## Verification & Testing

The platform includes automated unit, integration, and regression test suites validating side-channel threshold bounds, Bayesian convergence, MCTS utility uniqueness, and network parsing resilience.

```bash
# Run complete test suite
python -m pytest tests/ -v
```

---

## Deployment & Operational Context

GARUDA is architected for deployment in hybrid, sovereign cloud, or fully air-gapped network configurations. Core components operate deterministically with local fallbacks, ensuring continuous detection capability during network isolation or upstream connectivity loss.
