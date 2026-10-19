<div align="center">

```
 ██████╗  █████╗ ██████╗ ██╗   ██╗██████╗  █████╗
██╔════╝ ██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗
██║  ███╗███████║██████╔╝██║   ██║██║  ██║███████║
██║   ██║██╔══██║██╔══██╗██║   ██║██║  ██║██╔══██║
╚██████╔╝██║  ██║██║  ██║╚██████╔╝██████╔╝██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
```

**Cyber-Physical Threat Intelligence & Autonomous Containment Platform**

*Developed under the iDEX (Innovations for Defence Excellence) initiative · Ministry of Defence, Government of India*

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?style=flat-square&logo=fastapi&logoColor=white)
![eBPF](https://img.shields.io/badge/eBPF-kernel--level-E95420?style=flat-square&logo=linux&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-336791?style=flat-square&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-containerised-2496ED?style=flat-square&logo=docker&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red?style=flat-square)
![STIX 2.1](https://img.shields.io/badge/STIX-2.1-orange?style=flat-square)

</div>

---

## The Problem

Modern state-sponsored threat actors — the kind that target defence networks, critical infrastructure, and strategic installations — have moved beyond simple malware. They live off the land: running entirely in memory, hijacking legitimate cloud services like Slack and Discord for command-and-control, and cloning government domains certificate by certificate before a single packet is fired.

Conventional endpoint detection misses all of this. It looks for files, signatures, and known-bad IPs. It can't see what the CPU is physically doing, can't track kernel-level process ancestry, and has no idea a lookalike domain for `mod.gov.in` was registered three weeks ago.

**GARUDA was built to close that gap.**

---

## What GARUDA Does

GARUDA is a multi-layer, autonomous threat detection and response platform that operates from hardware sensors all the way up to strategic intelligence feeds — five tightly integrated subsystems working in concert.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         G A R U D A  ·  SYSTEM TOPOLOGY                     │
├──────────────────────────────────┬──────────────────────────────────────────┤
│     EXTERNAL ATTACK SURFACE      │       MONITORED HOST INFRASTRUCTURE      │
│                                  │                                          │
│  · Certificate Transparency logs │  · eBPF kprobes  (execve / mmap /        │
│  · Abuse.ch / MalwareBazaar      │    tcp_connect / clone)                  │
│  · Shodan · RIPE · URLScan       │  · Hardware RAPL + Perf Counters         │
│  · ASN / BGP / WHOIS feeds       │  · Volatile memory baseline models       │
└────────────────┬─────────────────┴───────────────────┬──────────────────────┘
                 │                                     │
                 ▼                                     ▼
     ┌───────────────────────┐         ┌───────────────────────────────┐
     │   SENTINEL Hunt Engine│         │  AXIOM Telemetry Ingestion    │
     │   CT polling · 15 min │         │  Mesh  ·  10 Hz ring buffer   │
     └───────────┬───────────┘         └───────────────┬───────────────┘
                 │                                     │
                 └──────────────────┬──────────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │  BRAHMA  Bayesian Attribution  │
                    │  KALI    Adversarial MCTS      │
                    └───────────────┬───────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │  DHARMA  Containment Grid      │
                    │  DNS sinkhole · SIGSTOP freeze │
                    └───────────────┬───────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │  UTNE  SITREP + TAXII 2.1 Feed│
                    │  LLM-grounded intel narrative  │
                    └───────────────────────────────┘
```

---

## Five Subsystems

### AXIOM — Hardware-Level Side-Channel Analysis

Most attackers assume userland is the only thing watching. AXIOM watches the hardware.

It samples CPU package and DRAM power draw via Intel RAPL, monitors L3 cache eviction bursts, and tracks scheduler run-queue steal time at 10 Hz. When an adversary runs an LSASS dump (`T1003.001`) or hollows a process (`T1055.012`), the power and cache signatures are physically distinct from normal workloads — and AXIOM catches them regardless of how the malware was written.

Anomaly detection uses Kullback-Leibler divergence against a Gaussian baseline built from a minimum of 1,000 clean samples. No alerts fire during baseline calibration. No guesses.

---

### EPPI — Kernel Process Provenance & Cloud C2 Detection

EPPI attaches non-invasive eBPF kprobes directly to kernel entry points: `execve`, `mmap`, `clone`, `tcp_connect`. It tracks every process spawned, every executable memory region created, and every outbound TCP connection — all with full parent–child lineage.

The critical capability: **cloud C2 classification**. When a process connects to `discord.com`, `hooks.slack.com`, `supabase.co`, or `firebase.io`, EPPI cross-references the connecting process's lineage against known-good baselines. A browser connecting to Discord is fine. A system binary that was spawned from a Word document connecting to Discord is an immediate escalation.

---

### SENTINEL — Active Infrastructure Hunting & Lifecycle Engine

Attackers register infrastructure weeks before they use it. SENTINEL watches them build it.

Every 15 minutes, SENTINEL ingests Certificate Transparency logs from crt.sh, hunting for domains that pattern-match against defence, government, and critical infrastructure naming conventions. Each candidate is enriched in parallel from four independent sources: Shodan InternetDB, RIPE Stat, ip-api, and URLScan.

Threat scoring:

```
Score = 10 × (0.40 · S_keyword + 0.25 · S_ports + 0.20 · S_ASN + 0.15 · S_URLScan)
```

Domains are tracked through a five-stage weaponization lifecycle:

```
CERT_ISSUED → DNS_RESOLVING → HTTP_LIVE → MX_CONFIGURED → WEAPONIZED
```

When a domain crosses the weaponization threshold, DHARMA is triggered automatically.

---

### BRAHMA & KALI — Adversary Modeling & Predictive Red-Teaming

Once an alert fires, the question isn't just *what happened* — it's *what comes next*.

**BRAHMA** applies online Bayesian updates across all 14 MITRE ATT&CK tactics using a Dirichlet-Multinomial model. Attribution is strictly gated — no attribution fires without corroborating physical signals and a minimum of 15 observations.

**KALI** takes BRAHMA's current adversary model and runs Monte Carlo Tree Search simulations across the threat transition graph. It surfaces the paths a threat actor is most likely to try next, evaluated against real detection probabilities, so defenders can patch specific gaps rather than hardening everything.

---

### DHARMA — Deterministic Containment

When BRAHMA flags a confirmed intrusion, DHARMA acts — with precision, not panic.

- **Process isolation** — Issues `SIGSTOP` over a hardened SSH channel. The process freezes instantly, keeping heap, registers, and file descriptors intact for forensic analysis. No data destroyed, no attacker alerted.
- **DNS sinkholing** — Pushes immediate Response Policy Zone (RPZ) entries to BIND and upstream Cloudflare DNS.
- **Audit immutability** — Every action is written to an append-only log with database-level Row-Level Security. No operator can quietly reverse a containment action without leaving a trace.

---

### UTNE — Executive Intelligence Narrative

UTNE synthesises the full evidence graph into structured SITREPs using a grounded LLM pipeline (Groq / Gemini, with local fallback). It exports STIX 2.1 bundles for inter-agency sharing via TAXII 2.1 feeds.

---

## Technical Stack

| Layer | Technologies |
|---|---|
| **Kernel & Agent** | C · eBPF / BCC · Python 3.10+ · Linux Kernel 5.15+ |
| **Telemetry** | Intel RAPL · `perf_event_open` · `/proc/schedstat` · TPM 2.0 PCR |
| **Backend Services** | Python · FastAPI · AsyncIO · HTTPX · NetworkX · NumPy · scikit-learn |
| **Adversary Modeling** | Bayesian Dirichlet-Multinomial · Monte Carlo Tree Search · Random Forest |
| **Database & Realtime** | PostgreSQL · Supabase Realtime · PostgREST · Row-Level Security |
| **Intelligence Standards** | STIX 2.1 · TAXII 2.1 · DNS RPZ (BIND) · MITRE ATT&CK v14 |
| **Frontend Console** | React 18 · Vite · Tailwind CSS · Lucide Icons · Supabase Realtime WS |
| **Deployment** | Docker · Render · Vercel · Cloudflare Workers · Upstash Redis |
| **LLM Inference** | Groq (Llama 3.1 8B / 70B) · Google Gemini · local fallback |

---

## Repository Structure

```
garuda/
│
├── garuda-agent/               # Bare-metal host monitoring daemon
│   └── garuda_agent/           #   eBPF kprobes · RAPL reader · scheduler telemetry
│
├── axiom-service/              # Physics-layer telemetry ingestion & anomaly scoring
│
├── sentinel-service/           # Active threat intelligence & CT log collector
│   └── hunt/                   #   crt.sh ingestion · enrichment · domain lifecycle
│
├── brahma-service/             # Attribution & red-team engine
│   ├── brahma/                 #   Bayesian tactic modelling · attribution gating
│   └── kali/                   #   Adversarial path synthesis · threat graph MCTS
│
├── network-service/            # UTNE executive narrative & TAXII 2.1 feeds
│
├── cloudflare-worker/          # Edge ingestion worker — real-time domain relay
│
├── frontend/                   # Tactical operations console (React / Vite)
│
├── migrations/                 # PostgreSQL schema migrations · RLS policies
├── data-pipeline/              # Offline classifier training pipelines
└── tests/                      # Unit · integration · regression suites
```

---

## Deployment

GARUDA runs in hybrid, sovereign cloud, and fully air-gapped configurations. All components include local fallbacks — detection continues during complete network isolation.

**Prerequisites**

- Linux host, kernel ≥ 5.15 (for eBPF and RAPL access)
- Docker & Docker Compose
- Supabase project (PostgreSQL + Realtime)
- Cloudflare account (DNS sinkholing)

```bash
# 1. Clone
git clone https://github.com/singhharsimar23-dotcom/garuda.git && cd garuda

# 2. Configure
cp .env.example .env
# Add Supabase, Cloudflare, and Groq credentials

# 3. Apply database schema
psql $DATABASE_URL < init_db.sql

# 4. Start all backend services
docker compose up -d

# 5. Deploy the host agent
pip install -e garuda-agent/
garuda-agent --config config/agent.yaml

# 6. Start the frontend console
cd frontend && npm install && npm run dev
```

Cloud services are pre-configured in [`render.yaml`](./render.yaml) for one-click Render deployment.

---

## Testing

```bash
# Full suite
python -m pytest tests/ -v

# Per subsystem
python -m pytest tests/test_sentinel.py -v
python -m pytest tests/test_brahma.py -v
python -m pytest tests/test_axiom.py -v
```

The suite validates side-channel threshold bounds, Bayesian convergence properties, MCTS utility uniqueness, STIX bundle structure, RPZ format correctness, and network parsing resilience.

---

## Intelligence Interoperability

| Standard | Implementation |
|---|---|
| **STIX 2.1** | Indicator objects with confidence scores, kill chain phases, evidence references |
| **TAXII 2.1** | Authenticated collection endpoints for SIEM/SOAR integration |
| **DNS RPZ** | BIND Response Policy Zone export for perimeter gateway ingestion |
| **MITRE ATT&CK v14** | All 14 tactics modelled with T-code-level attribution |

---

## Acknowledgements

This project was developed as part of the **iDEX (Innovations for Defence Excellence)** initiative under the **Ministry of Defence, Government of India** — a programme that connects innovators with the challenges of national security.

---

<div align="center">

*Built for India's defenders.*

</div>

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
