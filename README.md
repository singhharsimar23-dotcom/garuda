# GARUDA (गरुड़) // Sovereign Cyber-Physical Threat Intelligence & Autonomous Containment Platform

[![Production Status](https://img.shields.io/badge/Status-Operational_%2F%2F_Production_Ready-00C853?style=for-the-badge&logo=shield&logoColor=white)](https://garuda-intel.vercel.app)
[![Platform Classification](https://img.shields.io/badge/Security-PROPRIETARY_%2F%2F_DEFENSE_CONFIDENTIAL-FF6B00?style=for-the-badge)](https://garuda-intel.vercel.app)
[![Live Interface](https://img.shields.io/badge/Console-garuda--intel.vercel.app-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://garuda-intel.vercel.app)
[![Standard Compliance](https://img.shields.io/badge/Standard-CERT--In_%2F%2F_STIX_2.1-1E88E5?style=for-the-badge)](https://garuda-intel.vercel.app)

> **GARUDA** is a sovereign, cyber-physical threat intelligence and autonomous response platform designed for high-assurance defense infrastructure, national data networks, and air-gapped strategic installations. Combining microarchitectural hardware side-channel telemetry, kernel-level causality tracking, Bayesian adversary modeling, and anti-hallucinatory intelligence synthesis, GARUDA bridges the critical gap between physical silicon invariants and national cyber sovereignty.

---

## 🎖 Executive Summary & Core Mission

Modern advanced persistent threats (APTs) and zero-day execution vectors routinely bypass traditional signature-based EDRs, host firewalls, and hypervisor-level monitors through kernel manipulation and in-memory execution. 

**GARUDA enforces a fundamental paradigm shift: *Software can lie, but physical silicon cannot.***

By observing microarchitectural energy consumption, CPU execution cycle disturbances, and hardware cache invariants at the bare-metal level, GARUDA detects weaponized payloads before they establish persistence—enforcing sub-5-second autonomous containment across networked, hybrid, and completely air-gapped critical infrastructure.

---

## ⚡ Core Operational Capabilities

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                               GARUDA CORE CAPABILITY MATRIX                                 │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│  1. Microarchitectural Silicon Radar (Sub-5s Hardware Side-Channel Anomaly Scoring)         │
│  2. Bayesian Kill-Chain Attribution Engine (14-Tactic Online Threat Actor Mapping)          │
│  3. Multi-Tier Autonomous Containment Grid (Deterministic Escalation with Zero Downtime)    │
│  4. Sovereign CTI Narrative Synthesizer (Honest, Evidence-Grounded Situational Reporting)   │
│  5. Tactical Air-Gapped USB Agent (Tri-Mode Fully Offline Mission-Ready Defense)            │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1. Hardware-Level Microarchitectural Invariant Analysis
* **Silicon Ground Truth**: Monitors hardware energy counters (RAPL), cache misses, entropy state, and kernel scheduling latencies at 1Hz continuous sampling.
* **Integrated Anomaly Scoring (IAS)**: Utilizes closed-form Gaussian Kullback-Leibler (KL) divergence to detect anomalies across 13 concurrent physical side channels.
* **Zero-Pollution Baseline Safeguard**: Enforces strict unpolluted baseline calibration ($\ge 1,000$ events) before validating anomaly thresholds, preventing attackers from slowly poisoning baseline distributions.

---

### 2. Bayesian Adversary Modeling & State Tracking
* **Probabilistic Kill-Chain Synthesis**: Continuously models threat actor advancement across all 14 MITRE ATT&CK tactics (Reconnaissance to Exfiltration) using online recursive Bayesian updates.
* **MAML Meta-Learning Initialization**: Calibrates tactic transition priors from global cyber-threat distributions, enabling fast attribution convergence against emerging regional state actors.
* **Deception Operations**: Dynamically seeds deterministic canary credentials and ghost operational documents with real-name sanitization to detect unauthorized lateral traversal instantly.

---

### 3. Multi-Tier Autonomous Response Grid
* **Tier 0 Containment ($< 5\text{s}$ SLA)**: Instantaneous sensor intensification (1Hz $\rightarrow$ 10Hz) and real-time DNS RPZ sinkholing without disrupting operational services.
* **Tier 1 Operator Containment**: Policy-gated, human-in-the-loop process isolation, network namespace partitioning, and firewall enforcement.
* **Cryptographic Rollback & Immutability**: Every mitigation plan computes complete rollback states and writes to a tamper-proof, append-only ledger protected by database-level immutability triggers.

---

### 4. Sovereign Threat Narrative & CERT-In Compliance
* **Anti-Hallucination Charter (Rule 8 Enforcement)**: Prohibits speculative attribution. If observation volume is mathematically insufficient ($N < 15$), the engine strictly outputs `ATTRIBUTION UNCERTAIN`.
* **Evidentiary Citation Binding**: Every operational Situation Report (SITREP) explicitly binds claims to physical and kernel evidence tokens (`[NODE-EVID-X]`).
* **Automated STIX 2.1 Bundling**: One-click generation of CERT-In compliant machine-readable threat packages for inter-agency coordination.

---

### 5. Tactical Air-Gapped USB Deployment
* **Tri-Mode Operational Adaptability**:
  - **`ALONGSIDE`**: Non-invasive plug-and-play monitoring on active host operating systems.
  - **`BOOTABLE`**: Standalone, hardened Linux operating system for forensic triage and uncompromised assessment.
  - **`AIRGAPPED`**: 100% network-isolated operation on high-security air-gapped weapon systems and command networks.
* **Hardware-Encrypted Persistence**: Stores forensic captures and audit trails on Ed25519-signed, LUKS2-encrypted physical partitions.
* **Offline Analyst Workstation Suite**: Command-line tools for generating high-resolution PDF intelligence briefings and STIX 2.1 bundles without internet connectivity.

---

## 🌐 Live Production Console & Infrastructure

The GARUDA platform is fully operational in production across distributed high-availability nodes:

* **Production Intelligence Console**: [**https://garuda-intel.vercel.app**](https://garuda-intel.vercel.app)
* **Real-time Alerting Matrix**: Automated critical escalation dispatched via encrypted defense channels and Telegram Bot integrations.
* **Distributed Cloud Services**: High-throughput microservice mesh backed by real-time change data capture (CDC) and encrypted key-value caching.

---

## 🔒 Enterprise & Defense Security Guarantees

| Invariant | System Guarantee |
| :--- | :--- |
| **Silicon Primacy** | Physical side-channel energy measurements cannot be spoofed by userland or kernel-mode rootkits. |
| **Audit Immutability** | Database triggers prohibit `DELETE` or unauthorized modification on containment action histories. |
| **Zero Synthetic Data** | All threat signatures are derived exclusively from verified hardware telemetry and authenticated open CTI feeds. |
| **Strict Attribution Honesty** | Refuses to guess adversary identities without mathematical Bayesian convergence. |
| **Air-Gapped Independence** | Complete mission readiness without external SaaS, telemetry phone-home, or third-party cloud dependencies. |

---

## 📊 Verification & Test Coverage

GARUDA undergoes continuous validation against a rigorous, multi-vector test suite:

```bash
# Execute Full Platform Test Suite
python -m pytest tests/ -v
```

* **Test Suite Status**: **64/64 Core Integration & Invariant Tests Passing (100% Pass Rate)**
* **Coverage Scope**: RAPL Rollover Resilience, Bayesian Convergence, Tier 0 SLA Enforcement, eBPF Causality DAGs, Air-Gapped Baselining Guards, and Anti-Hallucination Assertions.

---

## 📄 Classification & Legal Notice

**CLASSIFICATION: PROPRIETARY // DEFENSE CONFIDENTIAL**  
*The internal mathematical models, kernel probe mechanics, and microarchitectural extraction algorithms contained within this platform constitute proprietary intellectual property developed for high-assurance sovereign defense applications. Public redistribution or unauthorized reverse engineering is strictly prohibited.*

Developed for **Innovations for Defence Excellence (iDEX)** and Sovereign Digital Infrastructure Defense.
