# Innovations for Defence Excellence (iDEX) — DISC Application
## Technical Abstract

### Project Title
**GARUDA: India-Sovereign Pre-Attack Cyber Threat Intelligence Platform for Defence Networks Using Physics-Layer Host Intrusion Detection**

---

### 1. Problem Statement (100 words)
State-sponsored advanced persistent threat (APT) actors, notably APT36 (Transparent Tribe) and SideCopy, conduct persistent espionage and destructive cyber operations targeting Indian defence establishments, military headquarters, and strategic public sector units. Existing commercial endpoint detection and response (EDR) solutions fail against dormant implants, memory-resident payloads, and zero-day execution techniques that bypass OS-level hooks. Furthermore, foreign EDR solutions introduce critical supply-chain sovereignty vulnerabilities, rely on foreign cloud backends, and lack specialized baseline models for indigenous platforms such as BOSS Linux (Bharat Operating System Solutions) and DRDO computing hardware.

---

### 2. Technological Innovation (200 words)
GARUDA pioneers physical-layer intrusion detection by sampling hardware microarchitectural power telemetry directly from Intel/AMD Running Average Power Limit (RAPL) registers, CPU performance counters (PMC), and kernel scheduler statistics. Because computation physically consumes energy, malicious memory injection, reflective DLL loading, and covert cryptographic beaconing produce measurable thermodynamic and microarchitectural deviations that are physically impossible for an adversary to conceal—even with kernel-level rootkits.

GARUDA models these invariants using a multi-channel Gaussian Kullback-Leibler (KL) Divergence formulation (Instruction/Anomaly Score, or IAS) computed in real time. This is augmented by:
1. **EPPI (eBPF Provenance Profiler)**: Lightweight kernel kprobes reconstructing causal process execution graphs (PROVDAG) tagged with millisecond-accurate physical power measurements.
2. **BRAHMA (Bayesian Model of Adversary Intent)**: Real-time probability tracking across all 14 MITRE ATT&CK kill-chain tactics calibrated against historical South Asian threat campaigns.
3. **DHARMA (Autonomous Tiered Response)**: Sub-5-second automated sensor intensification, DNS sinkholing, and operator-supervised process isolation with deterministic rollback.
4. **MAYA & KALI-PRIME**: Proactive deception canary generators and weekly adversarial path synthesis algorithms pre-populating containment plans.

---

### 3. Deployment & Sovereign Architecture (150 words)
GARUDA provides flexible sovereign deployment architectures tailored to military constraints:
- **Tactical USB Appliance**: A plug-and-play, zero-host-install hardware pendrive running from a cryptographically signed read-only Alpine Linux image. Designed for rapid incident response and air-gapped classified enclaves, it computes IAS scores locally against an encrypted SQLite database and generates offline PDF forensic reports and STIX 2.1 packages.
- **Sovereign Cloud & On-Premise Core**: Microservices architecture deployed within Indian regional datacenters or isolated military Kubernetes clusters.
- **National Intelligence Integration**: Native STIX 2.1 / TAXII 2.1 compliance enabling automated, bidirectional threat indicator exchange with CERT-In and Defence Cyber Agency (DCyA) command operations.

---

### 4. Empirical Validation & Results (150 words)
GARUDA's detection pipeline has been validated across standard Linux server environments and BOSS Linux virtualized defense nodes. In empirical evaluations:
- Simulated APT36 C2 beaconing (AES-256 encrypted network communication) generated distinct RAPL package energy and L3 cache miss divergences detected by the AXIOM engine within 60 seconds of implant activation.
- Continuous 72-hour baselining demonstrated zero false positives under standard server, database, and compile workloads.
- Sub-5-second Tier 0 automated containment was demonstrated through real-time sensor rate intensification and STIX DNS sinkhole generation.
- Full end-to-end integration across all 57 automated test suites confirms complete mathematical parity between cloud and air-gapped scoring algorithms.

---

### 5. Project Team & Sovereignty Commitment
The GARUDA team consists of indigenous cyber defence researchers and systems software engineers committed to building self-reliant, zero-foreign-dependency cyber defense infrastructure for the Republic of India.
