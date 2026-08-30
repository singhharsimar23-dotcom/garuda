# GARUDA Tactical USB Defense Agent
## Zero-Host-Install Physics-Layer Intrusion Detection for Sovereign & Air-Gapped Networks

---

### Executive Overview
**GARUDA Tactical USB** is an India-sovereign host defense and incident response appliance designed for high-security defense networks, command posts, and air-gapped critical infrastructure. Operating directly from a cryptographically signed read-only media partition, GARUDA monitors microarchitectural physical invariants without requiring persistent software installation on target hosts.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PORTABLE HARDWARE INTRUSION DETECTION (USB / LIVE SQUASHFS / LUKS2)         │
│  - 0% Host Dependency: No kernel compilation or persistent agents required  │
│  - Physics-Layer Invariants: Intel/AMD RAPL, IPC, L3 Cache Misses, Entropy  │
│  - Air-Gapped Autonomy: Local Gaussian KL Divergence scoring in SQLite      │
│  - Sovereign Compatibility: BOSS Linux, Bharat Operating System, RHEL, Ubuntu│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Three Operational Modes

| Operating Mode | Network Context | Execution Model | Storage & Telemetry |
| :--- | :--- | :--- | :--- |
| **Mode 1: Live Host Monitor** | Networked Defense Workstation | USB plugged into running OS; background monitoring | WireGuard / HTTPS sync to AXIOM Cloud Backend |
| **Mode 2: Bootable Forensic Triage** | Suspect Compromised Machine | UEFI direct-boot into Alpine Linux RAM Root | Ephemeral triage with read-only host disk mounting |
| **Mode 3: Air-Gapped Sovereign Defense** | Classified Isolated Facility | 100% Offline; zero network sockets opened | Encrypted local buffering on LUKS2 data partition |

---

### Key Technical Capabilities

1. **Physics-Layer Microarchitectural Telemetry**:
   - Continuous 1Hz measurement of CPU package energy (RAPL $\mu\text{J}$), core power, and DRAM dissipation.
   - Hardware performance counter tracking: Instructions Retired, LLC/L3 Cache Miss Spikes, and Dynamic IPC.
   - Kernel scheduler wait/run latency and hardware entropy pool depletion monitoring.

2. **Offline Instruction/Anomaly Scoring (IAS)**:
   - Onboard statistical engine computing Gaussian Kullback-Leibler (KL) Divergence across 6 physical channels against calibrated host baselines.
   - Strict baselining safety gate: $< 1000$ observation events prevent false alarms during host onboarding.

3. **Air-Gapped Analyst Workstation Suite**:
   - Single-command forensic extraction generating executive PDF situation reports with 30-day IAS time series.
   - Automatic conversion of confirmed anomalies into standardized STIX 2.1 JSON packages for national SOC submission.

---

### Technical Specifications

- **Form Factor**: High-endurance Industrial Grade USB 3.2 Drive (32GB / 64GB Hardware Encrypted).
- **Architecture Support**: x86_64 (Intel 6th Gen+ / AMD Zen+), ARM64 (Graviton/Neoverse).
- **Host OS Compatibility**: BOSS Linux 8/9, Debian 11/12, Ubuntu 20.04/22.04/24.04, RHEL/CentOS 8/9.
- **Cryptographic Security**: Ed25519 GPG firmware signature, LUKS2 AES-256-XTS data encryption.
