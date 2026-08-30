# iDEX DISC Portal Submission — Problem Statement

### Challenge Domain
**Defence Cyber Operations & Critical Information Infrastructure Protection (CIIP)**

---

### Challenge Title
**Indigenous Physics-Layer Endpoint Detection & Autonomous Response System for Sovereign & Air-Gapped Military Networks**

---

### Context & Operational Gap
1. **Dormant and Memory-Only Malware in Defence Networks**: Modern state-sponsored threat groups deploy sophisticated in-memory loaders and living-off-the-land techniques that evade conventional file-based antivirus and signature-based EDR agents.
2. **Air-Gapped Network Vulnerabilities**: Classified military headquarters and tactical field command centers operate in isolated (air-gapped) environments where cloud-dependent security tools cannot function.
3. **Foreign Supply Chain Risk**: Reliance on foreign-origin EDR software creates unacceptable sovereignty and intelligence leakage risks for critical national defense infrastructure.
4. **Lack of Hardware-Level Ground Truth**: Traditional security products rely on software APIs that can be hooked, blinded, or bypassed by kernel-level rootkits. Physical CPU thermodynamic power dissipation cannot be falsified by software.

---

### Proposed Solution: Project GARUDA
GARUDA addresses this national defense priority through an indigenous, physics-layer host intrusion detection system and autonomous response engine that:
- Measures unalterable CPU physical power dissipation (RAPL) and microarchitectural performance counters to detect malicious computation.
- Operates in zero-host-install tactical USB mode for air-gapped forensic triage and persistent sovereign enterprise mode for networked command centers.
- Employs Bayesian adversary intent tracking (BRAHMA) and automated tiered response (DHARMA) to neutralize threats in under 5 seconds.
