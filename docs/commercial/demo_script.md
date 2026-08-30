# GARUDA Proof-of-Concept: 10-Minute Live Demonstration Script

---

### Prerequisites & Setup
- **Target Host**: Ubuntu 22.04 LTS or BOSS Linux VM.
- **Operator Console**: Browser open to Vercel Operator UI (`/phase3`).
- **Alert Channel**: Mobile phone with Telegram notification channel.
- **Hardware Appliance**: GARUDA Tactical USB Drive.

---

### Demonstration Timeline (10 Minutes)

#### Minute 00:00 - 01:30 | Zero-Host-Install Plug & Play Activation
1. **Presenter Narrative**: *"Traditional security requires complex agent installations and kernel modules. Watch how GARUDA activates instantaneously from a signed USB drive with zero host modification."*
2. **Action**: Insert GARUDA Tactical USB into target VM.
3. **Observation**: Udev auto-launches background agent. Run `journalctl -f | grep garuda`.
4. **UI View**: In Vercel UI (`/axiom`), new node appears with status `BASELINING`.

#### Minute 01:30 - 03:30 | Physical Microarchitectural Baselining
1. **Presenter Narrative**: *"GARUDA continuously samples 6 hardware physical channels at 1Hz: Intel RAPL package power, DRAM energy, CPU IPC, L3 cache misses, entropy, and scheduler delays."*
2. **UI View**: Point to `PhysicsMonitor` table. Show normal baseline power (~15.2W) and baseline IAS score ($\approx 0.0\sigma$).

#### Minute 03:30 - 05:30 | Simulated APT36 C2 Beacon & Physics Spike
1. **Action**: Execute `simulate_beacon.sh` (emulates AES-256 encrypted C2 network bursts).
2. **Observation**: 
   - CPU Package Power surges from 15.2W to 28.5W.
   - L3 Cache misses spike by $+340\%$.
   - IAS Score rises rapidly: $0.8 \rightarrow 1.8 \rightarrow 3.1 \rightarrow 5.4\sigma$ (CRITICAL).
3. **Alerting**: Phone receives instant Telegram alert with physical divergence details.

#### Minute 05:30 - 07:00 | BRAHMA Bayesian Kill-Chain Tracker
1. **Action**: Switch to `BRAHMA (ADVERSARY)` tab in Operator UI.
2. **Observation**:
   - Discrete posterior over 14 MITRE tactics updates in real time.
   - Command & Control (`C2`) tactic probability peaks at $> 0.82$.
   - Confidence badge transitions to `CONVERGED`.

#### Minute 07:00 - 08:30 | DHARMA Tier 0/1 Autonomous Response
1. **Presenter Narrative**: *"Within 5 seconds, DHARMA executes Tier 0 automated response: intensifying sensor rates to 10Hz and sinkholing malicious C2 domains."*
2. **Action**: Switch to `DHARMA (QUEUE)` tab.
3. **Observation**:
   - Tier 1 `PROCESS_ISOLATION` pending approval for malicious PID with 15-minute countdown.
   - Click **APPROVE (SIGSTOP)**.
   - On target VM, run `ps aux | grep payload_worker`: process is frozen in state `T` (`SIGSTOP`).

#### Minute 08:30 - 09:30 | UTNE Executive SITREP Narrative
1. **Action**: Switch to `UTNE (SITREP)` tab.
2. **Observation**:
   - Live stream of executive incident narrative generated with evidence node citations (`NODE-EVID-1`).
   - Grounded Q&A: Type *"What physical evidence triggered the containment?"* and observe instantaneous contextual response.

#### Minute 09:30 - 10:00 | Air-Gapped Offline Forensic Triage
1. **Action**: Remove USB drive from host VM.
2. **Action**: On analyst workstation, run `python usb-analyst/garuda_analyst.py --usb /media/garuda/data`.
3. **Observation**:
   - Generates executive PDF report (`isolated-endpoint_garuda_report.pdf`) with 30-day IAS graph and physics table.
   - Generates valid STIX 2.1 JSON bundle for national CERT-In reporting.
4. **Closing**: *"Complete physical defense lifecycle demonstrated in 10 minutes—from microarchitectural detection to autonomous containment and air-gapped forensic reporting."*
