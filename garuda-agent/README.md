# GARUDA Host Telemetry Agent (`garuda-agent`)

The `garuda-agent` is a lightweight host-level physical execution monitoring agent designed to detect side-channel anomalies, evasive malware, and unauthorized execution on Linux infrastructure (BOSS Linux, Debian, Ubuntu, RHEL).

## Monitored Channels
1. **RAPL Power Channels**: Intel/AMD microjoule energy consumption counters (`/sys/class/powercap` and `hwmon`).
2. **Hardware Performance Counters**: Hardware instructions, cache-misses, cycles, and IPC via `perf_event_open` / `perf stat`.
3. **Kernel Entropy Pool**: Entropy consumption and depletion rates (`/proc/sys/kernel/random/entropy_avail`).
4. **Hardware TPM 2.0 PCRs**: Platform Configuration Register measurement integrity (`tpm2_pcrread`).
5. **Kernel Scheduler Latency**: Wait time delay ratios and context switch rates (`/proc/schedstat`).
6. **EPPI eBPF Event Streams**: Kernel kprobe provenance tracking (kernel 5.4+).

---

## 3 USB Deployment Modes

### Mode 1: Dropped Daemon Service (Standard Networked Endpoint)
For persistent background monitoring on networked defense workstations and servers.

```bash
# 1. Install pip package
pip install .

# 2. Configure environment
export AGENT_API_KEY="<your-agent-key>"
export AXIOM_URL="https://garuda-intel.vercel.app"
export GARUDA_AGENT_ID="node-hq-01"

# 3. Start systemd service
sudo cp garuda-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now garuda-agent
```

### Mode 2: Standalone USB Live Triage (Incident Response Forensics)
For plug-and-play forensic triage of compromised hosts without installing persistent dependencies.

```bash
# Run directly from mounted USB mount point:
cd /media/usb/garuda-agent
python3 -m garuda_agent.agent_main
```

### Mode 3: Air-Gapped Offline Collector (Classified / Non-Networked SCADA)
For isolated networks. Telemetry is written directly to the local SQLite database buffer (`/media/usb/almanac.db`).

```bash
export LOCAL_DB_PATH="/media/usb/garuda_almanac.db"
export AXIOM_URL="http://127.0.0.1:0" # Forces local offline buffering
python3 -m garuda_agent.agent_main
```
When reconnected to an ingestion node, the buffered SQLite database is ingested directly by running:
```bash
python3 -m garuda_agent.agent_main --sync-offline
```
