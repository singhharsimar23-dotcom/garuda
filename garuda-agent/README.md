# GARUDA Host Telemetry Daemon (`garuda_agent`)

Production-grade hardware physics & kernel execution telemetry daemon for the **GARUDA** platform. Runs as a root systemd service on monitored Linux hosts (NIC/DRDO/MoD servers) and streams high-precision hardware physics telemetry to **AXIOM-II** on Render.com.

---

## Architecture & Monitored Channels

The daemon samples physical hardware state and kernel counters at 1 Hz (normal mode) or 10 Hz (conflict mode):

1. **Intel RAPL / AMD Power (`rapl.py`)**
   - Discovers domains via `/sys/class/powercap/intel-rapl` (`package-0`, `dram`, `core`)
   - Handles 32-bit hardware rollover and AMD `hwmon` fallback
   - Power computation: `delta_energy_uJ / delta_time_s / 1_000_000` (Watts)

2. **Hardware Performance Counters (`perf.py`)**
   - Direct x86_64/aarch64 `perf_event_open` syscalls via `ctypes`
   - Monitors: `PERF_COUNT_HW_INSTRUCTIONS`, `PERF_COUNT_HW_CACHE_MISSES`, `PERF_COUNT_HW_CPU_CYCLES`
   - Gracefully handles `EACCES` or missing kernel perf permissions

3. **Kernel Entropy Monitor (`entropy.py`)**
   - Monitors `/proc/sys/kernel/random/entropy_avail`
   - Flags sustained drops (<512 bits) and critical covert channel depletion (<128 bits, APT36 signature)

4. **Scheduler Steal & Latency (`schedstat.py`)**
   - Parses `/proc/schedstat` (v15) across all CPUs
   - Computes steal/wait ratio `waiting / (running + waiting)` to detect hidden container CPU stealing (>0.15)

5. **TPM 2.0 PCR Integrity (`tpm.py`)**
   - Subprocess wrapper for `tpm2_pcrread` over `/dev/tpmrm0`

6. **Integrated Anomaly Score Engine (`ias.py`)**
   - Weighted multi-channel Gaussian Kullback-Leibler (KL) divergence
   - K-Means ($k=4$) dynamic workload clustering: `IDLE`, `WEB_SERVER`, `DATABASE`, `BATCH`
   - **Contamination Prevention**: Baselines are locked and NOT updated when $IAS \ge 1.5$
   - Thresholds: Log $\ge 1.5$, Medium $\ge 3.0$, Critical $\ge 5.0$

7. **Resilient HTTP Streaming & SQLite Buffer (`streamer.py`, `buffer.py`)**
   - Streams payloads via HTTP POST `Authorization: Bearer <AGENT_KEY>`
   - Exponential backoff: `1s, 2s, 4s, 8s, 16s`
   - Offline SQLite buffer: max 10,000 FIFO records at `/var/lib/garuda/buffer.db`
   - Automatic buffer drain on reconnection
   - `401 Unauthorized` handling: emits `AGENT_KEY_REJECTED` and alerts syslog

---

## Installation

```bash
cd garuda-agent
pip install -e .
```

### Dependencies
- Python 3.9+
- `toml`
- `httpx`
- `numpy`
- `scikit-learn`

---

## Configuration (`/etc/garuda/config.toml`)

```toml
axiom_host = "axiom.garuda-defense.org"
agent_api_key = "GARUDA_SECURE_API_TOKEN"
poll_hz = 1
conflict_mode_hz = 10
conflict_mode = false
buffer_db_path = "/var/lib/garuda/buffer.db"
agent_id_path = "/etc/garuda/agent_id"
log_file = "/var/log/garuda-agent.log"
```

---

## Running the Daemon

```bash
# Single test shot
garuda-agent --dry-run --once

# Verbose daemon run
garuda-agent --config /etc/garuda/config.toml --verbose
```

---

## Systemd Service Installation

Generate and install the hardened systemd unit file:

```bash
sudo garuda-service --output /etc/systemd/system/garuda-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now garuda-agent
```
