"""
GARUDA Host Agent Main Loop & Orchestrator
Continuously samples host physical telemetry, coordinates channels, and handles process lifecycle signals.
"""

import logging
import signal
import sys
import time
from typing import Any, Dict, Optional

from .config import AgentConfig, get_config
from .entropy_reader import EntropyReader
from .eppi_loader import EPPILoader
from .local_almanac import LocalAlmanac
from .perf_reader import PerfReader
from .rapl_reader import RAPLReader
from .schedstat_reader import SchedstatReader
from .telemetry_batcher import TelemetryBatcher
from .tpm_reader import TPMReader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("garuda_agent.main")


class GarudaAgent:
    """
    Main agent orchestration service.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or get_config()
        self.running = False
        self.poll_interval = self.config.poll_interval_sec
        self.almanac = LocalAlmanac(self.config.local_db_path)
        self.batcher = TelemetryBatcher(self.config, self.almanac)

        # Initialize readers according to feature flags
        self.rapl = RAPLReader() if self.config.rapl_enabled else None
        self.perf = PerfReader() if self.config.perf_enabled else None
        self.entropy = EntropyReader() if self.config.entropy_enabled else None
        self.tpm = TPMReader() if self.config.tpm_enabled else None
        self.schedstat = SchedstatReader() if self.config.schedstat_enabled else None
        self.eppi = EPPILoader() if self.config.eppi_enabled else None

        self.last_tpm_time = 0.0
        self.last_purge_time = 0.0
        self.tpm_interval_sec = 3600.0  # 1 hour
        self.purge_interval_sec = 86400.0  # 24 hours

        self._setup_signals()

    def _setup_signals(self) -> None:
        """Register signal handlers for termination and on-demand integrity triggers."""
        try:
            signal.signal(signal.SIGINT, self._handle_shutdown_signal)
            signal.signal(signal.SIGTERM, self._handle_shutdown_signal)
            # SIGUSR1 is Unix-only
            if hasattr(signal, "SIGUSR1"):
                signal.signal(signal.SIGUSR1, self._handle_usr1_signal)
        except Exception as e:
            logger.debug(f"Signal setup warning: {e}")

    def _handle_shutdown_signal(self, signum, frame) -> None:
        logger.info(f"Received signal {signum}. Initiating graceful shutdown and flushing buffer...")
        self.running = False

    def _handle_usr1_signal(self, signum, frame) -> None:
        logger.info("Received SIGUSR1. Forcing immediate TPM snapshot and telemetry flush...")
        self._sample_tpm_snapshot(force=True)
        self.batcher.flush()

    def sample_channels(self) -> Dict[str, Any]:
        """
        Samples all active telemetry channels and returns a unified observation record.
        """
        now = time.time()
        obs: Dict[str, Any] = {
            "timestamp": now,
            "agent_id": self.config.agent_id,
            "hostname": self.config.hostname,
        }

        # 1. RAPL Channel
        if self.rapl and self.rapl.available:
            obs["rapl_pkg_uw"] = self.rapl.read_package_power_uw()
            obs["rapl_dram_uw"] = self.rapl.read_dram_power_uw()
            obs["rapl_core_uw"] = self.rapl.read_core_power_uw()
        else:
            obs["rapl_pkg_uw"] = None
            obs["rapl_dram_uw"] = None
            obs["rapl_core_uw"] = None

        # 2. Perf Counters Channel
        if self.perf and self.perf.available:
            perf_data = self.perf.read_metrics(duration_sec=0.1)
            obs["instructions"] = perf_data.get("instructions")
            obs["cache_misses"] = perf_data.get("cache_misses")
            obs["cycles"] = perf_data.get("cycles")
            obs["ipc"] = perf_data.get("ipc")
        else:
            obs["instructions"] = None
            obs["cache_misses"] = None
            obs["cycles"] = None
            obs["ipc"] = None

        # 3. Entropy Channel
        if self.entropy and self.entropy.available:
            obs["entropy_avail"] = self.entropy.read_entropy_bits()
        else:
            obs["entropy_avail"] = None

        # 4. Schedstat Channel
        if self.schedstat and self.schedstat.available:
            sched_data = self.schedstat.read_schedstat()
            obs["sched_run_ms_per_sec"] = sched_data.get("run_time_ms_per_sec")
            obs["sched_wait_ms_per_sec"] = sched_data.get("wait_time_ms_per_sec")
            obs["sched_delay_ratio"] = sched_data.get("run_delay_ratio")
        else:
            obs["sched_run_ms_per_sec"] = None
            obs["sched_wait_ms_per_sec"] = None
            obs["sched_delay_ratio"] = None

        # 5. EPPI eBPF Events
        if self.eppi and self.eppi.enabled:
            obs["eppi_events"] = self.eppi.read_events()
        else:
            obs["eppi_events"] = []

        return obs

    def _sample_tpm_snapshot(self, force: bool = False) -> Optional[Dict[str, str]]:
        now = time.time()
        if self.tpm and self.tpm.available and (force or (now - self.last_tpm_time) >= self.tpm_interval_sec):
            self.last_tpm_time = now
            pcrs = self.tpm.read_pcrs()
            if pcrs:
                logger.info(f"TPM 2.0 PCR snapshot captured: {pcrs}")
                return pcrs
        return None

    def process_response(self, response: Dict[str, Any]) -> None:
        """
        Processes server response from AXIOM (e.g. updating poll interval or intensification).
        """
        if not response:
            return
        
        status = response.get("status")
        ias_level = response.get("anomaly_level", "CLEAN")
        new_poll = response.get("recommended_poll_interval_sec")
        
        if new_poll and isinstance(new_poll, (int, float)) and new_poll > 0:
            if new_poll != self.poll_interval:
                logger.info(f"Updating agent poll interval: {self.poll_interval}s -> {new_poll}s (IAS level: {ias_level})")
                self.poll_interval = float(new_poll)

        if ias_level in ("MEDIUM", "CRITICAL"):
            logger.warning(f"AXIOM Anomaly Detected on host: Level={ias_level}, Score={response.get('ias_score')}")

    def run(self, max_iterations: Optional[int] = None) -> None:
        """
        Starts the telemetry collection loop.
        """
        self.running = True
        logger.info(f"Starting GARUDA Agent (ID: {self.config.agent_id}, Target: {self.config.axiom_url})")
        
        # Initial boot TPM reading
        self._sample_tpm_snapshot(force=True)

        iterations = 0
        while self.running:
            start_t = time.time()

            try:
                # 1. Sample all channels
                obs = self.sample_channels()
                
                # Check TPM periodic timer
                tpm_state = self._sample_tpm_snapshot()
                if tpm_state:
                    obs["tpm_pcrs"] = tpm_state

                # 2. Add to batcher
                response = self.batcher.add_reading(obs)
                if response:
                    self.process_response(response)

                # Periodic purge check (daily)
                if (now := time.time()) - self.last_purge_time >= self.purge_interval_sec:
                    self.last_purge_time = now
                    self.almanac.purge_old_records()

            except Exception as e:
                logger.error(f"Unexpected error in agent sampling loop: {e}", exc_info=True)

            iterations += 1
            if max_iterations and iterations >= max_iterations:
                break

            # Sleep remaining time to maintain target rate
            elapsed = time.time() - start_t
            sleep_time = max(0.05, self.poll_interval - elapsed)
            time.sleep(sleep_time)

        # Shutdown flush
        logger.info("Flushing final telemetry before shutdown...")
        self.batcher.flush()
        logger.info("GARUDA Agent stopped cleanly.")


def main():
    agent = GarudaAgent()
    agent.run()


if __name__ == "__main__":
    main()
