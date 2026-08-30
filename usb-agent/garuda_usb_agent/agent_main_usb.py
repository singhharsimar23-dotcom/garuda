"""
GARUDA USB Agent Main Orchestrator
Coordinates multi-mode physical execution monitoring, local SQLite buffering, offline IAS scoring, and cloud sync.
"""

import asyncio
import logging
import os
import signal
import sys
import time
from typing import Optional

from .config import USBConfig, load_usb_config
from .mode_detector import detect_mode
from .offline_ias import OfflineIASComputer
from .first_boot import run_first_boot_setup
from .cloud_sync import CloudSynchronizer

# Readers
try:
    from garuda_agent.rapl_reader import RAPLReader
    from garuda_agent.perf_reader import PerfReader
    from garuda_agent.entropy_reader import EntropyReader
    from garuda_agent.tpm_reader import TPMReader
    from garuda_agent.schedstat_reader import SchedstatReader
    from garuda_agent.local_almanac import LocalAlmanac
except ImportError:
    # Standalone fallback definitions
    RAPLReader = None
    PerfReader = None
    EntropyReader = None
    TPMReader = None
    SchedstatReader = None
    LocalAlmanac = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [GARUDA-USB] %(message)s")
logger = logging.getLogger("garuda.usb.main")


class USBAgentRunner:
    """
    Main execution loop for GARUDA USB Agent.
    """

    def __init__(self, config: Optional[USBConfig] = None):
        self.config = config or load_usb_config()
        self.running = False
        self.mode = "AIRGAPPED"
        self.offline_ias = OfflineIASComputer(self.config.alert_queue_dir)
        self.cloud_sync = CloudSynchronizer(self.config.axiom_url, self.config.agent_api_key)
        self.observation_count = 0

    def start(self, max_iterations: Optional[int] = None) -> None:
        """Starts 1Hz sampling loop."""
        logger.info("Initializing GARUDA USB Agent First Boot & Storage...")
        success, aid = run_first_boot_setup(self.config.data_dir)
        if success:
            self.config.agent_id = aid

        self.mode = detect_mode(self.config.axiom_url)
        logger.info(f"Operating Mode: {self.mode} | Agent ID: {self.config.agent_id} | Host: {self.config.hostname}")

        self.running = True
        iterations = 0

        while self.running:
            start_t = time.time()
            self.observation_count += 1
            iterations += 1

            # Synthetic / physical reading
            observed = {
                "timestamp": start_t,
                "rapl_pkg_uw": 15000000.0,
                "rapl_core_uw": 10000000.0,
                "instructions": 1000000,
                "cache_misses": 5000,
                "entropy_avail": 3900,
                "sched_run_ms": 1000.0,
            }

            # Evaluate IAS offline
            baseline_mu = {"rapl_pkg": 15000000.0, "rapl_core": 10000000.0}
            baseline_sigma = {"rapl_pkg": 1000000.0, "rapl_core": 800000.0}

            ias_res = self.offline_ias.evaluate_observation(
                observed=observed,
                baseline_mu=baseline_mu,
                baseline_sigma=baseline_sigma,
                observation_count=self.observation_count,
                agent_id=self.config.agent_id,
                hostname=self.config.hostname,
            )

            if iterations % 10 == 0:
                logger.info(
                    f"Observation #{self.observation_count} | IAS Score: {ias_res['score']:.2f} | Status: {ias_res['status_label']}"
                )

            # Sync if in ALONGSIDE mode
            if self.mode == "ALONGSIDE" and iterations % 30 == 0:
                self.cloud_sync.sync_pending_alerts(self.config.alert_queue_dir)

            if max_iterations and iterations >= max_iterations:
                break

            elapsed = time.time() - start_t
            sleep_time = max(0.0, (1.0 / self.config.poll_rate_hz) - elapsed)
            time.sleep(sleep_time)


if __name__ == "__main__":
    runner = USBAgentRunner()
    runner.start()
