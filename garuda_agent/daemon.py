"""
GARUDA Host Telemetry Daemon
Main loop, signal management, exact frequency sensor polling, and payload dispatch.
"""

import argparse
from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import socket
import sys
import time
import uuid
from typing import Any, Dict, List, Optional
try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Python 3.6-3.10 with tomli
    except ImportError:
        try:
            import toml as tomllib  # toml library
        except ImportError:
            tomllib = None

from garuda_agent.buffer import LocalBuffer
from garuda_agent.entropy import EntropyReader
from garuda_agent.ias import IASComputer
from garuda_agent.perf import PerfReader
from garuda_agent.rapl import RAPLReader
from garuda_agent.schedstat import SchedstatReader
from garuda_agent.streamer import TelemetryStreamer
from garuda_agent.tpm import TPMReader

logger = logging.getLogger("garuda_agent.daemon")

DEFAULT_CONFIG_PATH = "/etc/garuda/config.toml"
DEFAULT_AGENT_ID_PATH = "/etc/garuda/agent_id"
DEFAULT_BUFFER_PATH = "/var/lib/garuda/buffer.db"
DEFAULT_LOG_PATH = "/var/log/garuda-agent.log"


def setup_logging(log_path: str = DEFAULT_LOG_PATH, verbose: bool = False) -> None:
    """Setup rotating log file handler (100MB rotation) and console stream handler."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File Handler
    log_dir = os.path.dirname(log_path)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            pass

    try:
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=100 * 1024 * 1024,  # 100 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except OSError as e:
        logger.warning(f"Could not open log file {log_path} for writing: {e}. Using console only.")


def get_or_create_agent_id(path: str = DEFAULT_AGENT_ID_PATH) -> str:
    """Retrieve or generate persistent UUID4 agent identifier."""
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                aid = f.read().strip()
                if aid:
                    return aid
        except OSError as e:
            logger.warning(f"Failed reading agent ID from {path}: {e}")

    new_id = str(uuid.uuid4())
    id_dir = os.path.dirname(path)
    if id_dir and not os.path.exists(id_dir):
        try:
            os.makedirs(id_dir, exist_ok=True)
        except OSError:
            pass

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_id + "\n")
    except OSError as e:
        logger.warning(f"Could not persist agent ID to {path}: {e}")

    return new_id


class GarudaDaemon:
    """
    Core telemetry daemon orchestrating hardware sensors, IAS anomaly detection, and streaming.
    """

    def __init__(
        self,
        config_path: str = DEFAULT_CONFIG_PATH,
        dry_run: bool = False,
        once: bool = False,
    ):
        self.config_path = config_path
        self.dry_run = dry_run
        self.once = once
        self.running = False
        self.reload_requested = False

        # Load configuration
        self.config = self._load_config()
        self.agent_id = get_or_create_agent_id(self.config.get("agent_id_path", DEFAULT_AGENT_ID_PATH))
        self.hostname = socket.gethostname()

        # Initialize hardware readers
        self.rapl_reader = RAPLReader()
        self.perf_reader = PerfReader()
        self.entropy_reader = EntropyReader()
        self.schedstat_reader = SchedstatReader()
        self.tpm_reader = TPMReader()
        self.ias_computer = IASComputer()

        # Buffer & Streamer
        buffer_path = self.config.get("buffer_db_path", DEFAULT_BUFFER_PATH)
        self.buffer = LocalBuffer(db_path=buffer_path)
        self.streamer = TelemetryStreamer(
            axiom_host=self.config.get("axiom_host", "localhost:8000"),
            agent_api_key=self.config.get("agent_api_key", ""),
            buffer=self.buffer,
        )

        self._setup_signals()

    def _load_config(self) -> Dict[str, Any]:
        """Load TOML configuration file if exists, or return defaults."""
        defaults = {
            "axiom_host": "axiom.garuda-defense.org",
            "agent_api_key": "GARUDA_DEFAULT_API_KEY",
            "poll_hz": 1,
            "conflict_mode_hz": 10,
            "conflict_mode": False,
            "buffer_db_path": DEFAULT_BUFFER_PATH,
            "agent_id_path": DEFAULT_AGENT_ID_PATH,
            "log_file": DEFAULT_LOG_PATH,
        }

        if os.path.exists(self.config_path):
            try:
                if tomllib is not None:
                    with open(self.config_path, "rb") as f:
                        if hasattr(tomllib, "load"):
                            loaded = tomllib.load(f)
                        elif hasattr(tomllib, "loads"):
                            loaded = tomllib.loads(f.read().decode("utf-8"))
                        else:
                            loaded = {}
                else:
                    # Simple fallback parser for basic key = value
                    loaded = {}
                    with open(self.config_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                k = k.strip()
                                v = v.strip().strip('"').strip("'")
                                if v.lower() == "true":
                                    v = True
                                elif v.lower() == "false":
                                    v = False
                                elif v.isdigit():
                                    v = int(v)
                                loaded[k] = v
                defaults.update(loaded)
                logger.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.error(f"Error loading configuration from {self.config_path}: {e}")
        else:

            logger.warning(f"Config file {self.config_path} not found; using defaults / environment.")
        return defaults

    def _setup_signals(self) -> None:
        """Register POSIX signal handlers."""
        try:
            signal.signal(signal.SIGINT, self._handle_term)
            signal.signal(signal.SIGTERM, self._handle_term)
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, self._handle_hup)
        except (ValueError, AttributeError) as e:
            logger.debug(f"Signal registration limited on this platform: {e}")

    def _handle_term(self, signum, frame) -> None:
        logger.info(f"Received signal {signum}. Initiating graceful shutdown...")
        self.running = False

    def _handle_hup(self, signum, frame) -> None:
        logger.info("Received SIGHUP. Reloading configuration...")
        self.reload_requested = True

    def collect_payload(self) -> Dict[str, Any]:
        """Collect all sensor telemetry and compute IAS score."""
        all_flags: List[str] = []

        # 1. RAPL
        rapl_payload, rapl_flags, _ = self.rapl_reader.read()
        all_flags.extend(rapl_flags)

        # 2. Perf
        perf_payload, perf_flags = self.perf_reader.read()
        all_flags.extend(perf_flags)

        # 3. Entropy
        entropy_payload, entropy_flags = self.entropy_reader.read()
        all_flags.extend(entropy_flags)

        # 4. Schedstat
        schedstat_payload, schedstat_flags = self.schedstat_reader.read()
        all_flags.extend(schedstat_flags)

        # 5. IAS computation
        ias_payload, ias_flags = self.ias_computer.compute(
            rapl=rapl_payload,
            perf=perf_payload,
            entropy=entropy_payload,
            schedstat=schedstat_payload,
        )
        all_flags.extend(ias_flags)

        # Conflict mode check
        conflict_mode = bool(self.config.get("conflict_mode", False))
        if conflict_mode:
            all_flags.append("CONFLICT_MODE")

        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "rapl": rapl_payload,
            "perf": perf_payload,
            "entropy": entropy_payload,
            "schedstat": schedstat_payload,
            "ias": ias_payload,
            "flags": sorted(list(set(all_flags))),
        }
        return payload

    def run(self) -> None:
        """Main daemon loop."""
        self.running = True
        logger.info(f"Starting GARUDA telemetry daemon (agent_id={self.agent_id}, dry_run={self.dry_run})")

        while self.running:
            if self.reload_requested:
                self.config = self._load_config()
                self.streamer.agent_api_key = self.config.get("agent_api_key", self.streamer.agent_api_key)
                self.streamer.axiom_host = self.config.get("axiom_host", self.streamer.axiom_host)
                self.reload_requested = False

            t_start = time.monotonic()
            payload = self.collect_payload()

            if self.dry_run:
                print(json.dumps(payload, indent=2))
            else:
                self.streamer.send(payload)

            if self.once:
                break

            # Exact Hz timing
            conflict_mode = bool(self.config.get("conflict_mode", False))
            target_hz = int(self.config.get("conflict_mode_hz", 10) if conflict_mode else self.config.get("poll_hz", 1))
            interval = 1.0 / max(1, target_hz)

            t_elapsed = time.monotonic() - t_start
            sleep_time = max(0.0, interval - t_elapsed)
            if sleep_time > 0 and self.running:
                time.sleep(sleep_time)

        self._shutdown()

    def _shutdown(self) -> None:
        """Flush buffer and release file descriptors."""
        logger.info("Cleaning up daemon resources...")
        self.perf_reader.close()
        if not self.dry_run and self.buffer.count() > 0:
            logger.info("Flushing local buffer before shutdown...")
            try:
                self.streamer.flush_buffer()
            except Exception as e:
                logger.warning(f"Error flushing buffer during shutdown: {e}")
        logger.info("Daemon stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="GARUDA Host Telemetry Agent Daemon")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to config.toml")
    parser.add_argument("--once", action="store_true", help="Collect a single telemetry reading and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print collected payload to stdout without POSTing")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    daemon = GarudaDaemon(
        config_path=args.config,
        dry_run=args.dry_run,
        once=args.once,
    )
    daemon.run()


if __name__ == "__main__":
    main()
