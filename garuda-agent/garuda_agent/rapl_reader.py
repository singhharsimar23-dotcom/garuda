"""
RAPL (Running Average Power Limit) Hardware Power Reader
Supports Intel RAPL (sysfs powercap) and AMD Energy (hwmon).
Gracefully degrades when hardware support or kernel modules are missing.
"""

import glob
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("garuda_agent.rapl")


class RAPLReader:
    """
    Reads hardware energy counters from sysfs and calculates power consumption in microWatts (μW).
    """

    def __init__(self):
        self.available: bool = False
        self.vendor: Optional[str] = None  # 'intel' or 'amd'
        self.pkg_paths: List[str] = []
        self.dram_paths: List[str] = []
        self.core_paths: List[str] = []
        
        # State tracking: path -> (last_reading_uj, last_timestamp, max_range_uj)
        self._last_state: Dict[str, Tuple[int, float, int]] = {}
        
        self._probe_channels()

    def _probe_channels(self) -> None:
        """
        Probe runtime sysfs paths for Intel and AMD energy counters.
        Never hardcodes specific device indexes.
        """
        # 1. Probe Intel RAPL via powercap
        intel_pkg_candidates = glob.glob("/sys/class/powercap/intel-rapl/intel-rapl:*/energy_uj")
        if intel_pkg_candidates:
            self.vendor = "intel"
            self.available = True
            for path in intel_pkg_candidates:
                parent_dir = os.path.dirname(path)
                name_file = os.path.join(parent_dir, "name")
                zone_name = ""
                if os.path.exists(name_file):
                    try:
                        with open(name_file, "r") as f:
                            zone_name = f.read().strip().lower()
                    except Exception as e:
                        logger.debug(f"Failed to read zone name from {name_file}: {e}")
                
                if "package" in zone_name or "pkg" in zone_name or not zone_name:
                    self.pkg_paths.append(path)
                elif "dram" in zone_name:
                    self.dram_paths.append(path)
                elif "core" in zone_name:
                    self.core_paths.append(path)
                else:
                    self.pkg_paths.append(path)

            # Look for subzones (e.g., DRAM / Core inside package)
            subzone_candidates = glob.glob("/sys/class/powercap/intel-rapl/intel-rapl:*/*/energy_uj")
            for sub_path in subzone_candidates:
                sub_dir = os.path.dirname(sub_path)
                sub_name_file = os.path.join(sub_dir, "name")
                sub_name = ""
                if os.path.exists(sub_name_file):
                    try:
                        with open(sub_name_file, "r") as f:
                            sub_name = f.read().strip().lower()
                    except Exception:
                        pass
                if "dram" in sub_name and sub_path not in self.dram_paths:
                    self.dram_paths.append(sub_path)
                elif "core" in sub_name and sub_path not in self.core_paths:
                    self.core_paths.append(sub_path)

            logger.info(
                f"Intel RAPL probed: {len(self.pkg_paths)} PKG, "
                f"{len(self.dram_paths)} DRAM, {len(self.core_paths)} CORE channels."
            )
            return

        # 2. Probe AMD energy counters via hwmon
        amd_candidates = glob.glob("/sys/class/hwmon/hwmon*/energy*_input") or glob.glob(
            "/sys/class/hwmon/hwmon*/power1_input"
        )
        if amd_candidates:
            self.vendor = "amd"
            self.available = True
            self.pkg_paths.extend(amd_candidates)
            logger.info(f"AMD Energy hwmon probed: {len(amd_candidates)} channels.")
            return

        # If not found, log warning and disable RAPL
        logger.warning(
            "No RAPL/hwmon powercap channels found on system. "
            "RAPL channel disabled (degraded mode)."
        )
        self.available = False

    def _get_max_energy_range(self, energy_path: str) -> int:
        """
        Read max_energy_range_uj from sysfs if available, otherwise default to 2^32.
        """
        parent_dir = os.path.dirname(energy_path)
        range_file = os.path.join(parent_dir, "max_energy_range_uj")
        if os.path.exists(range_file):
            try:
                with open(range_file, "r") as f:
                    return int(f.read().strip())
            except Exception as e:
                logger.debug(f"Failed to read max_energy_range_uj from {range_file}: {e}")
        return 2**32  # Standard 32-bit wrap default

    def _read_channel(self, path: str) -> Optional[float]:
        """
        Reads energy in μJ and calculates power in μW over the elapsed time interval.
        Handles counter rollover correctly.
        """
        now = time.monotonic()
        try:
            with open(path, "r") as f:
                content = f.read().strip()
                if not content:
                    return None
                current_uj = int(content)
        except PermissionError:
            logger.warning(f"Permission denied reading RAPL sysfs: {path}. Check read permissions.")
            return None
        except FileNotFoundError:
            logger.debug(f"RAPL sysfs path removed: {path}")
            return None
        except Exception as e:
            logger.warning(f"Error reading RAPL counter at {path}: {e}")
            return None

        if path not in self._last_state:
            max_range = self._get_max_energy_range(path)
            self._last_state[path] = (current_uj, now, max_range)
            return 0.0

        prev_uj, prev_time, max_range = self._last_state[path]
        delta_time = now - prev_time

        if delta_time <= 0.0:
            return 0.0

        # Calculate energy delta with rollover handling
        if current_uj >= prev_uj:
            delta_uj = current_uj - prev_uj
        else:
            # Counter rollover occurred
            delta_uj = (current_uj + max_range) - prev_uj
            logger.debug(f"RAPL counter wrap detected at {path}: prev={prev_uj}, cur={current_uj}, max={max_range}")

        # Power in μW = μJ / seconds
        power_uw = delta_uj / delta_time
        self._last_state[path] = (current_uj, now, max_range)
        return power_uw

    def read_package_power_uw(self) -> Optional[float]:
        """Read combined CPU package power consumption in μW."""
        if not self.available or not self.pkg_paths:
            return None
        powers = [self._read_channel(p) for p in self.pkg_paths]
        valid_powers = [p for p in powers if p is not None]
        return sum(valid_powers) if valid_powers else None

    def read_dram_power_uw(self) -> Optional[float]:
        """Read combined DRAM power consumption in μW."""
        if not self.available or not self.dram_paths:
            return None
        powers = [self._read_channel(p) for p in self.dram_paths]
        valid_powers = [p for p in powers if p is not None]
        return sum(valid_powers) if valid_powers else None

    def read_core_power_uw(self) -> Optional[float]:
        """Read combined CPU core power consumption in μW."""
        if not self.available or not self.core_paths:
            return None
        powers = [self._read_channel(p) for p in self.core_paths]
        valid_powers = [p for p in powers if p is not None]
        return sum(valid_powers) if valid_powers else None
