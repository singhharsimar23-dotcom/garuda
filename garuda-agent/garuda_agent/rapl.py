"""
RAPL Hardware Power Reader
Reads Intel Running Average Power Limit (RAPL) and AMD Energy/Power sysfs interfaces.
Follows strict runtime existence checks as per the Anti-Hallucination Charter.
"""

import glob
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("garuda_agent.rapl")

INTEL_RAPL_BASE = "/sys/class/powercap/intel-rapl"
AMD_HWMON_GLOB = "/sys/class/hwmon/hwmon*/power1_input"
AMD_HWMON_AVG_GLOB = "/sys/class/hwmon/hwmon*/power1_average"
DEFAULT_MAX_ENERGY_RANGE_UJ = 2**32  # Standard 32-bit uJ rollover if unspecified


class RAPLDomain:
    """Represents a discovered RAPL power domain."""

    def __init__(self, path: str, name: str, max_energy_range_uj: int = DEFAULT_MAX_ENERGY_RANGE_UJ):
        self.path = path
        self.name = name
        self.max_energy_range_uj = max_energy_range_uj
        self.last_energy_uj: Optional[int] = None
        self.last_timestamp: Optional[float] = None


class RAPLReader:
    """
    Reads hardware energy counters from sysfs and computes power consumption in Watts.
    Supports Intel RAPL (/sys/class/powercap/intel-rapl) and AMD hwmon fallbacks.
    """

    def __init__(self, base_path: str = INTEL_RAPL_BASE):
        self.base_path = base_path
        self.domains: Dict[str, RAPLDomain] = {}
        self.is_amd_fallback: bool = False
        self.amd_power_paths: List[str] = []
        self._discover_domains()

    def _discover_domains(self) -> None:
        """Discover RAPL domains or AMD hwmon power interfaces with existence checks."""
        self.domains.clear()
        self.amd_power_paths.clear()
        self.is_amd_fallback = False

        # 1. Check Intel RAPL sysfs existence
        if os.path.exists(self.base_path):
            # Discover top-level domains (intel-rapl:*) and subdomains (intel-rapl:*/* or intel-rapl:*:*)
            patterns = [
                os.path.join(self.base_path, "intel-rapl:*"),
                os.path.join(self.base_path, "intel-rapl:*", "intel-rapl:*:*"),
                os.path.join(self.base_path, "intel-rapl:*:*"),
            ]
            discovered_paths = set()
            for pattern in patterns:
                for path in glob.glob(pattern):
                    if os.path.exists(path):
                        discovered_paths.add(path)


            for domain_path in sorted(discovered_paths):
                energy_path = os.path.join(domain_path, "energy_uj")
                if not os.path.exists(energy_path):
                    continue

                # Read domain name
                name_path = os.path.join(domain_path, "name")
                domain_name = os.path.basename(domain_path)
                if os.path.exists(name_path):
                    try:
                        with open(name_path, "r", encoding="utf-8") as f:
                            read_name = f.read().strip()
                            if read_name:
                                domain_name = read_name
                    except (OSError, IOError) as e:
                        logger.warning(f"Failed to read RAPL domain name from {name_path}: {e}")

                # Read max energy range
                max_range = DEFAULT_MAX_ENERGY_RANGE_UJ
                max_range_path = os.path.join(domain_path, "max_energy_range_uj")
                if os.path.exists(max_range_path):
                    try:
                        with open(max_range_path, "r", encoding="utf-8") as f:
                            val_str = f.read().strip()
                            if val_str.isdigit():
                                max_range = int(val_str)
                    except (OSError, IOError, ValueError) as e:
                        logger.warning(f"Failed to read max_energy_range_uj from {max_range_path}: {e}")

                self.domains[domain_path] = RAPLDomain(
                    path=domain_path,
                    name=domain_name,
                    max_energy_range_uj=max_range,
                )

        if self.domains:
            logger.info(f"Discovered {len(self.domains)} Intel RAPL domain(s): {[d.name for d in self.domains.values()]}")
            return

        # 2. Check AMD hwmon fallback
        amd_matches = glob.glob(AMD_HWMON_GLOB) + glob.glob(AMD_HWMON_AVG_GLOB)
        valid_amd = [p for p in amd_matches if os.path.exists(p)]
        if valid_amd:
            self.is_amd_fallback = True
            self.amd_power_paths = valid_amd
            logger.info(f"Using AMD hwmon power fallback with paths: {self.amd_power_paths}")

    @property
    def available(self) -> bool:
        """Check if any power telemetry interface is currently available."""
        return bool(self.domains or (self.is_amd_fallback and self.amd_power_paths))

    def read(self) -> Tuple[Dict[str, float], List[str], Dict[str, float]]:
        """
        Read power consumption across domains.
        Returns:
            - standard_payload: {"pkg_w": float, "dram_w": float, "core_w": float, "unavailable": bool}
            - flags: List of warning/status flags (e.g. ["RAPL_UNAVAILABLE"])
            - raw_by_domain: Detailed mapping of domain_name -> watts
        """
        # Re-check existence if previously empty
        if not self.available:
            self._discover_domains()

        if not self.available:
            return (
                {"pkg_w": 0.0, "dram_w": 0.0, "core_w": 0.0, "unavailable": True},
                ["RAPL_UNAVAILABLE"],
                {},
            )

        raw_by_domain: Dict[str, float] = {}
        now = time.monotonic()

        # Case A: Intel RAPL
        if self.domains:
            for domain_path, domain in self.domains.items():
                energy_path = os.path.join(domain_path, "energy_uj")
                if not os.path.exists(energy_path):
                    logger.warning(f"RAPL path disappeared: {energy_path}")
                    continue

                try:
                    with open(energy_path, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    current_energy_uj = int(content)
                except ValueError:
                    logger.warning(f"Corrupt non-integer energy_uj at {energy_path}: '{content}'")
                    continue
                except (OSError, IOError) as e:
                    logger.warning(f"Failed to read energy_uj at {energy_path}: {e}")
                    continue

                if domain.last_energy_uj is not None and domain.last_timestamp is not None:
                    delta_time = now - domain.last_timestamp
                    if delta_time > 0:
                        delta_energy = current_energy_uj - domain.last_energy_uj
                        # Handle counter wraparound
                        if delta_energy < 0:
                            delta_energy += domain.max_energy_range_uj

                        # Power in Watts = (uJ / s) / 1_000_000
                        watts = (delta_energy / delta_time) / 1_000_000.0
                        raw_by_domain[domain.name] = max(0.0, round(watts, 4))
                    else:
                        raw_by_domain[domain.name] = 0.0
                else:
                    # Baseline initialization sample
                    raw_by_domain[domain.name] = 0.0

                domain.last_energy_uj = current_energy_uj
                domain.last_timestamp = now

        # Case B: AMD hwmon fallback
        elif self.is_amd_fallback:
            for path in self.amd_power_paths:
                if not os.path.exists(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        val_str = f.read().strip()
                    # hwmon power1_input is in microwatts
                    microwatts = int(val_str)
                    watts = microwatts / 1_000_000.0
                    raw_by_domain["package-0"] = max(0.0, round(watts, 4))
                except (OSError, IOError, ValueError) as e:
                    logger.warning(f"Failed reading AMD hwmon power at {path}: {e}")

        # Map to standard required domains: package-0 (rapl_pkg), dram (rapl_dram), core (rapl_core)
        pkg_w = 0.0
        dram_w = 0.0
        core_w = 0.0

        for name, watts in raw_by_domain.items():
            name_lower = name.lower()
            if "package" in name_lower or "pkg" in name_lower:
                pkg_w = max(pkg_w, watts)
            elif "dram" in name_lower or "memory" in name_lower:
                dram_w = max(dram_w, watts)
            elif "core" in name_lower:
                core_w = max(core_w, watts)

        # If only 1 domain exists and it is the package, report it
        if pkg_w == 0.0 and len(raw_by_domain) == 1:
            pkg_w = list(raw_by_domain.values())[0]

        payload = {
            "pkg_w": round(pkg_w, 4),
            "dram_w": round(dram_w, 4),
            "core_w": round(core_w, 4),
            "unavailable": False,
        }
        flags: List[str] = []
        return payload, flags, raw_by_domain
