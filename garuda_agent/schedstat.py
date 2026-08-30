"""
Linux /proc/schedstat Telemetry Reader
Parses kernel CPU scheduler statistics (version 15) to detect abnormal CPU steal/wait ratios.
Prefixes all file reads with existence checks as mandated by the Anti-Hallucination Charter.
"""

import logging
import os
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("garuda_agent.schedstat")

SCHEDSTAT_PATH = "/proc/schedstat"
ELEVATED_STEAL_THRESHOLD = 0.15


class SchedstatReader:
    """
    Parses /proc/schedstat to compute CPU scheduler wait/steal latency ratio.
    """

    def __init__(self, path: str = SCHEDSTAT_PATH):
        self.path = path
        self.last_running_ns: Optional[int] = None
        self.last_waiting_ns: Optional[int] = None
        self.last_timeslices: Optional[int] = None
        self.last_timestamp: Optional[float] = None

    def read(self) -> Tuple[Dict[str, float], List[str]]:
        """
        Read scheduler statistics across all CPUs and compute steal ratio.
        Returns:
            - payload: {"steal_ratio": float}
            - flags: List of flags (e.g. ["ELEVATED_STEAL"])
        """
        now = time.monotonic()
        if not os.path.exists(self.path):
            return {"steal_ratio": 0.0}, []

        running_total_ns = 0
        waiting_total_ns = 0
        timeslices_total = 0

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if not parts:
                        continue
                    # Lines starting with 'cpu<N>'
                    # Version 15 format:
                    # cpu<N> yld_count ... (field 7: running_time_ns, field 8: waiting_time_ns, field 9: timeslices)
                    if parts[0].startswith("cpu") and len(parts) >= 10:
                        try:
                            # In /proc/schedstat v15:
                            # parts[7]: total time running on cpu (ns)
                            # parts[8]: total time waiting for cpu (ns)
                            # parts[9]: total timeslices executed
                            running = int(parts[7])
                            waiting = int(parts[8])
                            tslices = int(parts[9])
                            running_total_ns += running
                            waiting_total_ns += waiting
                            timeslices_total += tslices
                        except (ValueError, IndexError):
                            continue
        except (OSError, IOError) as e:
            logger.warning(f"Error reading schedstat from {self.path}: {e}")
            return {"steal_ratio": 0.0}, []

        steal_ratio = 0.0
        flags = []

        if (
            self.last_running_ns is not None
            and self.last_waiting_ns is not None
        ):
            delta_running = max(0, running_total_ns - self.last_running_ns)
            delta_waiting = max(0, waiting_total_ns - self.last_waiting_ns)
            total_active = delta_running + delta_waiting

            if total_active > 0:
                steal_ratio = round(delta_waiting / total_active, 4)
            else:
                steal_ratio = 0.0

            if steal_ratio > ELEVATED_STEAL_THRESHOLD:
                flags.append("ELEVATED_CPU_STEAL")

        self.last_running_ns = running_total_ns
        self.last_waiting_ns = waiting_total_ns
        self.last_timeslices = timeslices_total
        self.last_timestamp = now

        payload = {"steal_ratio": steal_ratio}
        return payload, flags
