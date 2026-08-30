"""
Linux Kernel Scheduler Statistics Reader
Parses /proc/schedstat to measure CPU run time, run delay (waiting time), and context switches.
"""

import logging
import os
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("garuda_agent.schedstat")


class SchedstatReader:
    """
    Tracks kernel scheduler run delay, execution time, and timeslices.
    High run delay relative to runtime indicates scheduling bottlenecks or micro-burst evasion.
    """

    def __init__(self, sysfs_path: str = "/proc/schedstat"):
        self.sysfs_path = sysfs_path
        self.available = os.path.exists(self.sysfs_path)
        self._last_state: Optional[Tuple[int, int, int, float]] = None  # (run_ns, wait_ns, pcount, time)

        if not self.available:
            logger.warning(f"Scheduler statistics path '{self.sysfs_path}' not found. Schedstat channel disabled.")

    def read_schedstat(self) -> Dict[str, Optional[float]]:
        """
        Reads /proc/schedstat and computes rates:
        - run_time_ms_per_sec: CPU running time in milliseconds per elapsed second
        - wait_time_ms_per_sec: CPU runnable waiting time in milliseconds per elapsed second
        - context_switches_per_sec: context switch rate
        - run_delay_ratio: wait_time / (run_time + wait_time)
        """
        default_res: Dict[str, Optional[float]] = {
            "run_time_ms_per_sec": None,
            "wait_time_ms_per_sec": None,
            "context_switches_per_sec": None,
            "run_delay_ratio": None,
        }

        if not self.available or not os.path.exists(self.sysfs_path):
            return default_res

        try:
            total_run_ns = 0
            total_wait_ns = 0
            total_pcount = 0

            with open(self.sysfs_path, "r") as f:
                for line in f:
                    # CPU lines format: cpu<N> <yield_count> <sched_count> <pcount> <sum_exec_runtime_ns> <sum_run_delay_ns> <sum_slice_ns>
                    if line.startswith("cpu"):
                        parts = line.split()
                        if len(parts) >= 6:
                            # parts[3]: pcount (tasks run), parts[4]: exec runtime (ns), parts[5]: run delay (ns)
                            pcount = int(parts[3])
                            exec_runtime_ns = int(parts[4])
                            run_delay_ns = int(parts[5])
                            
                            total_pcount += pcount
                            total_run_ns += exec_runtime_ns
                            total_wait_ns += run_delay_ns

            now = time.monotonic()
            if self._last_state is None:
                self._last_state = (total_run_ns, total_wait_ns, total_pcount, now)
                return {
                    "run_time_ms_per_sec": 0.0,
                    "wait_time_ms_per_sec": 0.0,
                    "context_switches_per_sec": 0.0,
                    "run_delay_ratio": 0.0,
                }

            prev_run_ns, prev_wait_ns, prev_pcount, prev_time = self._last_state
            dt = now - prev_time
            if dt <= 0.0:
                return default_res

            delta_run_ns = max(0, total_run_ns - prev_run_ns)
            delta_wait_ns = max(0, total_wait_ns - prev_wait_ns)
            delta_pcount = max(0, total_pcount - prev_pcount)

            # Convert nanoseconds to milliseconds per second
            run_ms_per_sec = (delta_run_ns / 1_000_000.0) / dt
            wait_ms_per_sec = (delta_wait_ns / 1_000_000.0) / dt
            pcount_per_sec = delta_pcount / dt

            denom = delta_run_ns + delta_wait_ns
            delay_ratio = (delta_wait_ns / denom) if denom > 0 else 0.0

            self._last_state = (total_run_ns, total_wait_ns, total_pcount, now)

            return {
                "run_time_ms_per_sec": run_ms_per_sec,
                "wait_time_ms_per_sec": wait_ms_per_sec,
                "context_switches_per_sec": pcount_per_sec,
                "run_delay_ratio": delay_ratio,
            }
        except Exception as e:
            logger.warning(f"Error parsing schedstat from {self.sysfs_path}: {e}")
            return default_res
