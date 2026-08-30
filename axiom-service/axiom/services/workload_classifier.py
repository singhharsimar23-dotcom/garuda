"""
Workload Classifier
Classifies incoming host execution telemetry into distinct architectural workload classes.
"""

from typing import Any, Dict
from ..models.telemetry import WorkloadClass


def classify_workload(observation: Dict[str, Any]) -> WorkloadClass:
    """
    Infers the active workload class (IDLE, COMPUTE_BOUND, MEMORY_BOUND, IO_BOUND, MIXED)
    from hardware performance metrics and kernel scheduler delays.
    """
    ipc = observation.get("ipc")
    instructions = observation.get("instructions")
    cache_misses = observation.get("cache_misses")
    sched_run_ms = observation.get("sched_run_ms_per_sec") or observation.get("sched_run_ms")
    sched_delay = observation.get("sched_delay_ratio")

    # 1. Idle Detection: Very low run time or negligible IPC
    if sched_run_ms is not None and sched_run_ms < 50.0:
        return WorkloadClass.IDLE
    if ipc is not None and ipc < 0.25 and (sched_run_ms is None or sched_run_ms < 150.0):
        return WorkloadClass.IDLE

    # 2. Memory-Bound Detection: High cache miss ratio
    if instructions and cache_misses and instructions > 0:
        miss_ratio = cache_misses / instructions
        if miss_ratio > 0.04 and (ipc is None or ipc < 1.2):
            return WorkloadClass.MEMORY_BOUND

    # 3. I/O-Bound Detection: High scheduler delay / wait states
    if sched_delay is not None and sched_delay > 0.45:
        return WorkloadClass.IO_BOUND

    # 4. Compute-Bound Detection: High IPC, low relative cache misses
    if ipc is not None and ipc >= 1.4:
        return WorkloadClass.COMPUTE_BOUND

    # 5. Mixed Workload Default
    return WorkloadClass.MIXED
