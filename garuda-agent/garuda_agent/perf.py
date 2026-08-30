"""
Hardware Performance Counters Reader via perf_event_open syscall (ctypes).
Monitors hardware cycles, instructions, and L3 cache misses.
Implements robust error handling for EACCES / ENOENT and non-Linux systems.
"""

import ctypes
import errno
import logging
import os
import platform
import struct
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("garuda_agent.perf")

# Linux perf_event constants
PERF_TYPE_HARDWARE = 0

PERF_COUNT_HW_CPU_CYCLES = 0x0
PERF_COUNT_HW_INSTRUCTIONS = 0x1
PERF_COUNT_HW_CACHE_MISSES = 0x3

# ioctl request codes for perf events on Linux (asm-generic/ioctls.h)
PERF_EVENT_IOC_ENABLE = 0x2400
PERF_EVENT_IOC_DISABLE = 0x2401
PERF_EVENT_IOC_RESET = 0x2403

# Syscall numbers for perf_event_open
# x86_64: 298, aarch64: 241, i386: 336
SYS_PERF_EVENT_OPEN_X86_64 = 298
SYS_PERF_EVENT_OPEN_AARCH64 = 241


class PerfEventAttr(ctypes.Structure):
    """Linux struct perf_event_attr (112 bytes standard size)."""

    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("config1", ctypes.c_uint64),
        ("config2", ctypes.c_uint64),
        ("branch_sample_type", ctypes.c_uint64),
        ("sample_regs_user", ctypes.c_uint64),
        ("sample_stack_user", ctypes.c_uint32),
        ("clockid", ctypes.c_int32),
        ("sample_regs_intr", ctypes.c_uint64),
        ("aux_watermark", ctypes.c_uint32),
        ("sample_max_stack", ctypes.c_uint16),
        ("reserved_2", ctypes.c_uint16),
    ]


class PerfReader:
    """
    Hardware Performance Counter reader using perf_event_open syscall.
    Reports instructions/s, cache_misses/s, and cycles/s.
    """

    def __init__(self, cpu: int = 0):
        self.cpu = cpu
        self.fds: Dict[str, int] = {}
        self.last_counts: Dict[str, int] = {}
        self.last_timestamp: Optional[float] = None
        self.is_available: bool = False
        self._libc: Optional[ctypes.CDLL] = None
        self._syscall_nr = SYS_PERF_EVENT_OPEN_X86_64
        self._init_perf()

    def _init_perf(self) -> None:
        """Initialize perf syscall and open counter descriptors."""
        if platform.system() != "Linux":
            logger.info("Perf hardware counters unavailable: Non-Linux OS detected.")
            self.is_available = False
            return

        arch = platform.machine()
        if "aarch64" in arch or "arm64" in arch:
            self._syscall_nr = SYS_PERF_EVENT_OPEN_AARCH64
        else:
            self._syscall_nr = SYS_PERF_EVENT_OPEN_X86_64

        try:
            self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        except (OSError, AttributeError) as e:
            logger.warning(f"Could not load libc for perf_event_open: {e}")
            self.is_available = False
            return

        counters = {
            "cycles": PERF_COUNT_HW_CPU_CYCLES,
            "instructions": PERF_COUNT_HW_INSTRUCTIONS,
            "cache_misses": PERF_COUNT_HW_CACHE_MISSES,
        }

        opened_fds = {}
        for name, config_val in counters.items():
            fd = self._open_counter(config_val)
            if fd < 0:
                err = ctypes.get_errno()
                # Clean up any opened fds
                for open_fd in opened_fds.values():
                    try:
                        os.close(open_fd)
                    except OSError:
                        pass
                opened_fds.clear()

                if err == errno.EACCES:
                    logger.warning("perf_event_open returned EACCES (Permission Denied). Hardware counters disabled.")
                elif err == errno.ENOENT:
                    logger.warning("perf_event_open returned ENOENT (Not Found). Hardware counters disabled.")
                else:
                    logger.warning(f"perf_event_open failed with errno {err}. Hardware counters disabled.")
                self.is_available = False
                return
            opened_fds[name] = fd

        self.fds = opened_fds
        self.is_available = True
        logger.info("Successfully initialized hardware perf counters (cycles, instructions, cache_misses).")

    def _open_counter(self, config: int) -> int:
        """Call sys_perf_event_open via ctypes syscall wrapper."""
        if not self._libc:
            return -1

        attr = PerfEventAttr()
        ctypes.memset(ctypes.byref(attr), 0, ctypes.sizeof(attr))
        attr.type = PERF_TYPE_HARDWARE
        attr.size = ctypes.sizeof(PerfEventAttr)
        attr.config = config
        # Flags: disabled=1 (bit 0), exclude_kernel=0, exclude_hv=0
        attr.flags = 1  # Start disabled

        # VERIFY: libc syscall signature: long syscall(long number, ...)
        syscall_func = self._libc.syscall
        syscall_func.argtypes = [
            ctypes.c_long,
            ctypes.POINTER(PerfEventAttr),
            ctypes.c_int,  # pid (-1 for all processes on this cpu)
            ctypes.c_int,  # cpu (0 for cpu 0)
            ctypes.c_int,  # group_fd (-1 for group leader)
            ctypes.c_ulong,  # flags (0)
        ]
        syscall_func.restype = ctypes.c_int

        fd = syscall_func(
            ctypes.c_long(self._syscall_nr),
            ctypes.byref(attr),
            ctypes.c_int(-1),
            ctypes.c_int(self.cpu),
            ctypes.c_int(-1),
            ctypes.c_ulong(0),
        )

        if fd >= 0:
            # Enable and reset counter
            try:
                import fcntl
                fcntl.ioctl(fd, PERF_EVENT_IOC_RESET, 0)
                fcntl.ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)
            except (OSError, ImportError) as e:
                logger.warning(f"Failed to reset/enable perf counter ioctl: {e}")

        return fd

    @property
    def available(self) -> bool:
        return self.is_available

    def read(self) -> Tuple[Dict[str, float], List[str]]:
        """
        Read perf counters and return rate per second.
        Returns:
            - payload: {"instructions_ps": float, "cache_misses_ps": float, "cycles_ps": float, "unavailable": bool}
            - flags: ["PERF_UNAVAILABLE"] if counters are not operational
        """
        if not self.is_available or not self.fds:
            return (
                {"instructions_ps": 0.0, "cache_misses_ps": 0.0, "cycles_ps": 0.0, "unavailable": True},
                ["PERF_UNAVAILABLE"],
            )

        now = time.monotonic()
        raw_values: Dict[str, int] = {}

        for name, fd in self.fds.items():
            try:
                data = os.read(fd, 8)
                if len(data) == 8:
                    val = struct.unpack("Q", data)[0]
                    raw_values[name] = val
                else:
                    logger.warning(f"Unexpected read length {len(data)} from perf fd for {name}")
            except OSError as e:
                logger.warning(f"Error reading perf counter {name}: {e}")

        if not raw_values:
            return (
                {"instructions_ps": 0.0, "cache_misses_ps": 0.0, "cycles_ps": 0.0, "unavailable": True},
                ["PERF_UNAVAILABLE"],
            )

        inst_ps = 0.0
        cache_miss_ps = 0.0
        cycles_ps = 0.0

        if self.last_timestamp is not None and self.last_counts:
            dt = now - self.last_timestamp
            if dt > 0:
                delta_inst = max(0, raw_values.get("instructions", 0) - self.last_counts.get("instructions", 0))
                delta_cache = max(0, raw_values.get("cache_misses", 0) - self.last_counts.get("cache_misses", 0))
                delta_cycles = max(0, raw_values.get("cycles", 0) - self.last_counts.get("cycles", 0))

                inst_ps = round(delta_inst / dt, 2)
                cache_miss_ps = round(delta_cache / dt, 2)
                cycles_ps = round(delta_cycles / dt, 2)

        self.last_counts = raw_values
        self.last_timestamp = now

        payload = {
            "instructions_ps": inst_ps,
            "cache_misses_ps": cache_miss_ps,
            "cycles_ps": cycles_ps,
            "unavailable": False,
        }
        return payload, []

    def close(self) -> None:
        """Close all open perf counter descriptors."""
        for name, fd in self.fds.items():
            try:
                if self._libc:
                    try:
                        import fcntl
                        fcntl.ioctl(fd, PERF_EVENT_IOC_DISABLE, 0)
                    except (OSError, ImportError):
                        pass
                os.close(fd)
            except OSError:
                pass
        self.fds.clear()
        self.is_available = False
