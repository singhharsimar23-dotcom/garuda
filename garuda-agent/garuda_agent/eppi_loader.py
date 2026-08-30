"""
EPPI (Execution Provenance and Physical Invariants) eBPF Loader
Applies kernel version gating (minimum 5.4 for kprobes, 5.7 for BPF LSM) and manages eBPF ring buffers.
"""

import logging
import os
import platform
from typing import Any, Dict, List

logger = logging.getLogger("garuda_agent.eppi")


class EPPILoader:
    """
    Manages loading of pre-compiled eBPF CO-RE bytecode for process execution provenance tracking.
    """

    def __init__(self, bpf_object_path: str = "/var/lib/garuda/eppi.bpf.o"):
        self.bpf_object_path = bpf_object_path
        self.enabled: bool = False
        self.kernel_version: tuple[int, int] = (0, 0)
        self.lsm_supported: bool = False

        self._check_kernel_compatibility()

    def _check_kernel_compatibility(self) -> None:
        """
        Gates eBPF execution based on Linux kernel release version.
        Requires >= 5.4 for standard kprobes/ringbuffers, >= 5.7 for BPF LSM.
        """
        if platform.system() != "Linux":
            logger.warning(f"EPPI eBPF requires Linux OS (current: {platform.system()}). EPPI disabled.")
            self.enabled = False
            return

        try:
            if hasattr(os, "uname"):
                release_str = os.uname().release
            else:
                release_str = platform.release()
            parts = release_str.split(".")[:2]
            # Strip non-digits (e.g., "5.4.0-generic" -> (5, 4))
            major = int("".join(filter(str.isdigit, parts[0])))
            minor = int("".join(filter(str.isdigit, parts[1])))
            self.kernel_version = (major, minor)
        except Exception as e:
            logger.warning(f"Could not determine kernel version: {e}. Defaulting to disabled.")
            self.enabled = False
            return

        if self.kernel_version < (5, 4):
            logger.warning(
                f"EPPI disabled — kernel {self.kernel_version[0]}.{self.kernel_version[1]} "
                "< 5.4 minimum required for eBPF kprobes."
            )
            self.enabled = False
            return

        if self.kernel_version >= (5, 7):
            self.lsm_supported = True
            logger.debug(f"Kernel {self.kernel_version[0]}.{self.kernel_version[1]} supports BPF LSM.")
        else:
            self.lsm_supported = False
            logger.debug(f"Kernel {self.kernel_version[0]}.{self.kernel_version[1]} does not support BPF LSM (requires 5.7+).")

        # Check for pre-compiled eBPF object file
        if not os.path.exists(self.bpf_object_path):
            logger.warning(
                f"eBPF object '{self.bpf_object_path}' not found (Session C builds this). "
                "EPPI running in stub mode."
            )
            self.enabled = False
            return

        self.enabled = True
        logger.info(f"EPPI eBPF loader enabled with object: {self.bpf_object_path}")

    def read_events(self) -> List[Dict[str, Any]]:
        """
        Polls events from the eBPF perf buffer / ring buffer.
        Returns a list of parsed process execution event dictionaries.
        """
        if not self.enabled:
            return []

        # Session A stub: returns empty event stream
        return []
