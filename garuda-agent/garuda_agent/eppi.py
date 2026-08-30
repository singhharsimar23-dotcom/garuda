"""
EPPI (Endpoint Process Provenance Identifier) User-Space Reader
Attaches eBPF kprobes via bcc or perf_event ring buffers to monitor process execution,
executable memory maps (T1055.012), and network socket connections.
"""

from datetime import datetime, timezone
import json
import logging
import os
import platform
import socket
import struct
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("garuda.agent.eppi")

EVENT_TYPE_NAMES = {
    1: "EXECVE",
    2: "CONNECT",
    3: "MMAP_EXEC",
    4: "CLONE",
}


class EPPISensor:
    """
    Manages eBPF kprobe lifecycle, polling the ring buffer for kernel security events.
    """

    def __init__(self, bpf_source_path: Optional[str] = None):
        self.bpf_source_path = bpf_source_path or os.path.join(os.path.dirname(__file__), "eppi_kprobes.c")
        self.is_available = False
        self.unavailability_reason = "UNINITIALIZED"
        self._bpf = None
        self._event_queue: List[Dict[str, Any]] = []

        self._initialize_ebpf()

    def _initialize_ebpf(self) -> None:
        if platform.system().lower() != "linux":
            self.is_available = False
            self.unavailability_reason = "NON_LINUX_OS"
            logger.info("EPPI eBPF probes disabled on non-Linux OS.")
            return

        if os.geteuid() != 0:
            self.is_available = False
            self.unavailability_reason = "PERMISSION_DENIED_NON_ROOT"
            logger.warning("EPPI requires root privileges (CAP_SYS_ADMIN / CAP_BPF). Running in degraded mode.")
            return

        try:
            from bcc import BPF  # type: ignore
            if os.path.exists(self.bpf_source_path):
                self._bpf = BPF(src_file=self.bpf_source_path)
            else:
                self.is_available = False
                self.unavailability_reason = "BPF_SOURCE_FILE_NOT_FOUND"
                logger.warning(f"EPPI BPF source {self.bpf_source_path} not found.")
                return

            self._bpf["eppi_events"].open_perf_buffer(self._handle_perf_event)
            self.is_available = True
            self.unavailability_reason = "ACTIVE"
            logger.info("EPPI eBPF kprobes attached successfully.")
        except ImportError:
            self.is_available = False
            self.unavailability_reason = "BCC_NOT_INSTALLED"
            logger.info("bcc python library not found. EPPI operating with fallback status.")
        except Exception as e:
            self.is_available = False
            self.unavailability_reason = f"BPF_INIT_FAILED: {str(e)}"
            logger.warning(f"Failed initializing EPPI eBPF kprobes: {e}")

    def _handle_perf_event(self, cpu: int, data: Any, size: int) -> None:
        if not self._bpf:
            return
        event = self._bpf["eppi_events"].event(data)
        evt_type = EVENT_TYPE_NAMES.get(event.event_type, "UNKNOWN")

        remote_ip = None
        if event.remote_addr:
            try:
                remote_ip = socket.inet_ntoa(struct.pack("<I", event.remote_addr))
            except Exception:
                remote_ip = str(event.remote_addr)

        evt_dict = {
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "event_type": evt_type,
            "comm": event.comm.decode("utf-8", "replace").strip(),
            "filename": event.filename.decode("utf-8", "replace").strip() if evt_type == "EXECVE" else None,
            "remote_addr": remote_ip,
            "remote_port": event.remote_port if evt_type == "CONNECT" else None,
            "mmap_addr": hex(event.mmap_addr) if evt_type == "MMAP_EXEC" else None,
            "mmap_len": event.mmap_len if evt_type == "MMAP_EXEC" else None,
            "mmap_flags": event.mmap_flags if evt_type == "MMAP_EXEC" else None,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        self._event_queue.append(evt_dict)

    def read_events(self, timeout_ms: int = 50) -> List[Dict[str, Any]]:
        if not self.is_available or not self._bpf:
            return []

        try:
            self._bpf.perf_buffer_poll(timeout=timeout_ms)
        except Exception as e:
            logger.debug(f"Perf buffer poll error: {e}")

        events = list(self._event_queue)
        self._event_queue.clear()
        return events

    def inject_synthetic_event(self, event_dict: Dict[str, Any]) -> None:
        if "timestamp_utc" not in event_dict:
            event_dict["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        self._event_queue.append(event_dict)


_eppi_instance: Optional[EPPISensor] = None


def get_eppi_sensor() -> EPPISensor:
    global _eppi_instance
    if _eppi_instance is None:
        _eppi_instance = EPPISensor()
    return _eppi_instance
