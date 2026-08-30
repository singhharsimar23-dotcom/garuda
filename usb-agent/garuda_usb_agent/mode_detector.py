"""
GARUDA USB Agent Operating Mode Detector
Determines runtime mode: ALONGSIDE, BOOTABLE, or AIRGAPPED.
"""

import logging
import os
import urllib.request
from typing import Literal, Optional

logger = logging.getLogger("garuda.usb.mode_detector")

OperatingMode = Literal["ALONGSIDE", "BOOTABLE", "AIRGAPPED"]


def is_running_from_usb() -> bool:
    """Checks if the agent binary or working directory resides on a USB / removable mount."""
    try:
        # Check /proc/mounts on Linux
        if os.path.exists("/proc/mounts"):
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    if "/media/garuda" in line or "/mnt/garuda_usb" in line:
                        return True
    except Exception as e:
        logger.debug(f"Could not read /proc/mounts: {e}")

    # Check environment override
    return os.environ.get("GARUDA_RUNNING_FROM_USB", "").lower() in ("true", "1", "yes")


def is_host_os_running() -> bool:
    """Checks if host OS root filesystem is active (vs standalone USB booted environment)."""
    # If booted into Alpine Live RAM root, /etc/alpine-release exists and /host is mounted or missing
    if os.environ.get("GARUDA_STANDALONE_BOOT", "").lower() in ("true", "1", "yes"):
        return False
    return os.path.exists("/etc") and not os.path.exists("/etc/garuda-standalone-live")


def is_endpoint_reachable(endpoint_url: Optional[str], timeout_sec: float = 2.0) -> bool:
    """Pings configured AXIOM endpoint to test cloud connectivity."""
    if not endpoint_url:
        return False

    url = f"{endpoint_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GARUDA-Mode-Probe/0.1"})
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def detect_mode(axiom_endpoint: Optional[str] = None) -> OperatingMode:
    """
    Evaluates system indicators and resolves operating mode:
    - ALONGSIDE: USB plugged into running host OS with active cloud connectivity
    - BOOTABLE: Host booted directly from USB into Alpine Linux live environment
    - AIRGAPPED: Host has no cloud reachability; all IAS and alerting runs offline to LUKS partition
    """
    from_usb = is_running_from_usb()
    host_active = is_host_os_running()

    if from_usb and not host_active:
        logger.info("Detected Mode: BOOTABLE (Live Alpine RAM root).")
        return "BOOTABLE"

    if axiom_endpoint and is_endpoint_reachable(axiom_endpoint):
        logger.info("Detected Mode: ALONGSIDE (Connected to cloud AXIOM).")
        return "ALONGSIDE"

    logger.info("Detected Mode: AIRGAPPED (Offline local almanac processing).")
    return "AIRGAPPED"
