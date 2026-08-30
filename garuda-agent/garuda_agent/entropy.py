"""
Kernel Entropy Pool Monitor
Monitors /proc/sys/kernel/random/entropy_avail for low-entropy anomalies and covert channels (APT36).
Follows runtime path existence checks as per the Anti-Hallucination Charter.
"""

import logging
import os
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("garuda_agent.entropy")

ENTROPY_AVAIL_PATH = "/proc/sys/kernel/random/entropy_avail"
LOW_ENTROPY_THRESHOLD = 512
CRITICAL_ENTROPY_THRESHOLD = 128
SUSTAINED_LOW_SECONDS_THRESHOLD = 30


class EntropyReader:
    """
    Reads Linux kernel available entropy bits and flags covert entropy exhaustion attacks.
    """

    def __init__(self, path: str = ENTROPY_AVAIL_PATH):
        self.path = path
        self.sustained_low_seconds: float = 0.0
        self.last_timestamp: Optional[float] = None

    def read(self) -> Tuple[Dict[str, any], list]:
        """
        Read current available entropy bits.
        Returns:
            - payload: {"bits": int, "depleting": bool, "sustained_low_s": int}
            - flags: List of flags (e.g. ["ENTROPY_DEPLETING", "ENTROPY_CRITICAL"])
        """
        now = time.monotonic()
        dt = (now - self.last_timestamp) if self.last_timestamp is not None else 1.0
        self.last_timestamp = now

        # Existence check
        if not os.path.exists(self.path):
            return {"bits": 4096, "depleting": False, "sustained_low_s": 0}, []

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                val_str = f.read().strip()
            bits = int(val_str)
        except (OSError, IOError, ValueError) as e:
            logger.warning(f"Failed to read entropy from {self.path}: {e}")
            return {"bits": 4096, "depleting": False, "sustained_low_s": 0}, []

        flags = []
        # Check low entropy conditions
        if bits < LOW_ENTROPY_THRESHOLD:
            self.sustained_low_seconds += dt
        else:
            self.sustained_low_seconds = 0.0

        depleting = False
        if bits < CRITICAL_ENTROPY_THRESHOLD:
            depleting = True
            flags.append("ENTROPY_CRITICAL")
        elif self.sustained_low_seconds > SUSTAINED_LOW_SECONDS_THRESHOLD:
            depleting = True
            flags.append("ENTROPY_DEPLETING")

        payload = {
            "bits": bits,
            "depleting": depleting,
            "sustained_low_s": int(self.sustained_low_seconds),
        }
        return payload, flags
