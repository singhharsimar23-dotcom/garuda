"""
Kernel Entropy Pool Reader
Reads /proc/sys/kernel/random/entropy_avail to monitor system entropy depletion.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("garuda_agent.entropy")


class EntropyReader:
    """
    Reads the available system entropy bits from Linux sysctl /proc interface.
    """

    def __init__(self, sysfs_path: str = "/proc/sys/kernel/random/entropy_avail"):
        self.sysfs_path = sysfs_path
        self.available = os.path.exists(self.sysfs_path)
        if not self.available:
            logger.warning(f"Entropy path '{self.sysfs_path}' not found. Entropy channel disabled.")

    def read_entropy_bits(self) -> Optional[int]:
        """
        Returns available entropy bits (usually between 0 and 4096).
        Returns None if sysfs file is missing or unreadable.
        """
        if not os.path.exists(self.sysfs_path):
            return None

        try:
            with open(self.sysfs_path, "r") as f:
                content = f.read().strip()
                if content.isdigit():
                    return int(content)
                return None
        except Exception as e:
            logger.debug(f"Error reading entropy from {self.sysfs_path}: {e}")
            return None
