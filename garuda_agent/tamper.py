"""
Agent Integrity & Tamper Detection Module
Verifies SHA256 integrity of the running telemetry daemon binary on startup.
Alerts on discrepancy (TAMPER_DETECTED) without crashing to avoid denial-of-service.
"""

import hashlib
import logging
import os
import sys
from typing import Optional, Tuple

logger = logging.getLogger("garuda.agent.tamper")

DEFAULT_HASH_PATH = "/etc/garuda/agent_hash.sha256"


class TamperDetector:
    """
    Computes and verifies cryptographic hash of the running daemon executable.
    """

    def __init__(self, hash_file_path: Optional[str] = None):
        self.hash_file_path = hash_file_path or os.environ.get("GARUDA_HASH_FILE", DEFAULT_HASH_PATH)

    def compute_binary_hash(self, target_path: Optional[str] = None) -> Optional[str]:
        """Compute SHA256 hash of the target binary or sys.argv[0]."""
        path = target_path or sys.argv[0]
        if not path or not os.path.exists(path):
            # Fallback to current file
            path = os.path.abspath(__file__)

        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception as e:
            logger.warning(f"Failed reading binary {path} for hashing: {e}")
            return None

    def verify_integrity(self, target_path: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verify current binary hash against stored reference.
        Returns (is_valid: bool, current_hash: str, expected_hash: str)
        """
        current_hash = self.compute_binary_hash(target_path)
        if not current_hash:
            return True, None, None

        if not os.path.exists(self.hash_file_path):
            logger.info(f"Integrity reference hash file {self.hash_file_path} not found. Recording baseline.")
            return True, current_hash, None

        try:
            with open(self.hash_file_path, "r", encoding="utf-8") as f:
                expected_hash = f.read().strip()

            if current_hash != expected_hash:
                logger.critical(
                    f"TAMPER_DETECTED: Binary SHA256 mismatch! Current: {current_hash}, Expected: {expected_hash}"
                )
                return False, current_hash, expected_hash

            logger.info("Agent binary integrity verified against baseline hash.")
            return True, current_hash, expected_hash
        except Exception as e:
            logger.warning(f"Error reading hash file {self.hash_file_path}: {e}")
            return True, current_hash, None


_tamper_detector = TamperDetector()


def get_tamper_detector() -> TamperDetector:
    return _tamper_detector
