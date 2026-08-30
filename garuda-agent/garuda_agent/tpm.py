"""
TPM 2.0 PCR Integrity Telemetry Reader
Wraps tpm2_pcrread subprocess if available; gracefully skips if hardware or tool is missing.
"""

import logging
import os
import shutil
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger("garuda_agent.tpm")


class TPMReader:
    """
    Reads hardware TPM 2.0 Platform Configuration Registers (PCRs).
    Gracefully disables when TPM device or tpm2-tools are not present.
    """

    def __init__(self, binary_name: str = "tpm2_pcrread"):
        self.binary_path = shutil.which(binary_name)
        self.device_exists = os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")
        self.is_available = bool(self.binary_path and self.device_exists)
        if not self.is_available:
            logger.info("TPM 2.0 hardware or tpm2_pcrread binary not found; skipping TPM collection.")

    @property
    def available(self) -> bool:
        return self.is_available

    def read_pcrs(self, banks: Optional[List[str]] = None) -> Dict[str, Dict[int, str]]:
        """
        Read PCR values for specified banks (default sha256:0..7).
        Returns empty dict on failure or if unavailable.
        """
        if not self.is_available or not self.binary_path:
            return {}

        if banks is None:
            banks = ["sha256:0,1,2,3,4,5,6,7"]

        results: Dict[str, Dict[int, str]] = {}
        try:
            cmd = [self.binary_path] + banks
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if proc.returncode != 0:
                logger.debug(f"tpm2_pcrread returned code {proc.returncode}: {proc.stderr}")
                return {}

            current_bank = "sha256"
            for line in proc.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    parts = line.split(":", 1)
                    if parts[0].isdigit():
                        pcr_idx = int(parts[0])
                        pcr_val = parts[1].strip()
                        if current_bank not in results:
                            results[current_bank] = {}
                        results[current_bank][pcr_idx] = pcr_val
                    else:
                        current_bank = parts[0].strip()

            return results
        except (subprocess.SubprocessError, OSError, IOError) as e:
            logger.warning(f"Error executing tpm2_pcrread: {e}")
            return {}
