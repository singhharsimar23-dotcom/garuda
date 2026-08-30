"""
TPM 2.0 PCR State Reader
Reads hardware Platform Configuration Registers (PCRs 0, 7, 10) using tpm2-tools.
"""

import logging
import re
import shutil
import subprocess
from typing import Dict, Optional

logger = logging.getLogger("garuda_agent.tpm")


class TPMReader:
    """
    Interacts with TPM 2.0 hardware via tpm2_pcrread to measure platform integrity.
    """

    def __init__(self, pcr_spec: str = "sha256:0,7,10"):
        self.pcr_spec = pcr_spec
        self.tool_path = shutil.which("tpm2_pcrread")
        self.available = self.tool_path is not None
        
        if not self.available:
            logger.warning("tpm2_pcrread not found — TPM channel disabled.")
        else:
            logger.info(f"TPMReader initialized with binary: {self.tool_path}")

    def read_pcrs(self) -> Optional[Dict[str, str]]:
        """
        Executes tpm2_pcrread and returns a mapping of PCR indices to their SHA256 hex digests.
        Example output: {'0': '0xABC...', '7': '0xDEF...', '10': '0x123...'}
        """
        if not self.available or not self.tool_path:
            return None

        cmd = [self.tool_path, self.pcr_spec]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
            if res.returncode != 0:
                logger.warning(f"tpm2_pcrread failed (code {res.returncode}): {res.stderr.strip()}")
                return None

            return self._parse_pcr_output(res.stdout)
        except Exception as e:
            logger.warning(f"Failed to execute tpm2_pcrread: {e}")
            return None

    def _parse_pcr_output(self, output: str) -> Dict[str, str]:
        """
        Parses YAML-like or text output from tpm2_pcrread.
        Standard format:
          0 : 0x0123456789ABCDEF...
          7 : 0x...
        """
        pcrs: Dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            # Match formats like "0: 0x...", "0 : 0x...", "0: 1234abc..."
            match = re.match(r"^(\d+)\s*:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]{64})", line)
            if match:
                idx, val = match.groups()
                pcrs[idx] = val
        return pcrs
