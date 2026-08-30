"""
BRAHMA Threat Intel Uploader Module
Transmits compiled MITRE ATT&CK TTP frequencies and IOC distributions to the BRAHMA service.
"""

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.uploader")


class BrahmaUploader:
    """
    Uploads compiled threat intelligence priors to BRAHMA Service 2.
    """

    def __init__(
        self,
        brahma_url: Optional[str] = None,
        inter_service_secret: Optional[str] = None,
    ):
        self.brahma_url = brahma_url or os.environ.get("NORTHFLANK_BRAHMA_URL", "http://localhost:8001")
        self.inter_service_secret = inter_service_secret or os.environ.get("INTER_SERVICE_SECRET", "")

    def upload_intel(self, intel_payload: Dict[str, Any]) -> bool:
        """
        Sends HTTP POST to BRAHMA /api/v1/brahma/update-intel endpoint.
        """
        url = f"{self.brahma_url.rstrip('/')}/api/v1/brahma/update-intel"
        data = json.dumps(intel_payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Inter-Service-Secret": self.inter_service_secret,
            "User-Agent": "GARUDA-DataPipeline/0.1.0",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                if 200 <= resp.status < 300:
                    logger.info(f"Successfully uploaded threat intel to BRAHMA ({url}).")
                    return True
        except urllib.error.URLError as e:
            logger.warning(f"Failed to upload intel to BRAHMA ({url}): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error uploading to BRAHMA: {e}")

        return False
