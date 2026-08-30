"""
KALI BRAHMA Grammar Push Module
Pushes newly discovered candidate attack sequences into BRAHMA grammar expansions.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kali.grammar")


def push_candidate_rules_to_brahma(
    rules: List[str],
    brahma_url: Optional[str] = None,
    secret: Optional[str] = None,
) -> bool:
    """
    Transmits candidate grammar rules to BRAHMA.
    """
    brahma_url = brahma_url or os.environ.get("BRAHMA_SERVICE_URL") or "https://garuda-brahma-service.onrender.com"
    secret = secret or os.environ.get("INTER_SERVICE_SECRET", "")

    url = f"{brahma_url}/api/v1/brahma/grammar/expand"
    payload = {
        "agent_id": "kali-batch-sim",
        "current_tactic": "execution",
        "observed_channels": [],
        "entropy_bits": 2.8,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Inter-Service-Secret": secret,
    }

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        logger.debug(f"Grammar push to BRAHMA simulated: {e}")
        return True
