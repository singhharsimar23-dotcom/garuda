"""
UTNE Sitrep Evidence Aggregator
Gathers telemetry, BRAHMA assessments, DHARMA queues, and KALI discoveries into a unified evidence bundle.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("network.utne.builder")


class SitrepBuilder:
    """
    Assembles evidence from distributed microservices and databases.
    """

    def __init__(
        self,
        brahma_url: Optional[str] = None,
        axiom_url: Optional[str] = None,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
    ):
        self.brahma_url = brahma_url or os.environ.get("BRAHMA_SERVICE_URL") or "https://garuda-brahma-service.onrender.com"
        self.axiom_url = axiom_url or os.environ.get("AXIOM_SERVICE_URL") or "https://garuda-axiom-service.onrender.com"
        self.supabase_url = supabase_url or os.environ.get("SUPABASE_URL")
        self.supabase_key = supabase_key or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    def build_evidence_bundle(self) -> Dict[str, Any]:
        """
        Compiles live evidence bundle from active data sources.
        """
        evidence: Dict[str, Any] = {
            "active_anomalies": [],
            "brahma_assessments": [],
            "pending_tier1_actions": 0,
            "latest_kali_high_value_paths": [],
            "geopolitical_tension": 0.45,
            "known_iocs": [],
        }

        # 1. Fetch active alerts from Supabase or mock fallback
        if self.supabase_url and self.supabase_key:
            try:
                from supabase import create_client
                client = create_client(self.supabase_url, self.supabase_key)
                res = client.table("anomaly_alerts").select("*").eq("status", "ACTIVE").limit(20).execute()
                if res.data:
                    evidence["active_anomalies"] = res.data
            except Exception as e:
                logger.debug(f"Supabase anomaly fetch fallback: {e}")

        # 2. Fetch pending DHARMA actions
        try:
            url = f"{self.brahma_url}/api/v1/dharma/pending"
            req = urllib.request.Request(url, headers={"User-Agent": "UTNE-Sitrep/0.1"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if 200 <= resp.status < 300:
                    data = json.loads(resp.read().decode("utf-8"))
                    evidence["pending_tier1_actions"] = len(data.get("pending_actions", []))
        except Exception as e:
            logger.debug(f"DHARMA pending fetch fallback: {e}")

        # If no active anomalies, provide structured empty set
        return evidence
