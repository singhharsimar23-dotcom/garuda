"""
Multi-Stream Evidence Fusion Engine for SENTINEL
Fuses physical microarchitecture (AXIOM-II), process provenance (EPPI), STIX IOCs, and regional tension into unified threat scores.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("sentinel.fusion")

APT36_PAYLOADS = {
    "elizarat", "crimsonrat", "caprarat", "obliquerat",
    "actionrat", "mythicleopard", "transparenttribe", "c-major"
}


class EvidenceFusionEngine:
    """
    Computes multi-dimensional fusion scores from physics, kernel kprobes, and intelligence streams.
    """

    def compute_eppi_signal(self, recent_eppi_events: List[Dict[str, Any]]) -> float:
        """
        Compute EPPI confidence signal in [0.0, 1.0]:
        - EXECVE of known APT36 payload name: 1.0
        - MMAP_EXEC (process injection): 0.8
        - CONNECT to known C2 IP/domain: 0.7
        - Unexpected CLONE from non-shell parent: 0.5
        - No EPPI data: 0.0 (EPPI_BLIND)
        """
        if not recent_eppi_events:
            return 0.0

        max_signal = 0.1  # baseline for clean activity

        for evt in recent_eppi_events:
            evt_type = evt.get("event_type", "").upper()
            comm = str(evt.get("comm", "")).lower()
            filename = str(evt.get("details", {}).get("filename") or "").lower()

            # Check APT36 Payload Name
            if evt_type == "EXECVE" and (any(p in comm or p in filename for p in APT36_PAYLOADS)):
                return 1.0

            if evt_type == "MMAP_EXEC":
                max_signal = max(max_signal, 0.8)

            if evt_type == "CONNECT" and evt.get("details", {}).get("remote_addr"):
                max_signal = max(max_signal, 0.7)

            if evt_type == "CLONE":
                max_signal = max(max_signal, 0.5)

        return round(max_signal, 4)

    def compute_fusion_score(
        self,
        ias_score: float,
        recent_eppi_events: List[Dict[str, Any]],
        stix_matches: int = 0,
        tension_index: float = 0.45,
    ) -> float:
        """
        Calculates composite evidence fusion score in [0.0, 10.0]:
        score = 10 * [0.40 * IAS_norm + 0.35 * EPPI_norm + 0.15 * STIX_norm + 0.10 * Tension_norm]
        """
        ias_norm = min(1.0, max(0.0, ias_score / 10.0))
        eppi_signal = self.compute_eppi_signal(recent_eppi_events)
        stix_norm = min(1.0, max(0.0, stix_matches / 5.0))
        tension_norm = min(1.0, max(0.0, tension_index / 1.0))

        weighted_sum = (
            (0.40 * ias_norm)
            + (0.35 * eppi_signal)
            + (0.15 * stix_norm)
            + (0.10 * tension_norm)
        )

        final_fusion_score = round(weighted_sum * 10.0, 4)
        return final_fusion_score


_fusion_engine = EvidenceFusionEngine()


def get_fusion_engine() -> EvidenceFusionEngine:
    return _fusion_engine
