"""
Multi-Stream Evidence Fusion Engine for SENTINEL
Fuses physical microarchitecture (AXIOM-II), process provenance (EPPI), STIX IOCs, and regional tension into unified threat scores.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel.fusion")

APT36_PAYLOADS = {
    "elizarat", "crimsonrat", "caprarat", "obliquerat",
    "actionrat", "mythicleopard", "transparenttribe", "c-major"
}


class EvidenceFusionEngine:
    """
    Computes multi-dimensional fusion scores from physics, kernel kprobes, and intelligence streams.
    """

    # EPPI signal weights for all event types.
    # Vibeware signals (0x08-0x0B) are lower than direct APT36 binary detection
    # because Discord/Slack/Supabase/Firebase are legitimate services on non-defense hosts.
    # On DRDO/NIC hosts: extremely high anomaly — weights reflect context-dependent severity.
    # Source: Session O vibeware threat model (Bitdefender, March 2026).
    EPPI_SIGNAL_WEIGHTS = {
        # Existing signals — DO NOT CHANGE WEIGHTS
        "EXECVE_APT36_BINARY": 1.0,    # Direct APT36 payload execution = maximum
        "MMAP_EXEC": 0.8,              # Process hollowing memory mapping
        "CONNECT": 0.7,                # Generic C2 CONNECT
        "CLONE": 0.5,                  # Unexpected process forking
        "EPPI_BLIND": 0.0,             # Telemetry gap
        # Vibeware signals (Session O, March 2026 APT36 pivot)
        "EPPI_VIBEWARE_C2_DISCORD": 0.85,   # Discord on defense host = near-impossible legitimate
        "EPPI_VIBEWARE_C2_SUPABASE": 0.90,  # SupaServ RAT confirmed pattern
        "EPPI_VIBEWARE_C2_FIREBASE": 0.85,  # Firebase C2
        "EPPI_VIBEWARE_C2_SLACK": 0.75,     # Slightly lower — some defense orgs use Slack
        "EPPI_VIBEWARE_C2_KNOWN_IOC": 1.0,  # Confirmed ThreatFox IOC IP = maximum
    }

    def compute_eppi_signal(self, recent_eppi_events: List[Dict[str, Any]]) -> float:
        if not recent_eppi_events:
            return 0.0

        max_signal = 0.1

        for evt in recent_eppi_events:
            evt_type = evt.get("event_type", "").upper()
            comm = str(evt.get("comm", "")).lower()
            filename = str(evt.get("details", {}).get("filename") or "").lower()

            if evt_type == "EXECVE" and (any(p in comm or p in filename for p in APT36_PAYLOADS)):
                return 1.0

            if evt_type == "MMAP_EXEC":
                max_signal = max(max_signal, 0.8)

            if evt_type == "CONNECT" and evt.get("details", {}).get("remote_addr"):
                max_signal = max(max_signal, 0.7)

            if evt_type == "CLONE":
                max_signal = max(max_signal, 0.5)

            # Vibeware C2 channel detection (APT36 2026 pivot)
            vibeware_weight = self.EPPI_SIGNAL_WEIGHTS.get(evt_type)
            if vibeware_weight is not None and evt_type.startswith("EPPI_VIBEWARE"):
                max_signal = max(max_signal, vibeware_weight)
                logger.info(
                    f"[FUSION] Vibeware C2 event detected: type={evt_type} "
                    f"comm={comm} weight={vibeware_weight}"
                )

        return round(max_signal, 4)

    def compute_fusion_score(
        self,
        ias_score: float,
        recent_eppi_events: List[Dict[str, Any]],
        stix_matches: int = 0,
        tension_index: float = 0.45,
    ) -> float:
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
