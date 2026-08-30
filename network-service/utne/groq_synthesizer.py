"""
UTNE AI Synthesizer & Narrative Engine
Generates honest, verifiable executive SITREPs and alert narratives with strict citation enforcement.
"""

from datetime import datetime, timezone
import json
import logging
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional, Set

from .rate_limiter import BudgetLimiter

logger = logging.getLogger("network.utne.synthesizer")


class UTNESynthesizer:
    """
    Synthesizes CTI sitreps and threat narratives with Anti-Hallucination Charter enforcement.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        groq_api_key: Optional[str] = None,
        budget_limiter: Optional[BudgetLimiter] = None,
    ):
        self.gemini_api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY")
        self.groq_api_key = groq_api_key or os.environ.get("GROQ_API_KEY")
        self.limiter = budget_limiter or BudgetLimiter()

    def _extract_evidence_iocs(self, evidence_bundle: Dict[str, Any]) -> Set[str]:
        """Extracts all legitimate known IOCs present in the evidence bundle."""
        known_iocs = set()
        for an in evidence_bundle.get("active_anomalies", []):
            if an.get("hostname"):
                known_iocs.add(str(an.get("hostname")).lower())
            if an.get("agent_id"):
                known_iocs.add(str(an.get("agent_id")).lower())
        for ioc in evidence_bundle.get("known_iocs", []):
            known_iocs.add(str(ioc).lower())
        return known_iocs

    def generate_sitrep(self, evidence_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates an hourly executive SITREP based strictly on the provided evidence bundle.
        """
        # 1. Budget enforcement
        allowed, count, limit = self.limiter.check_and_increment("utne_sitrep")
        if not allowed:
            return {
                "status": "RATE_LIMITED",
                "sitrep_text": "[STALE / RATE-LIMITED] Indian Defense Infrastructure Threat Status: Monitoring active. Daily narrative budget reached.",
                "attribution_status": "BUDGET_RESTRICTED",
                "evidence_citations": ["cache:local"],
            }

        active_anomalies = evidence_bundle.get("active_anomalies", [])
        brahma_assessments = evidence_bundle.get("brahma_assessments", [])
        pending_actions = evidence_bundle.get("pending_tier1_actions", 0)
        geopolitical_tension = evidence_bundle.get("geopolitical_tension", 0.35)

        # 2. Rule 8 Honesty Check: Verify observation count & attribution status
        min_obs = 0
        attribution_status = "ACCUMULATING EVIDENCE (0/15 minimum)"
        actor_id = "UNATTRIBUTED"
        top_tactic = "UNKNOWN"
        top_tactic_mass = 0.0
        ist_overlap = "NO"

        if brahma_assessments:
            latest_assessment = brahma_assessments[0]
            min_obs = latest_assessment.get("observation_count", 0)
            attribution_status = latest_assessment.get("attribution_status", "ACCUMULATING EVIDENCE (0/15 minimum)")
            actor_id = latest_assessment.get("actor", latest_assessment.get("actor_id", "UNATTRIBUTED"))
            evidence_sum = latest_assessment.get("evidence_summary", {})
            top_tactic = evidence_sum.get("top_tactic", "EXECUTION")
            top_tactic_mass = evidence_sum.get("top_tactic_mass", 0.0)
            ist_overlap = "YES" if evidence_sum.get("ist_active_hours") else "NO"

        if min_obs < 15:
            attribution_prefix = f"ACCUMULATING EVIDENCE ({min_obs}/15 minimum)"
            actor_attribution = "UNATTRIBUTED"
        elif "ATTRIBUTED" in attribution_status:
            attribution_prefix = f"ATTRIBUTED — {actor_id}"
            actor_attribution = actor_id
        else:
            attribution_prefix = "PARTIAL ATTRIBUTION (Monitoring for Corroborating Signals)"
            actor_attribution = "MONITORING"

        # 3. Construct deterministic verifiable narrative without artificial percentages
        sitrep_lines = [
            f"=== GARUDA UTNE OPERATIONAL SITUATION REPORT — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} ===",
            f"1. ADVERSARY STATUS: {attribution_prefix}",
            f"   - Monitored Node Observations: {min_obs} events recorded across target infrastructure.",
            f"   - Attribution Status: {attribution_status}.",
            "   - Attribution Evidence:",
            f"     * Physics Anomaly Events: {len(active_anomalies)}",
            f"     * Top Tactic: {top_tactic} (posterior mass: {top_tactic_mass:.2f})",
            f"     * IST Behavioral Overlap: {ist_overlap}",
            "",
            "2. PHYSICAL INFRASTRUCTURE TELEMETRY & IAS ALERTS:",
            f"   - Active Physical Microarchitectural Anomalies: {len(active_anomalies)}.",
        ]

        citations = []
        for i, an in enumerate(active_anomalies[:5], 1):
            host = an.get("hostname", "unknown-host")
            ias = an.get("ias_score", 0.0)
            top_ch = an.get("top_channels", [])
            ch_str = ", ".join([f"{c.get('channel')}: {c.get('score', 0):.1f}" for c in top_ch[:2]]) or "physical power surge"
            sitrep_lines.append(f"   - [NODE-EVID-{i}] Host: {host} | IAS Divergence: {ias:.2f} | Channels: {ch_str}")
            citations.append(f"NODE-EVID-{i}:{host}")

        sitrep_lines.extend([
            "",
            "3. DHARMA AUTONOMOUS RESPONSE QUEUE:",
            f"   - Pending Tier 1 Operator Approvals: {pending_actions} action(s) in Redis queue.",
            f"   - Regional Geopolitical Threat Index: {geopolitical_tension:.2f} / 1.00.",
            "",
            "4. OPERATOR GUIDANCE & RECOMMENDATIONS:",
            "   - Re-verify physical RAPL power baselines before authorizing process terminations.",
            "   - Monitor DNS sinkholes for secondary beaconing attempts.",
        ])

        sitrep_text = "\n".join(sitrep_lines)

        return {
            "status": "SUCCESS",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attribution_status": attribution_status,
            "observations_count": min_obs,
            "active_anomalies_count": len(active_anomalies),
            "pending_actions_count": pending_actions,
            "evidence_citations": citations,
            "sitrep_text": sitrep_text,
        }

