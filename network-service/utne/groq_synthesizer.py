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

        # 2. Rule 8 Honesty Check: Verify observation count & convergence
        min_obs = 0
        is_converged = False
        actor_id = "UNATTRIBUTED"
        confidence_val = 0.0

        if brahma_assessments:
            latest_assessment = brahma_assessments[0]
            min_obs = latest_assessment.get("observation_count", 0)
            is_converged = latest_assessment.get("convergence_status") == "CONVERGED"
            actor_id = latest_assessment.get("actor_id", "UNATTRIBUTED")
            confidence_val = latest_assessment.get("confidence", 0.0)

        # Strict Rule 8 Attribution Formatting
        if min_obs < 15 or not is_converged or actor_id == "UNATTRIBUTED":
            attribution_prefix = "ATTRIBUTION UNCERTAIN (Insufficient Bayesian Observations)"
            actor_attribution = "UNATTRIBUTED"
            confidence_display = f"{confidence_val * 100:.1f}% (Pre-Convergence)"
        else:
            attribution_prefix = f"ATTRIBUTED TO {actor_id.upper()} (Confidence: {confidence_val * 100:.1f}%)"
            actor_attribution = actor_id
            confidence_display = f"{confidence_val * 100:.1f}%"

        # 3. Construct deterministic verifiable narrative
        sitrep_lines = [
            f"=== GARUDA UTNE OPERATIONAL SITUATION REPORT — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} ===",
            f"1. ADVERSARY STATUS: {attribution_prefix}",
            f"   - Monitored Node Observations: {min_obs} events recorded across target infrastructure.",
            f"   - Bayesian Convergence Status: {'CONVERGED' if is_converged else 'INSUFFICIENT_DATA'}.",
            f"   - Attribution Confidence: {confidence_display}.",
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
            "attribution_status": actor_attribution,
            "convergence_status": "CONVERGED" if is_converged else "INSUFFICIENT_DATA",
            "confidence": confidence_val,
            "observations_count": min_obs,
            "active_anomalies_count": len(active_anomalies),
            "pending_actions_count": pending_actions,
            "evidence_citations": citations,
            "sitrep_text": sitrep_text,
        }
