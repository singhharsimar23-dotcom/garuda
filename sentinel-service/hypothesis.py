"""
Operational Threat Hypothesis Generator
Synthesizes 2-sentence operational hypotheses via ResilientLLMClient cascading over Groq, Gemini, and offline templates.
Strictly cites observed evidence IDs and avoids percentages.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings

try:
    from lib.resilient_llm import ResilientLLMClient
except ImportError:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from lib.resilient_llm import ResilientLLMClient

logger = logging.getLogger("sentinel.hypothesis")


class HypothesisSynthesizer:
    """
    Generates grounded operational hypotheses from multi-source evidence graphs with multi-provider resilience.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.llm_client = ResilientLLMClient(
            groq_api_key=self.settings.groq_api_key,
            gemini_api_key=os.environ.get("GEMINI_API_KEY"),
            preferred_groq_model=self.settings.groq_model,
        )

    async def generate_hypothesis(
        self,
        campaign_id: str,
        hostname: str,
        top_tactic: str,
        fusion_score: float,
        evidence_chain_summary: List[Dict[str, Any]],
        observed_technique_ids: List[str],
        brahma_attribution_status: str,
    ) -> str:
        """
        Generates 2-sentence operational hypothesis citing concrete evidence IDs.
        """
        evidence_ids = [e.get("id", "NODE-01") for e in evidence_chain_summary[:3]]
        evidence_str = ", ".join(str(eid) for eid in evidence_ids) if evidence_ids else "NODE-INIT"
        techniques_str = ", ".join(observed_technique_ids) if observed_technique_ids else "T1059"

        system_prompt = (
            "You are GARUDA sentinel. Generate a 2-sentence operational hypothesis based ONLY on the provided evidence. "
            "Never mention confidence percentages. Never attribute without evidence. Reference specific evidence IDs."
        )

        context = {
            "campaign_id": campaign_id,
            "hostname": hostname,
            "top_tactic": top_tactic,
            "fusion_score": fusion_score,
            "evidence_nodes": evidence_ids,
            "observed_technique_ids": observed_technique_ids,
            "BRAHMA_attribution_status": brahma_attribution_status,
        }

        user_prompt = f"Synthesize operational hypothesis for context: {json.dumps(context)}"

        def offline_fallback() -> str:
            return (
                f"Observed adversary activity on host {hostname} exhibits primary {top_tactic.upper()} tactics "
                f"correlated across evidence nodes [{evidence_str}]. "
                f"Adversary posture aligns with {brahma_attribution_status} utilizing technique progression [{techniques_str}] (Fusion: {fusion_score:.2f})."
            )

        try:
            hypothesis_text, provider = await self.llm_client.generate_completion(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                fallback_template_fn=offline_fallback,
                temperature=0.1,
                max_tokens=200,
            )
            logger.info(f"[HYPOTHESIS] Generated hypothesis via {provider} for {hostname}.")
            return hypothesis_text
        except Exception as e:
            logger.warning(f"Failed in resilient hypothesis generation: {e}")
            return offline_fallback()


_hypothesis_synthesizer = HypothesisSynthesizer()


def get_hypothesis_synthesizer() -> HypothesisSynthesizer:
    return _hypothesis_synthesizer
