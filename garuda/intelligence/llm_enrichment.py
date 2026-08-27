import json
import logging
from typing import Any, Dict
try:
    import anthropic
except ImportError:
    anthropic = None

from garuda.config import settings

logger = logging.getLogger("garuda.intelligence.llm_enrichment")

SYSTEM_PROMPT = """You are a cyber threat intelligence analyst. Generate a plain-English
threat summary for a non-technical military officer. STRICT RULES:
1. Only describe what is in the provided JSON data. No inference beyond it.
2. Do not claim APT36 attribution unless otx_attributed=True in the data.
3. End every response with: AI-ASSISTED DRAFT — ANALYST REVIEW REQUIRED.
4. Maximum 150 words. No bullet points. One paragraph."""


async def generate_threat_narrative(alert: Dict[str, Any]) -> str:
    """
    Generate an executive natural language threat intelligence summary using Anthropic Claude.

    Translates technical IOCs, network infrastructure fingerprints, and detection signals
    into a concise plain-English paragraph tailored for defense leadership and non-technical officers.

    Args:
        alert: Complete threat alert dictionary containing domain, score, signals, sector, etc.

    Returns:
        str: Concise plain-English summary ending with the required compliance disclaimer.
    """
    domain = alert.get("domain", "Unknown Domain")
    score = alert.get("score", 0)
    sector = alert.get("sector", "Critical Infrastructure")
    signals = alert.get("signals", {})
    otx_attributed = signals.get("otx_attributed", False)

    # If Anthropic client and API key are available, query Claude
    if settings.ANTHROPIC_API_KEY and anthropic is not None:
        try:
            client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
            user_msg = f"Generate threat summary for this alert: {json.dumps(alert, default=str)}"

            response = await client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=300,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            narrative = response.content[0].text.strip()
            if not narrative.endswith("AI-ASSISTED DRAFT — ANALYST REVIEW REQUIRED."):
                narrative += " AI-ASSISTED DRAFT — ANALYST REVIEW REQUIRED."
            return narrative
        except Exception as e:
            logger.error(f"[llm_enrichment] Error calling Anthropic Claude API: {e}")

    # Deterministic fallback conforming strictly to system instructions
    attribution_clause = (
        "with confirmed pulse attribution to APT36 threat actor infrastructure"
        if otx_attributed
        else "with infrastructure characteristics exhibiting high brand impersonation risk"
    )

    fallback_narrative = (
        f"Suspicious domain {domain} was detected targeting the {sector} sector with a threat score of {score}/100 "
        f"{attribution_clause}. The infrastructure was flagged based on keyword patterns, registrar profile, and hosting network correlation. "
        f"Immediate operational triage is advised to monitor potential credential harvesting or adversary reconnaissance against defense assets. "
        f"AI-ASSISTED DRAFT — ANALYST REVIEW REQUIRED."
    )
    return fallback_narrative
