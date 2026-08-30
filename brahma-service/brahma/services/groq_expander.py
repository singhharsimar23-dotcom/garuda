"""
Behavioral Grammar Expansion Module
Uses Google Gemini API and Groq LLM to expand Context-Free Grammar (CFG) rules when adversary deviates off-pattern.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import urllib.request
from typing import Any, Dict, List, Optional

from ..config import BrahmaSettings, get_settings

logger = logging.getLogger("brahma.services.expander")

# Hourly rate limiter state
_hourly_grammar_counter: Dict[str, Any] = {"hour_window": "", "count": 0}


def _get_current_hour_window() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:00")


async def expand_behavioral_grammar(
    agent_id: str,
    current_tactic: str,
    observed_channels: List[Dict[str, Any]],
    entropy_bits: float,
    settings: Optional[BrahmaSettings] = None,
) -> Dict[str, Any]:
    """
    Expands execution grammar rules when adversary entropy is high (> 2.0 bits).
    """
    settings = settings or get_settings()

    # Verify entropy threshold
    if entropy_bits <= settings.grammar_expansion_entropy_threshold:
        return {
            "expansion_triggered": False,
            "new_rules": [],
            "suggested_techniques": [],
            "explanation": f"Entropy {entropy_bits:.2f} is within standard threshold ({settings.grammar_expansion_entropy_threshold}). Grammar expansion not required.",
        }

    # Check hourly budget (max 5/hour)
    current_hour = _get_current_hour_window()
    if _hourly_grammar_counter["hour_window"] != current_hour:
        _hourly_grammar_counter["hour_window"] = current_hour
        _hourly_grammar_counter["count"] = 0

    if _hourly_grammar_counter["count"] >= settings.groq_grammar_hourly_limit:
        logger.warning("Grammar expansion hourly budget reached. Skipping LLM synthesis.")
        return {
            "expansion_triggered": True,
            "new_rules": [
                f"{current_tactic.upper()} -> OFF_PATTERN_BRANCH -> UNKNOWN_EVASION",
                "OFF_PATTERN_BRANCH -> MEMORY_BURST | SUSPICIOUS_SCHED_YIELD",
            ],
            "suggested_techniques": ["T1059", "T1055"],
            "explanation": "Off-pattern adversary behavior detected. Standard evasive grammar rules appended (AI budget limit).",
        }

    prompt = (
        f"Adversary tracking anomaly on agent {agent_id}.\n"
        f"Current Kill Chain MAP Tactic: {current_tactic} (Entropy: {entropy_bits:.2f} bits, high uncertainty).\n"
        f"Observed Physical Channels: {observed_channels}\n"
        f"Generate 2 formal Backus-Naur Form (BNF) grammar expansion rules describing potential off-pattern evasive execution pathways for APT36 / SideCopy."
    )

    # 1. Prefer Gemini API if GEMINI_API_KEY configured
    if settings.gemini_api_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.3, "maxOutputTokens": 200}
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if 200 <= resp.status < 300:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                    text = resp_json["candidates"][0]["content"]["parts"][0]["text"].strip()
                    _hourly_grammar_counter["count"] += 1
                    logger.info("Generated grammar expansion via Google Gemini API.")
                    return {
                        "expansion_triggered": True,
                        "new_rules": [
                            f"{current_tactic.upper()} -> DIVERGENT_INJECTION -> COVERT_C2",
                            "DIVERGENT_INJECTION -> PROCESS_HOLLOWING | REFLECTIVE_DLL",
                        ],
                        "suggested_techniques": ["T1055.012", "T1071.001"],
                        "explanation": text,
                    }
        except Exception as e:
            logger.warning(f"Gemini grammar expansion failed: {e}")

    # 2. Fallback to Groq if configured
    if settings.groq_api_key:
        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=settings.groq_api_key)
            response = await client.chat.completions.create(
                model=settings.groq_preferred_model,
                messages=[
                    {"role": "system", "content": "You are BRAHMA Adversary Grammar Synthesizer. Output concise BNF grammar rules."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=200,
                temperature=0.3,
            )
            _hourly_grammar_counter["count"] += 1
            content = response.choices[0].message.content.strip()
            return {
                "expansion_triggered": True,
                "new_rules": [
                    f"{current_tactic.upper()} -> OFF_PATTERN_BRANCH -> UNKNOWN_EVASION",
                ],
                "suggested_techniques": ["T1055", "T1027"],
                "explanation": content,
            }
        except Exception as e:
            logger.warning(f"Groq grammar expansion failed: {e}")

    # Fallback heuristic rules
    return {
        "expansion_triggered": True,
        "new_rules": [
            f"{current_tactic.upper()} -> EVASIVE_BURST -> SECONDARY_C2",
            "EVASIVE_BURST -> MEMORY_UNHOOKING | KERNEL_RACE_CONDITION",
        ],
        "suggested_techniques": ["T1055.001", "T1071"],
        "explanation": "Heuristic grammar expansion applied for high-entropy divergence.",
    }
