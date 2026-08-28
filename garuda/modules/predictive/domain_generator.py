"""
APT36 domain candidate generation, DNS availability filtering, and scoring.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, List, Optional, Sequence

import dns.resolver
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

from garuda.detection.nic_ground_truth import compute_similarity

logger = logging.getLogger("garuda.modules.predictive.domain_generator")

APT36_PREFERRED_TLDS = [".space", ".online", ".site", ".xyz"]

APT36_ACTION_WORDS = [
    "login",
    "portal",
    "secure",
    "services",
    "update",
    "webmail",
    "sso",
    "access",
    "verify",
    "connect",
]

# Confirmed historical APT36 naming examples from GARUDA retrohunt.
APT36_HISTORICAL_DOMAINS = [
    "modgovindia.space",
    "army-hq-portal.space",
    "securestore.cv",
    "modindia-sso.online",
    "nicwebmail-secure.site",
    "drdo-vpn.online",
]

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
)

_SYSTEM_PROMPT = """You are generating candidate phishing domains that APT36 might register.
Follow these EXACT naming patterns observed in historical APT36 campaigns:
  {target_keyword}-{action_word}.{preferred_tld}
  {target_keyword}{action_word}.{preferred_tld}
Examples of real APT36 domains: modgovindia.space, securestore.cv, army-hq-portal.space
Generate ONLY names that follow these patterns.
No creativity. No novel patterns. APT36 is methodical.
Return only domain names, one per line, nothing else."""


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def filter_valid_apt36_tlds(domains: Sequence[str]) -> list[str]:
    """Keep only domains ending in APT36 preferred TLDs (.com/.net excluded)."""
    result: list[str] = []
    for raw in domains:
        domain = _normalize_domain(raw)
        if not domain or not _DOMAIN_RE.match(domain):
            continue
        if any(domain.endswith(tld) for tld in APT36_PREFERRED_TLDS):
            result.append(domain)
    return result


def _parse_llm_domains(response_text: str) -> list[str]:
    lines = []
    for line in response_text.splitlines():
        candidate = _normalize_domain(line.split("#")[0].strip())
        if candidate and "." in candidate:
            lines.append(candidate)
    return filter_valid_apt36_tlds(lines)


def _matches_historical_apt36_pattern(domain: str, target_keywords: list[str]) -> bool:
    """True when domain follows confirmed APT36 naming structure."""
    domain = _normalize_domain(domain)
    if domain in APT36_HISTORICAL_DOMAINS:
        return True

    name, _, tld = domain.rpartition(".")
    if f".{tld}" not in APT36_PREFERRED_TLDS:
        return False

    name_lower = name.lower()
    has_action = any(action in name_lower for action in APT36_ACTION_WORDS)
    has_keyword = any(kw.replace("-", "") in name_lower.replace("-", "") for kw in target_keywords)
    if has_action and has_keyword:
        return True

    # Hyphenated keyword-action pattern: army-hq-portal
    if "-" in name_lower and has_action:
        return True

    return False


async def generate_candidate_domains(
    target_keywords: list[str],
    anthropic_client: Any,
) -> list[str]:
    """
    Generate domain name candidates using Claude.

    Parses LLM response, validates domain strings, filters to APT36 TLDs.
    """
    if not target_keywords:
        return []

    tld_list = ", ".join(APT36_PREFERRED_TLDS)
    system = _SYSTEM_PROMPT.format(
        target_keyword="{target_keyword}",
        action_word="{action_word}",
        preferred_tld=tld_list,
    )
    user_msg = (
        f"Target keywords: {target_keywords}\n"
        f"Preferred TLDs: {APT36_PREFERRED_TLDS}\n"
        "Generate 20 candidate domains."
    )

    try:
        response = await anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )
        text_blocks = [
            block.text
            for block in response.content
            if hasattr(block, "text")
        ]
        raw_text = "\n".join(text_blocks)
    except Exception as exc:
        logger.error("[domain_generator] Claude generation failed: %s", exc)
        return _fallback_candidates(target_keywords)

    return _parse_llm_domains(raw_text)


def _fallback_candidates(target_keywords: list[str]) -> list[str]:
    """Deterministic fallback when LLM is unavailable."""
    candidates: list[str] = []
    for kw in target_keywords[:5]:
        clean_kw = kw.replace("-", "")
        for action in APT36_ACTION_WORDS[:4]:
            for tld in APT36_PREFERRED_TLDS[:2]:
                candidates.append(f"{clean_kw}-{action}{tld}")
                candidates.append(f"{clean_kw}{action}{tld}")
    return filter_valid_apt36_tlds(candidates)[:20]


async def _dns_available(domain: str) -> bool:
    """Return True when domain has no A record (NXDOMAIN / unregistered)."""
    domain = _normalize_domain(domain)

    def _check() -> bool:
        try:
            dns.resolver.resolve(domain, "A")
            return False
        except NXDOMAIN:
            return True
        except (NoAnswer, NoNameservers):
            # No A record but zone exists — treat as unavailable.
            return False
        except Exception:
            # Resolver errors — assume unavailable to avoid false negatives.
            return True

    return await asyncio.get_running_loop().run_in_executor(None, _check)


async def filter_available_candidates(domains: list[str]) -> list[str]:
    """
    Filter to unregistered domains via DNS NXDOMAIN check (free, no WhoisFreaks).
    """
    unique = list(dict.fromkeys(_normalize_domain(d) for d in domains if d))
    results = await asyncio.gather(*[_dns_available(d) for d in unique])
    return [domain for domain, available in zip(unique, results) if available]


def score_candidate(
    domain: str,
    target_keywords: list[str],
    tension_index: float,
    nic_ground_truth: list[str],
) -> float:
    """
    Score domain for pre-registration priority (0.0–1.0).

    +0.3 top-3 TLD (.space, .online, .site)
    +0.3 contains high-tension narrative keyword
    +0.2 rapidfuzz NIC similarity > 0.75
    +0.2 matches confirmed historical APT36 naming pattern

    Recommend registration when score > 0.7.
    """
    domain = _normalize_domain(domain)
    score = 0.0

    top3_tlds = APT36_PREFERRED_TLDS[:3]
    if any(domain.endswith(tld) for tld in top3_tlds):
        score += 0.3

    name_lower = domain.split(".")[0]
    narrative_hit = any(
        kw.replace("-", "") in name_lower.replace("-", "")
        for kw in target_keywords
    )
    if narrative_hit and tension_index >= 0.5:
        score += 0.3
    elif narrative_hit:
        score += 0.15

    # NIC ground-truth similarity via rapidfuzz.
    nic_score, _ = compute_similarity(domain)
    if nic_ground_truth:
        best = 0.0
        for nic_domain in nic_ground_truth:
            nic_sim, _ = compute_similarity(f"{name_lower}.{nic_domain.split('.')[-1]}")
            best = max(best, nic_sim)
        nic_score = max(nic_score, best)

    if nic_score > 0.75:
        score += 0.2

    if _matches_historical_apt36_pattern(domain, target_keywords):
        score += 0.2

    return round(min(1.0, score), 4)


def build_score_rationale(
    domain: str,
    target_keywords: list[str],
    tension_index: float,
    score: float,
) -> str:
    """Human-readable rationale for analyst review."""
    parts = [f"score={score:.2f}", f"tension={tension_index:.2f}"]
    if any(kw in domain for kw in target_keywords):
        parts.append("narrative_keyword_match")
    if score > 0.7:
        parts.append("recommended_for_preregistration")
    return "; ".join(parts)
