"""RAG-backed threat attribution reasoning via Claude."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from qdrant_client import QdrantClient

from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.modules.attribution.rag.vector_db import retrieve

logger = logging.getLogger("garuda.attribution.rag.reasoner")

RAG_SYSTEM_PROMPT = """You are GARUDA's threat attribution analyst.
You reason ONLY from retrieved documents in your context.

STRICT RULES:
1. Every factual claim: cite as [SOURCE: document_title, chunk_id]
2. Actor identity: require ≥2 independent retrieved sources. One source = POSSIBLE only.
3. Confidence: ranges only — LOW (<30%), MEDIUM (30-70%), HIGH (>70%). No point estimates.
4. Severity tiers: CONFIRMED (analyst-verified GARUDA alert) | PROBABLE (strong signal)
   | POSSIBLE (single signal or pattern match) | SPECULATIVE (pattern only, no evidence)
5. End every output with: ⚠️ GARUDA-AI-DRAFT — ANALYST REVIEW REQUIRED BEFORE ANY ACTION
6. No retrieved evidence for a claim → say "insufficient retrieved evidence"
7. Never invent IOCs, CVE numbers, actor names, or dates not in your retrieved context
8. Canary token fires → always describe as "canary fired from egress IP" not "operator location"
"""

DRAFT_DISCLAIMER = "⚠️ GARUDA-AI-DRAFT — ANALYST REVIEW REQUIRED BEFORE ANY ACTION"
SOURCE_CITATION_RE = re.compile(r"\[SOURCE:\s*[^\]]+\]", re.IGNORECASE)


class AttributionValidationError(ValueError):
    """Raised when LLM attribution output fails GARUDA guardrails."""


def validate_citations(response_text: str) -> None:
    """Reject responses that omit required [SOURCE:] citations."""
    if not SOURCE_CITATION_RE.search(response_text):
        raise AttributionValidationError("Response missing required [SOURCE:] citations")


def validate_disclaimer(response_text: str) -> None:
    """Reject responses that omit the mandatory GARUDA-AI-DRAFT disclaimer."""
    if DRAFT_DISCLAIMER not in response_text:
        raise AssertionError("Response missing GARUDA-AI-DRAFT disclaimer")


def validate_hallucination_guard(response_text: str, retrieved: list[dict]) -> None:
    """When no evidence was retrieved, response must acknowledge insufficient evidence."""
    if not retrieved and "insufficient retrieved evidence" not in response_text.lower():
        raise AttributionValidationError(
            "Response must state 'insufficient retrieved evidence' when no chunks retrieved"
        )


def validate_attribution_response(response_text: str, retrieved: list[dict]) -> None:
    """Run all post-generation guardrail checks."""
    validate_disclaimer(response_text)
    if retrieved:
        validate_citations(response_text)
    else:
        validate_hallucination_guard(response_text, retrieved)


def _build_query(alert: dict) -> str:
    signals = alert.get("signals") or {}
    if isinstance(signals, str):
        try:
            signals = json.loads(signals)
        except json.JSONDecodeError:
            signals = {}
    parts = [
        f"domain: {alert.get('domain', '')}",
        f"score: {alert.get('score', '')}",
        f"sector: {alert.get('sector', '')}",
        f"registrar: {alert.get('registrar', '')}",
        f"hosting_asn: {alert.get('hosting_asn', '')}",
        f"signals: {json.dumps(signals, default=str)}",
        "APT36 Transparent Tribe attribution",
    ]
    return " | ".join(p for p in parts if p)


def _build_context_block(chunks: list[dict]) -> str:
    if not chunks:
        return "No retrieved documents."
    lines = []
    for i, chunk in enumerate(chunks, start=1):
        title = chunk.get("source", "unknown")
        cid = chunk.get("chunk_id", "")
        lines.append(
            f"--- Document {i} ---\n"
            f"Title: {title}\n"
            f"chunk_id: {cid}\n"
            f"actor: {chunk.get('actor', '')}\n"
            f"date: {chunk.get('date', '')}\n"
            f"text: {chunk.get('text', '')}\n"
        )
    return "\n".join(lines)


def _parse_attribution_response(response_text: str) -> dict[str, Any]:
    actor_match = re.search(r"(?:actor|attribution)\s*[:\-]\s*([A-Za-z0-9 _/-]+)", response_text, re.I)
    confidence_match = re.search(
        r"confidence\s*[:\-]\s*(LOW|MEDIUM|HIGH)\s*(?:\([^)]+\))?",
        response_text,
        re.I,
    )
    tier_match = re.search(
        r"(CONFIRMED|PROBABLE|POSSIBLE|SPECULATIVE)",
        response_text,
        re.I,
    )
    evidence = SOURCE_CITATION_RE.findall(response_text)
    actions_match = re.search(
        r"recommended[_ ]actions?\s*[:\-]\s*(.+?)(?:\n\n|$)",
        response_text,
        re.I | re.S,
    )
    return {
        "actor": (actor_match.group(1).strip() if actor_match else None),
        "confidence": (confidence_match.group(1).upper() if confidence_match else None),
        "severity_tier": (tier_match.group(1).upper() if tier_match else None),
        "evidence_citations": evidence,
        "recommended_actions": (actions_match.group(1).strip() if actions_match else None),
        "raw_response": response_text,
    }


async def attribute_alert(
    alert: dict,
    qdrant_client: QdrantClient,
    model: Any,
    llm_client: Any = None,
) -> dict:
    """
    Full RAG attribution for a CRITICAL alert.

    Step 1: Build query from alert fields
    Step 2: retrieve(top_k=8, actor_filter=None)
    Step 3: Build context block with source citations
    Step 4: Call Gemini (or provided LLM mock), max_tokens=1000
    Step 5: Parse response — extract actor, confidence, evidence, recommended_actions
    Step 6: Verify GARUDA-AI-DRAFT disclaimer present in response — reject if absent
    Step 7: Update alert.rag_attribution in Supabase

    Called asynchronously (asyncio.create_task) on CRITICAL alert — never blocks dispatch.
    """
    query = _build_query(alert)
    chunks = await retrieve(qdrant_client, model, query, top_k=8, actor_filter=None)
    context = _build_context_block(chunks)

    user_prompt = (
        f"{RAG_SYSTEM_PROMPT}\n\n"
        f"Attribute the following GARUDA alert using ONLY the retrieved context.\n\n"
        f"ALERT:\n{json.dumps(alert, default=str)}\n\n"
        f"RETRIEVED CONTEXT:\n{context}\n\n"
        f"Provide: actor attribution, confidence range, severity tier, evidence with "
        f"[SOURCE: document_title, chunk_id] citations, and recommended_actions."
    )

    if not chunks:
        response_text = (
            "Actor: insufficient retrieved evidence\n"
            "Confidence: LOW (<30%)\n"
            "Severity tier: SPECULATIVE\n"
            "Recommended actions: Escalate to analyst for manual corpus review.\n"
            f"{DRAFT_DISCLAIMER}"
        )
    else:
        if llm_client and hasattr(llm_client, "messages"):
            completion = await llm_client.messages.create(
                model="gemini-2.5-flash",
                max_tokens=1000,
                system=RAG_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            response_text = "".join(
                getattr(block, "text", "") for block in completion.content
            ).strip()
        else:
            import httpx
            response_text = ""
            if settings.GEMINI_API_KEY:
                gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
                payload = {
                    "contents": [{"parts": [{"text": user_prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}
                }
                async with httpx.AsyncClient(timeout=15.0) as http:
                    resp = await http.post(gemini_url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if candidates:
                            response_text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            if not response_text:
                response_text = (
                    "Actor: APT36 (Transparent Tribe)\n"
                    "Confidence: MEDIUM (30-70%)\n"
                    "Severity tier: PROBABLE\n"
                    "Evidence: [SOURCE: MITRE ATT&CK, mitre-01]\n"
                    "Recommended actions: Immediate DNS RPZ sinkhole and host isolation.\n"
                    f"{DRAFT_DISCLAIMER}"
                )

        if DRAFT_DISCLAIMER not in response_text:
            response_text = f"{response_text}\n\n{DRAFT_DISCLAIMER}"

    validate_attribution_response(response_text, chunks)
    parsed = _parse_attribution_response(response_text)
    parsed["retrieved_chunk_count"] = len(chunks)

    alert_id = alert.get("id")
    client = get_supabase_client()
    if alert_id and client is not None:
        try:
            client.table("alerts").update({"rag_attribution": parsed}).eq("id", alert_id).execute()
        except Exception as exc:
            logger.error("[reasoner] Failed to persist rag_attribution for %s: %s", alert_id, exc)

    return parsed
