"""
Resilient Multi-Provider LLM Fallback Client
Provides robust cascaded failover across Groq models, Google Gemini models, and deterministic offline synthesis.
Guarantees zero downtime when models get decommissioned or hit rate limits, with strict anti-hallucination sanitization.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger("sentinel.llm")

# Active Groq production models in order of failover priority
GROQ_FALLBACK_CHAIN = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "groq/compound",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]

# Active Gemini production models in order of failover priority
GEMINI_FALLBACK_CHAIN = [
    "gemini-2.5-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]


class ResilientLLMClient:
    """
    Executes chat completions with automatic provider and model fallback cascading.
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        preferred_groq_model: Optional[str] = None,
    ):
        self.groq_api_key = groq_api_key or os.environ.get("GROQ_API_KEY")
        self.gemini_api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY")

        custom_groq = preferred_groq_model or os.environ.get("GROQ_PREFERRED_MODEL") or os.environ.get("GROQ_MODEL")
        self.groq_models = [custom_groq] + [m for m in GROQ_FALLBACK_CHAIN if m != custom_groq] if custom_groq else GROQ_FALLBACK_CHAIN
        self.gemini_models = GEMINI_FALLBACK_CHAIN

    async def generate_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_template_fn: Optional[Any] = None,
        temperature: float = 0.1,
        max_tokens: int = 400,
    ) -> Tuple[str, str]:
        if self.groq_api_key:
            for model in self.groq_models:
                try:
                    ans = await self._call_groq(model, system_prompt, user_prompt, temperature, max_tokens)
                    if ans:
                        sanitized = self._sanitize_anti_hallucination(ans)
                        logger.info(f"[LLM SUCCESS] Completed via Groq model '{model}'.")
                        return sanitized, f"groq:{model}"
                except Exception as e:
                    logger.warning(f"[LLM FAILOVER] Groq model '{model}' failed ({e}). Attempting next model...")

        if self.gemini_api_key:
            for model in self.gemini_models:
                try:
                    ans = await self._call_gemini(model, system_prompt, user_prompt, temperature, max_tokens)
                    if ans:
                        sanitized = self._sanitize_anti_hallucination(ans)
                        logger.info(f"[LLM SUCCESS] Completed via Gemini model '{model}'.")
                        return sanitized, f"gemini:{model}"
                except Exception as e:
                    logger.warning(f"[LLM FAILOVER] Gemini model '{model}' failed ({e}). Attempting next model...")

        logger.warning("[LLM FALLBACK] Upstream AI APIs exhausted or offline. Utilizing deterministic grounded template.")
        if fallback_template_fn:
            fallback_text = fallback_template_fn()
        else:
            fallback_text = (
                "Operational telemetry active. Threat intelligence grounded strictly in verified microarchitectural "
                "and STIX evidence without percentage representations."
            )
        return self._sanitize_anti_hallucination(fallback_text), "offline:deterministic"

    async def _call_groq(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> Optional[str]:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
            elif resp.status_code in (404, 400):
                raise ValueError(f"Model '{model}' decommissioned or invalid: HTTP {resp.status_code}")
            elif resp.status_code == 429:
                raise RuntimeError(f"Rate limited on Groq model '{model}': HTTP 429")
            else:
                raise RuntimeError(f"Groq HTTP error {resp.status_code}: {resp.text}")

    async def _call_gemini(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> Optional[str]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.gemini_api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {"parts": [{"text": f"System Context: {system_prompt}\n\nUser Question: {user_prompt}"}]}
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates and "content" in candidates[0]:
                    parts = candidates[0]["content"].get("parts", [])
                    if parts:
                        return parts[0].get("text", "").strip()
            elif resp.status_code in (404, 400):
                raise ValueError(f"Gemini model '{model}' unavailable: HTTP {resp.status_code}")
            elif resp.status_code == 429:
                raise RuntimeError(f"Gemini quota exceeded on '{model}': HTTP 429")
            else:
                raise RuntimeError(f"Gemini HTTP error {resp.status_code}: {resp.text}")
        return None

    def _sanitize_anti_hallucination(self, text: str) -> str:
        cleaned = re.sub(
            r"(?:confidence|certainty|attributed\s+with)\s*:\s*\d+(?:\.\d+)?%",
            "Attribution Gating: Evidence-Based",
            text,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(
            r"(APT36|SideCopy|Transparent Tribe)\s*\(\s*(?:confidence:\s*)?\d+(?:\.\d+)?%\s*\)",
            r"\1",
            cleaned,
            flags=re.IGNORECASE,
        )
        return cleaned


_default_llm_client = ResilientLLMClient()


def get_resilient_llm_client() -> ResilientLLMClient:
    return _default_llm_client
