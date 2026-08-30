"""
Acceptance and Failover Tests for Resilient Multi-Provider LLM Client.
Tests cascaded failover across Groq models, Gemini models, and offline deterministic synthesis under model decommissioning and 429 rate limits.
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from lib.resilient_llm import ResilientLLMClient, get_resilient_llm_client


class TestLLMResilience(unittest.TestCase):
    """Test suite for Multi-Provider LLM Fallback Chain."""

    def test_1_groq_primary_success(self):
        """1. Primary Groq model completes successfully when healthy."""
        client = ResilientLLMClient(groq_api_key="TEST_GROQ_KEY")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Activity aligns with APT36 execution profile."}}]
        }

        with patch("httpx.AsyncClient.post", return_value=mock_resp):
            ans, provider = asyncio.run(
                client.generate_completion(
                    system_prompt="You are GARUDA.",
                    user_prompt="Explain threat.",
                )
            )
            self.assertEqual(ans, "Activity aligns with APT36 execution profile.")
            self.assertTrue(provider.startswith("groq:"))

    def test_2_groq_decommissioned_model_fails_over_to_next_model(self):
        """2. When a Groq model is decommissioned (404), client cascades to the next active model."""
        client = ResilientLLMClient(
            groq_api_key="TEST_GROQ_KEY",
            preferred_groq_model="deprecated-llama-old",
        )

        resp_404 = MagicMock(status_code=404, text="Model deprecated")
        resp_200 = MagicMock(
            status_code=200,
            json=lambda: {"choices": [{"message": {"content": "Cascaded successfully to secondary model."}}]},
        )

        # First call 404, second call 200
        with patch("httpx.AsyncClient.post", side_effect=[resp_404, resp_200]):
            ans, provider = asyncio.run(
                client.generate_completion(
                    system_prompt="You are GARUDA.",
                    user_prompt="Explain threat.",
                )
            )
            self.assertEqual(ans, "Cascaded successfully to secondary model.")
            self.assertIn("groq:", provider)

    def test_3_groq_exhausted_fails_over_to_gemini(self):
        """3. When all Groq models fail, client cascades to Google Gemini."""
        client = ResilientLLMClient(
            groq_api_key="TEST_GROQ_KEY",
            gemini_api_key="TEST_GEMINI_KEY",
        )

        resp_500 = MagicMock(status_code=500, text="Groq Outage")
        gemini_200 = MagicMock(
            status_code=200,
            json=lambda: {
                "candidates": [{
                    "content": {"parts": [{"text": "Gemini response: activity is corroborated by microarchitectural anomalies."}]}
                }]
            },
        )

        # Fail all Groq attempts, then succeed on Gemini
        side_effects = [resp_500] * len(client.groq_models) + [gemini_200]

        with patch("httpx.AsyncClient.post", side_effect=side_effects):
            ans, provider = asyncio.run(
                client.generate_completion(
                    system_prompt="You are GARUDA.",
                    user_prompt="Explain threat.",
                )
            )
            self.assertIn("Gemini response", ans)
            self.assertTrue(provider.startswith("gemini:gemini-2.5-flash"))

    def test_4_all_providers_down_uses_deterministic_fallback(self):
        """4. When all upstream APIs are down, client uses offline grounded template without crashing."""
        client = ResilientLLMClient(
            groq_api_key="TEST_GROQ_KEY",
            gemini_api_key="TEST_GEMINI_KEY",
        )

        resp_500 = MagicMock(status_code=500, text="Service Unavailable")

        with patch("httpx.AsyncClient.post", return_value=resp_500):
            ans, provider = asyncio.run(
                client.generate_completion(
                    system_prompt="You are GARUDA.",
                    user_prompt="Explain threat.",
                    fallback_template_fn=lambda: "Deterministic offline telemetry grounding.",
                )
            )
            self.assertEqual(ans, "Deterministic offline telemetry grounding.")
            self.assertEqual(provider, "offline:deterministic")

    def test_5_anti_hallucination_sanitizes_any_provider_output(self):
        """5. Verifies anti-hallucination filter strips percentage confidence across all providers."""
        client = ResilientLLMClient(groq_api_key="TEST_GROQ_KEY")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Activity is attributed to APT36 (Confidence: 89.5%) based on L3 miss rates."}}]
        }

        with patch("httpx.AsyncClient.post", return_value=mock_resp):
            ans, _ = asyncio.run(
                client.generate_completion(
                    system_prompt="You are GARUDA.",
                    user_prompt="Explain threat.",
                )
            )
            self.assertNotIn("89.5%", ans)
            self.assertNotIn("Confidence: 89.5%", ans)
            self.assertIn("Attribution Gating: Evidence-Based", ans)


if __name__ == "__main__":
    unittest.main()
