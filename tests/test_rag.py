"""
GARUDA Session 11 Acceptance Tests — RAG Attribution

Tests cover embedding dimensions, Qdrant collection config, actor filtering,
and reasoner guardrails (citations, disclaimer, hallucination guard).
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
from qdrant_client import QdrantClient, models


class TestRagVectorDb(unittest.TestCase):
    """Vector store unit tests — offline where possible."""

    def test_embedding_dimension(self):
        from garuda.modules.attribution.rag.vector_db import EMBEDDING_DIM, load_model

        model = load_model()
        vector = model.encode("APT36 Transparent Tribe test query", show_progress_bar=False)
        arr = np.asarray(vector)
        if arr.ndim == 2:
            arr = arr[0]
        self.assertEqual(arr.shape, (EMBEDDING_DIM,))
        self.assertEqual(EMBEDDING_DIM, 384)

    def test_qdrant_collection_384(self):
        from garuda.modules.attribution.rag.vector_db import COLLECTION_NAME, EMBEDDING_DIM

        client = QdrantClient(":memory:")
        client.create_collection(
            COLLECTION_NAME,
            vectors_config=models.VectorParams(
                size=EMBEDDING_DIM,
                distance=models.Distance.COSINE,
            ),
        )
        info = client.get_collection(COLLECTION_NAME)
        self.assertEqual(info.config.params.vectors.size, 384)
        self.assertNotEqual(info.config.params.vectors.size, 768)

    def test_retrieval_actor_filter(self):
        from garuda.modules.attribution.rag.vector_db import (
            COLLECTION_NAME,
            EMBEDDING_DIM,
            embed_and_upsert,
            load_model,
            retrieve,
        )

        async def _run() -> None:
            client = QdrantClient(":memory:")
            client.create_collection(
                COLLECTION_NAME,
                vectors_config=models.VectorParams(
                    size=EMBEDDING_DIM,
                    distance=models.Distance.COSINE,
                ),
            )
            model = load_model()
            apt36_text = "APT36 Transparent Tribe Pakistan targeting Indian defence sector"
            apt41_text = "APT41 Chinese state-sponsored espionage campaign"
            await embed_and_upsert(
                client,
                model,
                [
                    {
                        "text": apt36_text,
                        "source": "test-apt36",
                        "actor": "APT36",
                        "date": "2024-01-01",
                        "chunk_id": "apt36-chunk-1",
                    },
                    {
                        "text": apt41_text,
                        "source": "test-apt41",
                        "actor": "APT41",
                        "date": "2024-01-01",
                        "chunk_id": "apt41-chunk-1",
                    },
                ],
            )
            results = await retrieve(
                client,
                model,
                "APT36 India cyber threat",
                top_k=8,
                actor_filter="APT36",
            )
            self.assertTrue(results)
            for hit in results:
                self.assertEqual(hit["actor"], "APT36")
                self.assertNotEqual(hit["actor"], "APT41")

        asyncio.run(_run())


class TestRagReasoner(unittest.TestCase):
    """Reasoner guardrail tests — no live LLM calls."""

    def test_citation_required(self):
        from garuda.modules.attribution.rag.reasoner import (
            AttributionValidationError,
            validate_attribution_response,
        )

        bad = (
            "Actor: APT36\nConfidence: HIGH (>70%)\n"
            "⚠️ GARUDA-AI-DRAFT — ANALYST REVIEW REQUIRED BEFORE ANY ACTION"
        )
        retrieved = [{"source": "MITRE", "chunk_id": "abc123", "text": "evidence"}]
        with self.assertRaises(AttributionValidationError):
            validate_attribution_response(bad, retrieved)

    def test_hallucination_guard(self):
        from garuda.modules.attribution.rag.reasoner import (
            AttributionValidationError,
            validate_attribution_response,
        )

        bad = (
            "Actor: APT36\nConfidence: HIGH (>70%)\n"
            "⚠️ GARUDA-AI-DRAFT — ANALYST REVIEW REQUIRED BEFORE ANY ACTION"
        )
        with self.assertRaises(AttributionValidationError):
            validate_attribution_response(bad, [])

        good = (
            "Actor: insufficient retrieved evidence\n"
            "⚠️ GARUDA-AI-DRAFT — ANALYST REVIEW REQUIRED BEFORE ANY ACTION"
        )
        validate_attribution_response(good, [])

    def test_draft_disclaimer(self):
        from garuda.modules.attribution.rag.reasoner import validate_disclaimer

        with self.assertRaises(AssertionError):
            validate_disclaimer("Actor: APT36 [SOURCE: MITRE, chunk-1]")

    @patch("garuda.modules.attribution.rag.reasoner.get_supabase_client")
    def test_attribute_alert_no_evidence_path(self, mock_supabase):
        from garuda.modules.attribution.rag.reasoner import attribute_alert

        mock_supabase.return_value = None

        async def _run() -> dict:
            from garuda.modules.attribution.rag.vector_db import COLLECTION_NAME, EMBEDDING_DIM

            qdrant = QdrantClient(":memory:")
            qdrant.create_collection(
                COLLECTION_NAME,
                vectors_config=models.VectorParams(
                    size=EMBEDDING_DIM,
                    distance=models.Distance.COSINE,
                ),
            )
            model = MagicMock()
            model.encode.return_value = np.zeros(384, dtype=np.float32)
            anthropic_client = AsyncMock()
            alert = {"id": "test-alert", "domain": "evil-modgov.space", "score": 90}
            return await attribute_alert(alert, qdrant, model, anthropic_client)

        result = asyncio.run(_run())
        self.assertIn("raw_response", result)
        self.assertIn("insufficient retrieved evidence", result["raw_response"].lower())


if __name__ == "__main__":
    unittest.main()
