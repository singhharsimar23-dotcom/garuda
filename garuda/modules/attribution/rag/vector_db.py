"""Qdrant vector store helpers for GARUDA threat-intel RAG."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

from qdrant_client import QdrantClient, models
try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = Any  # type: ignore

logger = logging.getLogger("garuda.attribution.rag.vector_db")

COLLECTION_NAME = "garuda_threat_intel"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384  # CORRECT dimension — v2.0 spec was wrong about this

CHUNK_SIZE = 400
CHUNK_OVERLAP = 100


def _chunk_id_for(source: str, offset: int) -> str:
    """Deterministic chunk_id from source + byte offset."""
    raw = f"{source}:{offset}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _point_id(chunk_id: str) -> int:
    return int(hashlib.sha256(chunk_id.encode("utf-8")).hexdigest()[:16], 16)


def chunk_text(
    text: str,
    source: str,
    actor: str | None = None,
    date: str | None = None,
) -> list[dict[str, Any]]:
    """
    Split text into 400-character windows with 100-character overlap.
    Returns chunk dicts ready for embed_and_upsert.
    """
    cleaned = " ".join(text.split())
    if not cleaned:
        return []

    chunks: list[dict[str, Any]] = []
    step = max(CHUNK_SIZE - CHUNK_OVERLAP, 1)
    offset = 0
    while offset < len(cleaned):
        piece = cleaned[offset : offset + CHUNK_SIZE]
        if not piece:
            break
        cid = _chunk_id_for(source, offset)
        chunks.append(
            {
                "text": piece,
                "source": source,
                "actor": actor,
                "date": date,
                "chunk_id": cid,
            }
        )
        if offset + CHUNK_SIZE >= len(cleaned):
            break
        offset += step
    return chunks


async def init_vector_db(qdrant_url: str, qdrant_api_key: str) -> QdrantClient:
    """
    Initialise Qdrant client. Create collection if absent.
    Qdrant free cloud tier: 1GB storage, no query limit.
    Sign up: cloud.qdrant.io → free tier → get URL + API key.
    """

    def _init() -> QdrantClient:
        client = QdrantClient(url=qdrant_url, api_key=qdrant_api_key)
        try:
            client.get_collection(COLLECTION_NAME)
        except Exception:
            logger.info("Creating Qdrant collection %s (dim=%d)", COLLECTION_NAME, EMBEDDING_DIM)
            client.create_collection(
                COLLECTION_NAME,
                vectors_config=models.VectorParams(
                    size=EMBEDDING_DIM,
                    distance=models.Distance.COSINE,
                ),
            )
        return client

    return await asyncio.to_thread(_init)


def load_model() -> SentenceTransformer:
    """
    Load sentence-transformers model locally. First run downloads ~90MB.
    Cached at ~/.cache/huggingface/hub after first download.
    GitHub Actions: cache this path with actions/cache to save 45s per run.
    Zero per-query cost — runs entirely on CPU in GitHub Actions ubuntu-latest.
    """
    return SentenceTransformer(EMBEDDING_MODEL)


async def embed_and_upsert(
    client: QdrantClient,
    model: SentenceTransformer,
    chunks: list[dict],  # [{text, source, actor, date, chunk_id}]
) -> int:
    """
    Embed text chunks and upsert to Qdrant.
    Chunking: 400 characters with 100 character overlap (simple, no NLTK needed).
    chunk_id: deterministic hash(source + offset) — enables safe re-ingestion.
    Returns count of vectors upserted.
    """
    if not chunks:
        return 0

    def _upsert() -> int:
        texts = [c["text"] for c in chunks]
        vectors = model.encode(texts, show_progress_bar=False)
        points = []
        for chunk, vector in zip(chunks, vectors):
            chunk_id = chunk.get("chunk_id") or _chunk_id_for(chunk["source"], 0)
            points.append(
                models.PointStruct(
                    id=_point_id(chunk_id),
                    vector=vector.tolist(),
                    payload={
                        "text": chunk["text"],
                        "source": chunk["source"],
                        "actor": chunk.get("actor"),
                        "date": chunk.get("date"),
                        "chunk_id": chunk_id,
                    },
                )
            )
        client.upsert(collection_name=COLLECTION_NAME, points=points)
        return len(points)

    return await asyncio.to_thread(_upsert)


async def retrieve(
    client: QdrantClient,
    model: SentenceTransformer,
    query: str,
    top_k: int = 8,
    actor_filter: str | None = None,
) -> list[dict]:
    """
    Retrieve top-K most relevant chunks.
    Optional filter: must_match actor field in Qdrant payload.
    Returns: [{text, source, actor, date, score, chunk_id}]
    """

    def _search() -> list[dict]:
        query_vector = model.encode(query, show_progress_bar=False).tolist()
        query_filter = None
        if actor_filter:
            query_filter = models.Filter(
                must=[
                    models.FieldCondition(
                        key="actor",
                        match=models.MatchValue(value=actor_filter),
                    )
                ]
            )
        hits = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=query_vector,
            limit=top_k,
            query_filter=query_filter,
        )
        return [
            {
                "text": hit.payload.get("text", ""),
                "source": hit.payload.get("source", ""),
                "actor": hit.payload.get("actor"),
                "date": hit.payload.get("date"),
                "chunk_id": hit.payload.get("chunk_id", ""),
                "score": float(hit.score),
            }
            for hit in hits
            if hit.payload
        ]

    return await asyncio.to_thread(_search)
