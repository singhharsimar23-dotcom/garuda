"""RAG corpus ingestion, vector retrieval, and LLM attribution reasoning."""

from garuda.modules.attribution.rag.reasoner import attribute_alert
from garuda.modules.attribution.rag.vector_db import (
    COLLECTION_NAME,
    EMBEDDING_DIM,
    EMBEDDING_MODEL,
    embed_and_upsert,
    init_vector_db,
    load_model,
    retrieve,
)

__all__ = [
    "COLLECTION_NAME",
    "EMBEDDING_DIM",
    "EMBEDDING_MODEL",
    "attribute_alert",
    "embed_and_upsert",
    "init_vector_db",
    "load_model",
    "retrieve",
]
