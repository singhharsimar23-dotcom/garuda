# All sources are public, free, and do not require special access

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
from typing import Any

import httpx
from bs4 import BeautifulSoup
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

from garuda.config import settings
from garuda.modules.attribution.rag.vector_db import (
    chunk_text,
    embed_and_upsert,
    init_vector_db,
    load_model,
)

logger = logging.getLogger("garuda.attribution.rag.corpus_builder")

MITRE_APT36_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/groups/"
    "group--36463338-eb6e-41be-a19a-dde7de4ede5f.json"
)
OTX_SEARCH_URL = "https://otx.alienvault.com/api/v1/pulses/search"
GDELT_CISA_URL = (
    "https://api.gdeltproject.org/api/v2/doc/doc"
    "?query=site:cisa.gov+apt36+OR+india+cyber"
    "&mode=artlist&format=json&maxrecords=20"
)


def _strip_html(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


async def ingest_mitre_attck_apt36(
    client: QdrantClient,
    model: SentenceTransformer,
) -> int:
    """
    MITRE ATT&CK G0134 (Transparent Tribe / APT36).
    Parse STIX bundle. Extract description + technique references as text chunks.
    Tag: actor="APT36"
    """
    chunks: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as http:
        response = await http.get(MITRE_APT36_URL)
        response.raise_for_status()
        bundle = response.json()

    objects = bundle.get("objects", [])
    group_obj = next((o for o in objects if o.get("type") == "intrusion-set"), None)
    if group_obj:
        description = group_obj.get("description", "")
        name = group_obj.get("name", "APT36")
        source = f"MITRE ATT&CK {name}"
        chunks.extend(chunk_text(description, source=source, actor="APT36"))

    technique_refs: list[str] = []
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
            ref = obj.get("target_ref", "")
            if ref.startswith("attack-pattern--"):
                technique_refs.append(ref)

    ext_refs = group_obj.get("external_references", []) if group_obj else []
    mitre_id = next((r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"), "G0134")
    technique_text = (
        f"MITRE ATT&CK group {mitre_id} technique references: "
        + ", ".join(sorted(set(technique_refs)))
    )
    chunks.extend(
        chunk_text(
            technique_text,
            source=f"MITRE ATT&CK {mitre_id} techniques",
            actor="APT36",
        )
    )

    return await embed_and_upsert(client, model, chunks)


async def ingest_otx_pulses(
    api_key: str,
    client: QdrantClient,
    model: SentenceTransformer,
) -> int:
    """
    OTX pulses tagged apt36, transparenttribe.
    For each pulse: name + description + tlp as one chunk.
    Tag: actor="APT36", date=pulse.created
    """
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    queries = ["apt36", "transparenttribe"]
    seen_ids: set[str] = set()
    chunks: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as http:
        for q in queries:
            response = await http.get(
                OTX_SEARCH_URL,
                params={"q": q, "limit": 100},
                headers=headers,
            )
            response.raise_for_status()
            for pulse in response.json().get("results", []):
                pulse_id = str(pulse.get("id", ""))
                if not pulse_id or pulse_id in seen_ids:
                    continue
                seen_ids.add(pulse_id)
                name = pulse.get("name", "")
                description = pulse.get("description", "") or ""
                tlp = pulse.get("tlp", "")
                created = pulse.get("created", "")
                text = f"{name}\n{description}\nTLP: {tlp}".strip()
                source = f"OTX Pulse {pulse_id}: {name}"
                chunks.extend(
                    chunk_text(text, source=source, actor="APT36", date=created)
                )

    return await embed_and_upsert(client, model, chunks)


async def ingest_garuda_confirmed_alerts(
    supabase_client,
    client: QdrantClient,
    model: SentenceTransformer,
) -> int:
    """
    GARUDA's own confirmed alerts — highest-weight ground truth.
    Query: alerts WHERE status='confirmed' ORDER BY detected_at DESC LIMIT 500
    Tag: actor="APT36" (or campaign actor if known), source="GARUDA_CONFIRMED"
    """
    if supabase_client is None:
        logger.warning("[corpus_builder] Supabase unavailable — skipping GARUDA confirmed alerts")
        return 0

    response = (
        supabase_client.table("alerts")
        .select("id,domain,score,sector,signals,status,detected_at,registrar,hosting_asn")
        .eq("status", "confirmed")
        .order("detected_at", desc=True)
        .limit(500)
        .execute()
    )
    rows = response.data or []
    chunks: list[dict[str, Any]] = []
    for row in rows:
        signals = row.get("signals") or {}
        if isinstance(signals, str):
            try:
                signals = json.loads(signals)
            except json.JSONDecodeError:
                signals = {}
        actor = signals.get("attributed_actor") or signals.get("campaign_actor") or "APT36"
        text = (
            f"GARUDA confirmed alert {row.get('id')}: domain={row.get('domain')} "
            f"score={row.get('score')} sector={row.get('sector')} "
            f"registrar={row.get('registrar')} hosting_asn={row.get('hosting_asn')} "
            f"signals={json.dumps(signals, default=str)}"
        )
        source = f"GARUDA_CONFIRMED:{row.get('id')}"
        date = str(row.get("detected_at", ""))
        chunks.extend(chunk_text(text, source=source, actor=actor, date=date))

    return await embed_and_upsert(client, model, chunks)


async def ingest_cisa_advisories(
    client: QdrantClient,
    model: SentenceTransformer,
) -> int:
    """
    CISA AA advisories mentioning APT36, Pakistan, or India.
    GDELT DOC 2.0 query for CISA advisories; fetch each article URL via httpx.
    """
    chunks: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as http:
        gdelt_response = await http.get(GDELT_CISA_URL)
        gdelt_response.raise_for_status()
        articles = gdelt_response.json().get("articles", [])

        for article in articles:
            url = article.get("url", "")
            title = article.get("title", "CISA Advisory")
            if not url:
                continue
            try:
                page = await http.get(url)
                page.raise_for_status()
                body = _strip_html(page.text)
            except httpx.HTTPError as exc:
                logger.warning("[corpus_builder] Failed to fetch %s: %s", url, exc)
                continue

            if not re.search(r"apt\s*36|transparent\s*tribe|pakistan|india", body, re.I):
                continue

            source = f"CISA Advisory: {title}"
            date = article.get("seendate", "")
            chunks.extend(chunk_text(body, source=source, actor="APT36", date=date))

    return await embed_and_upsert(client, model, chunks)


async def ingest_all() -> int:
    """Run all corpus ingestors. Returns total vectors upserted."""
    if not settings.QDRANT_URL or not settings.QDRANT_API_KEY:
        raise RuntimeError("QDRANT_URL and QDRANT_API_KEY must be set for corpus ingestion")

    from garuda.database import get_supabase_client

    qdrant = await init_vector_db(settings.QDRANT_URL, settings.QDRANT_API_KEY)
    model = load_model()
    supabase = get_supabase_client()

    total = 0
    total += await ingest_mitre_attck_apt36(qdrant, model)
    total += await ingest_otx_pulses(settings.OTX_API_KEY or "", qdrant, model)
    total += await ingest_garuda_confirmed_alerts(supabase, qdrant, model)
    total += await ingest_cisa_advisories(qdrant, model)
    logger.info("[corpus_builder] Ingested %d vectors total", total)
    return total


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GARUDA RAG corpus ingestion")
    parser.add_argument("--ingest-all", action="store_true", help="Run all ingest sources")
    return parser.parse_args()


async def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    args = _parse_args()
    if args.ingest_all:
        count = await ingest_all()
        print(f"Ingested {count} vectors")


if __name__ == "__main__":
    asyncio.run(_main())
