"""
Canary document factory — synthetic lure documents with canarytokens.org tracking.

Docs: https://docs.canarytokens.org/guide/
VERIFY: POST endpoint and field names before production use.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger("garuda.modules.canary.factory")

CANARYTOKENS_BASE = "https://canarytokens.org/generate"
CANARY_API_ENABLED = True

CANARY_DOCUMENT_THEMES: list[dict[str, str]] = [
    {
        "filename": "CDS_Directive_Armed_Forces_Strategic_Update_Q3_2026.pdf",
        "sector": "MOD_CDS",
        "doc_type": "pdf",
    },
    {
        "filename": "MoD_Procurement_Standing_Committee_Minutes_Aug2026.docx",
        "sector": "MOD_PROCUREMENT",
        "doc_type": "msword",
    },
    {
        "filename": "DRDO_DARE_Project_Status_Review_Monsoon2026.xlsx",
        "sector": "DRDO_DARE",
        "doc_type": "excel",
    },
    {
        "filename": "CAIR_Annual_Technical_Review_2025_26.pdf",
        "sector": "DRDO_CAIR",
        "doc_type": "pdf",
    },
    {
        "filename": "IAF_Operational_Readiness_Assessment_Southwest_Command.docx",
        "sector": "IAF_OPS",
        "doc_type": "msword",
    },
    {
        "filename": "Indian_Navy_Fleet_Readiness_H2_2026.xlsx",
        "sector": "NAVY_OPS",
        "doc_type": "excel",
    },
    {
        "filename": "Army_HQ_Cybersecurity_Audit_Findings_2026.pdf",
        "sector": "ARMY_HQ",
        "doc_type": "pdf",
    },
    {
        "filename": "NIC_Security_Advisory_Critical_Systems_Aug2026.pdf",
        "sector": "NIC",
        "doc_type": "pdf",
    },
    {
        "filename": "BOSS_Linux_9_Security_Patch_Notes_Critical.pdf",
        "sector": "BOSS_LINUX",
        "doc_type": "pdf",
    },
    {
        "filename": "ISRO_Gaganyaan_Mission_Control_Update_Q3.docx",
        "sector": "ISRO",
        "doc_type": "msword",
    },
]

_DOC_TYPE_MAP = {
    "pdf": "pdf",
    "msword": "msword",
    "excel": "excel",
    "docx": "msword",
    "xlsx": "excel",
}


async def create_canary_token(
    doc_type: str,
    memo: str,
    webhook_url: str,
    *,
    document_theme: Optional[str] = None,
    sector: Optional[str] = None,
) -> dict | None:
    """
    POST to canarytokens.org to create a tracking token.

    Returns {token, download_url, auth_token} or None on failure.
    """
    if not CANARY_API_ENABLED:
        logger.info("[canary] CANARY_API_ENABLED=False — skipping token creation")
        return None

    token_type = _DOC_TYPE_MAP.get(doc_type.lower(), doc_type)
    payload = {
        "type": token_type,
        "memo": memo,
        "webhook_url": webhook_url,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(CANARYTOKENS_BASE, json=payload)
            if resp.status_code >= 400:
                logger.warning("[canary] Token creation failed (%s): %s", resp.status_code, resp.text)
                return None
            data = resp.json()
    except Exception as exc:
        logger.warning("[canary] Token creation error: %s", exc)
        return None

    token = data.get("token") or data.get("canarytoken")
    auth_token = data.get("auth_token") or data.get("auth")
    if not token:
        logger.warning("[canary] Response missing token field: %s", data)
        return None

    download_url = data.get("url") or f"https://canarytokens.org/download/{token}"

    record = {
        "token": str(token),
        "token_type": token_type,
        "memo": memo,
        "document_theme": document_theme,
        "sector": sector,
        "webhook_url": webhook_url,
        "auth_token": auth_token,
        "download_url": download_url,
    }

    from garuda.database import upsert_canary_token

    await upsert_canary_token(record)
    return {"token": str(token), "download_url": download_url, "auth_token": auth_token}


async def create_themed_canary_batch(webhook_url: str) -> list[dict]:
    """Create one canary token per document theme."""
    created: list[dict] = []
    for theme in CANARY_DOCUMENT_THEMES:
        result = await create_canary_token(
            doc_type=theme["doc_type"],
            memo=f"GARUDA canary: {theme['filename']}",
            webhook_url=webhook_url,
            document_theme=theme["filename"],
            sector=theme["sector"],
        )
        if result:
            created.append({**theme, **result})
    return created
