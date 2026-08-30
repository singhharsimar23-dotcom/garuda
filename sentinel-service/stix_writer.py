"""
STIX 2.1 indicator writer for GARUDA CT Hunt and Vibeware IOC ingestion.
Writes to the stix_objects table in Supabase.

Table schema (from migrations/000_master_production_schema.sql):
  stix_objects: id (uuid), type, ioc_value, created_at, ...
  Extended by migration 013: ioc_type, malware_family, source columns.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


async def write_stix_indicator(
    supabase_client,
    domain: str,
    ip: Optional[str],
    cert: dict,
    convergence_score: float,
    garuda_score: float,
    logged_at: datetime,
    enrichment: dict,
) -> str:
    """
    Write a STIX 2.1 indicator for a CT-detected domain into stix_objects.

    Returns the STIX indicator ID (UUID string).
    """
    stix_id = f"indicator--{uuid.uuid4()}"

    # Build STIX 2.1 indicator pattern (domain or IP)
    if ip:
        pattern = f"[domain-name:value = '{domain}'] AND [ipv4-addr:value = '{ip}']"
    else:
        pattern = f"[domain-name:value = '{domain}']"

    row = {
        "id": stix_id,
        "type": "indicator",
        "spec_version": "2.1",
        "created": logged_at.isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": f"CT-detected APT36 lure domain: {domain}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": logged_at.isoformat(),
        "ioc_value": domain,
        "ioc_type": "ct_domain",
        "source": "CT_HUNT",
        # confidence is integer 0-100 per STIX 2.1 spec
        "confidence": min(100, int(convergence_score * 10)),
        "raw_indicator": {
            "domain": domain,
            "ip": ip,
            "cert_id": cert.get("id"),
            "issuer": cert.get("issuer_name"),
            "garuda_score": garuda_score,
            "convergence_score": convergence_score,
            "enrichment": enrichment,
        },
    }

    try:
        if supabase_client:
            supabase_client.table("stix_objects").upsert(
                row, on_conflict="ioc_value"
            ).execute()
            logger.info(
                f"[STIX] Written indicator for domain={domain} "
                f"convergence={convergence_score:.2f}"
            )
    except Exception as exc:
        logger.error(f"Failed to write STIX indicator domain={domain}: {exc}")

    return stix_id
