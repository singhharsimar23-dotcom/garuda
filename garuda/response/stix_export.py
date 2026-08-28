from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

import stix2
from stix2 import Bundle, DomainName, IPv4Address, Indicator, Relationship

from garuda.database import get_taxii_collections, insert_stix_objects
from garuda.detection.ioc_confidence import compute_ioc_confidence

logger = logging.getLogger("garuda.response.stix_export")


def _format_valid_from(detected_at: Optional[Any]) -> datetime:
    """Format detected_at timestamp into an aware UTC datetime for STIX2 Indicator."""
    if not detected_at:
        return datetime.now(timezone.utc)
    if isinstance(detected_at, datetime):
        return detected_at if detected_at.tzinfo else detected_at.replace(tzinfo=timezone.utc)
    if isinstance(detected_at, str):
        try:
            dt = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _map_sector_to_slug(sector: Optional[str]) -> str:
    """Map alert sector name to target collection slug."""
    if not sector:
        return "generic-government"
    sec_lower = sector.lower()
    if "nic" in sec_lower or "gov.in" in sec_lower or "portal" in sec_lower:
        return "nic-sector"
    if "drdo" in sec_lower or "defence research" in sec_lower or "r&d" in sec_lower:
        return "drdo-defence"
    if "military" in sec_lower or "army" in sec_lower or "navy" in sec_lower or "air force" in sec_lower or "hq" in sec_lower:
        return "military-hq"
    return "generic-government"


def create_stix_bundle(alert: Dict[str, Any]) -> Bundle:
    """
    Convert a GARUDA threat alert into a standard STIX 2.1 JSON Bundle
    with official custom extension properties (x_garuda_*).

    Constructs STIX 2.1 SDO/SCO objects:
        - DomainName (Observable SCO)
        - IPv4Address (Observable SCO, if hosting_ip is resolved)
        - Indicator (SDO with algorithmic confidence and India extension)
        - Relationship (based-on connection between Indicator and Domain)

    Args:
        alert: Complete threat alert dictionary.

    Returns:
        Bundle: Validated STIX2 Bundle instance.
    """
    domain = alert.get("domain", "unknown-threat.space")
    hosting_ip = alert.get("hosting_ip")
    detected_at = _format_valid_from(alert.get("detected_at") or alert.get("created_at"))
    sector = alert.get("sector") or "Critical Infrastructure"
    cluster_id = alert.get("cluster_id")
    signals = alert.get("signals") or {}

    # Compute confidence and methodology algorithmic provenance via ioc_confidence engine
    confidence, methodology = compute_ioc_confidence(signals)

    # 1. Domain Observable (SCO)
    domain_obj = DomainName(value=domain)
    objects: List[Any] = [domain_obj]

    # 2. IPv4 Observable (SCO, if present and valid)
    if hosting_ip and "." in str(hosting_ip) and hosting_ip != "127.0.0.1":
        try:
            ip_obj = IPv4Address(value=str(hosting_ip))
            objects.append(ip_obj)
        except Exception as e:
            logger.warning(f"[stix_export] Invalid IPv4 address '{hosting_ip}': {e}")

    # India-context STIX 2.1 Extension properties
    custom_props = {
        "x_garuda_target_sector": str(sector),
        "x_garuda_operator_cluster_id": str(cluster_id) if cluster_id else None,
        "x_garuda_geopolitical_event_ref": alert.get("geopolitical_ref") or "IN-PK-CYBER-OBS-2026",
        "x_garuda_confidence_methodology": methodology,
        "x_garuda_ispr_narrative_context": alert.get("llm_narrative") or alert.get("analyst_note"),
    }

    # 3. Threat Indicator (SDO)
    indicator = Indicator(
        name=f"APT36 suspected domain: {domain}",
        description=f"GARUDA threat intelligence alert targeting {sector} with algorithmic confidence {confidence}/100.",
        pattern=f"[domain-name:value = '{domain}']",
        pattern_type="stix",
        valid_from=detected_at,
        labels=["malicious-activity", "apt36", "cyber-espionage"],
        confidence=confidence,
        custom_properties=custom_props,
        allow_custom=True,
    )
    objects.append(indicator)

    # 4. Relationship (SRO)
    rel = Relationship(
        relationship_type="based-on",
        source_ref=indicator.id,
        target_ref=domain_obj.id,
    )
    objects.append(rel)

    bundle = Bundle(objects=objects, allow_custom=True)

    # Spec Validation: ensure round-trip serialization and deserialization
    serialized = bundle.serialize()
    _ = stix2.parse(serialized, allow_custom=True)

    return bundle


def export_to_json(bundle: Bundle) -> str:
    """Serialize a STIX2 Bundle into formatted pretty-printed JSON string."""
    return bundle.serialize(pretty=True)


async def persist_stix_bundle(
    alert: Dict[str, Any],
    collection_slugs: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Construct a validated STIX 2.1 bundle for an alert and persist all objects
    into the stix_objects table across appropriate TAXII collections.

    Args:
        alert: Complete threat alert record.
        collection_slugs: Optional explicit list of target collection slugs.
                          If omitted, auto-routes to:
                          - 'all-iocs'
                          - 'high-confidence' (if confidence >= 70)
                          - Sector collection ('nic-sector', 'drdo-defence', etc.)
                          - 'apt36-cluster' (if cluster_id exists)

    Returns:
        List of persisted stix_objects rows.
    """
    bundle = create_stix_bundle(alert)
    signals = alert.get("signals") or {}
    confidence, methodology = compute_ioc_confidence(signals)

    # Determine collections
    target_slugs = set(collection_slugs or [])
    if not collection_slugs:
        target_slugs.add("all-iocs")
        if confidence >= 70:
            target_slugs.add("high-confidence")
        sector_slug = _map_sector_to_slug(alert.get("sector"))
        target_slugs.add(sector_slug)
        if alert.get("cluster_id"):
            target_slugs.add("apt36-cluster")

    # Fetch available collections to map slug -> collection_id
    collections = await get_taxii_collections()
    slug_to_id: Dict[str, str] = {c["slug"]: str(c["id"]) for c in collections}

    now_iso = datetime.now(timezone.utc).isoformat()
    persisted_rows: List[Dict[str, Any]] = []

    india_context = {
        "x_garuda_target_sector": alert.get("sector") or "Critical Infrastructure",
        "x_garuda_operator_cluster_id": alert.get("cluster_id"),
        "x_garuda_geopolitical_event_ref": alert.get("geopolitical_ref") or "IN-PK-CYBER-OBS-2026",
        "x_garuda_confidence_methodology": methodology,
        "x_garuda_ispr_narrative_context": alert.get("llm_narrative") or alert.get("analyst_note"),
    }

    for slug in target_slugs:
        coll_id = slug_to_id.get(slug)
        if not coll_id:
            continue

        for obj in bundle.objects:
            raw_dict = json.loads(obj.serialize())
            # Ensure spec_version is tracked
            created_ts = raw_dict.get("created") or now_iso
            modified_ts = raw_dict.get("modified") or raw_dict.get("created") or now_iso

            row = {
                "id": f"{obj.id}:{coll_id}",
                "type": str(obj.type),
                "spec_version": "2.1",
                "created": created_ts,
                "modified": modified_ts,
                "collection_id": coll_id,
                "confidence": confidence if obj.type == "indicator" else None,
                "india_context": india_context if obj.type == "indicator" else None,
                "raw": raw_dict,
                "revoked": raw_dict.get("revoked", False),
            }
            persisted_rows.append(row)

    if persisted_rows:
        await insert_stix_objects(persisted_rows)

    return persisted_rows
