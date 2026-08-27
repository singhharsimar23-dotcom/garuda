from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional
from stix2 import Bundle, DomainName, IPv4Address, Indicator, Relationship

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


def create_stix_bundle(alert: Dict[str, Any]) -> Bundle:
    """
    Convert a GARUDA threat alert into a standard STIX 2.1 JSON Bundle.

    Constructs STIX 2.1 SCO/SDO objects:
        - DomainName (Observable)
        - IPv4Address (Observable, if hosting_ip is resolved)
        - Indicator (Patterned detection rule with confidence score)
        - Relationship (based-on connection between Indicator and Domain)

    Args:
        alert: Complete threat alert dictionary.

    Returns:
        Bundle: Serialized STIX2 Bundle instance.
    """
    domain = alert.get("domain", "unknown-threat.space")
    hosting_ip = alert.get("hosting_ip")
    score = int(alert.get("score", 70))
    detected_at = _format_valid_from(alert.get("detected_at"))
    sector = alert.get("sector", "Critical Infrastructure")

    # 1. Domain Observable
    domain_obj = DomainName(value=domain)
    objects: list[Any] = [domain_obj]

    # 2. IPv4 Observable (if present)
    ip_obj = None
    if hosting_ip and "." in hosting_ip and hosting_ip != "127.0.0.1":
        try:
            ip_obj = IPv4Address(value=hosting_ip)
            objects.append(ip_obj)
        except Exception as e:
            logger.warning(f"[stix_export] Invalid IPv4 address '{hosting_ip}': {e}")

    # 3. Threat Indicator
    indicator = Indicator(
        name=f"APT36 suspected domain: {domain}",
        description=f"GARUDA threat intelligence alert targeting {sector} with composite score {score}/100.",
        pattern=f"[domain-name:value = '{domain}']",
        pattern_type="stix",
        valid_from=detected_at,
        labels=["malicious-activity", "apt36", "cyber-espionage"],
        confidence=score,
    )
    objects.append(indicator)

    # 4. Relationship
    rel = Relationship(
        relationship_type="based-on",
        source_ref=indicator.id,
        target_ref=domain_obj.id,
    )
    objects.append(rel)

    return Bundle(objects=objects)


def export_to_json(bundle: Bundle) -> str:
    """Serialize a STIX2 Bundle into formatted pretty-printed JSON string."""
    return bundle.serialize(pretty=True)
