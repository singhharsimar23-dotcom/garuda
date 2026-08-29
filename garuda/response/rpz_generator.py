"""
GARUDA — Response Policy Zone (RPZ) DNS Defense Engine

Generates RFC-conformant BIND DNS Response Policy Zone (RPZ) files
for recursive resolvers across Indian defence networks and national infrastructure.

RPZ Policy & Trade-Off Documentation:
------------------------------------
An RPZ feed published to recursive DNS resolvers causes IMMEDIATE and TOTAL
resolution failure for all downstream endpoints. If an attacker domain is blocked,
threat actor C2 communications are severed. BUT if a legitimate government
or military domain is blocked (False Positive), critical defence infrastructure
goes dark.

Therefore:
1. RPZ publish threshold is strictly gated at confidence >= 80 (RPZ_MIN_CONFIDENCE).
2. Domains ending in protected national TLDs/zones (.gov.in, .nic.in, .mil.in, .res.in)
   or listed in the sovereign whitelist are NEVER assigned an 'nxdomain' action.
3. Every entry has an added_at timestamp and expires automatically after 90 days
   (RPZ_EXPIRY_DAYS) unless actively re-corroborated.
4. Entries are soft-deleted via 'removed_at', preserving a tamper-evident audit trail.
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from garuda.config import settings
from garuda.database import (
    expire_stale_rpz_entries,
    get_active_rpz_entries,
    get_all_rpz_entries,
    soft_delete_rpz_entry,
    upsert_rpz_entry,
)

logger = logging.getLogger("garuda.response.rpz_generator")

# Protected sovereign apexes that can NEVER be blocked by RPZ
PROTECTED_NATIONAL_SUFFIXES: Tuple[str, ...] = (
    ".gov.in",
    ".nic.in",
    ".mil.in",
    ".res.in",
    ".ac.in",
    ".edu.in",
    ".drdo.gov.in",
    ".mod.gov.in",
    ".isro.gov.in",
    ".afcert.mod.gov.in",
)

# Standard BIND RPZ Pass-through target
RPZ_PASSTHRU_TARGET: str = "rpz-passthru."


def is_domain_protected(domain: str) -> bool:
    """
    Check if a domain is part of protected Indian sovereign or educational infrastructure.
    Guarantees that no legitimate gov.in or military domain is ever NXDOMAIN'd.
    """
    clean = domain.strip().lower().rstrip(".")
    if not clean:
        return True
    for suffix in PROTECTED_NATIONAL_SUFFIXES:
        if clean.endswith(suffix.rstrip(".")) or clean == suffix.lstrip("."):
            return True
    return False


def validate_rpz_eligibility(
    domain: str,
    confidence: int,
    action: str = "nxdomain",
    override_protection: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Verify if a domain meets all quality and safety criteria for RPZ publication.

    Returns:
        Tuple[bool, Optional[str]]: (is_eligible, failure_reason)
    """
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return False, "Domain cannot be empty."

    # Validate basic domain format
    domain_regex = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if not domain_regex.match(clean_domain):
        return False, f"Invalid domain name format: '{clean_domain}'"

    # Action check
    act = action.lower().strip()
    if act not in ("nxdomain", "passthru"):
        return False, f"Unsupported RPZ action '{action}'. Must be 'nxdomain' or 'passthru'."

    # Strict confidence threshold
    if confidence < settings.RPZ_MIN_CONFIDENCE and act == "nxdomain":
        return (
            False,
            f"Confidence score {confidence} is below the strict RPZ threshold ({settings.RPZ_MIN_CONFIDENCE}). "
            "A blocking feed with false positives is unacceptable for recursive resolvers.",
        )

    # Honeypot self-protection safeguard (FIX-01)
    from garuda.utils.honeypot_guard import is_own_honeypot
    if is_own_honeypot(clean_domain):
        return (
            False,
            f"Domain '{clean_domain}' is a GARUDA honeypot lure. Refusing to block own honeypot in RPZ.",
        )

    # Sovereign protection safeguard
    if act == "nxdomain" and not override_protection and is_domain_protected(clean_domain):
        return (
            False,
            f"Domain '{clean_domain}' is part of protected sovereign national infrastructure. "
            "NXDOMAIN action is strictly rejected.",
        )

    return True, None


def compute_zone_serial(dt: Optional[datetime] = None, revision: int = 1) -> str:
    """
    Compute standard BIND zone serial number in YYYYMMDDNN format.
    Example: 2026082701
    """
    target_dt = dt or datetime.now(timezone.utc)
    date_part = target_dt.strftime("%Y%m%d")
    rev_part = f"{min(99, max(1, revision)):02d}"
    return f"{date_part}{rev_part}"


def render_rpz_zone_file(
    entries: List[Dict[str, Any]],
    origin: Optional[str] = None,
    ttl: Optional[int] = None,
    soa_mname: Optional[str] = None,
    soa_rname: Optional[str] = None,
    serial: Optional[str] = None,
) -> str:
    """
    Render a list of RPZ entries into a fully conformant BIND 9 Response Policy Zone file.

    Format:
      - $TTL directive
      - SOA record with 5 timer fields (Refresh: 1h, Retry: 10m, Expire: 1w, Minimum/Negative TTL: 5m)
      - NS record pointing to the sovereign RPZ authority
      - Rule for each domain:
          <domain> CNAME .           (for nxdomain)
          *.<domain> CNAME .         (wildcard child domains)
          <domain> CNAME rpz-passthru. (for passthru allowlists)
    """
    zone_origin = origin or settings.RPZ_ZONE_ORIGIN
    zone_ttl = ttl or settings.RPZ_ZONE_TTL
    mname = soa_mname or settings.RPZ_SOA_MNAME
    rname = soa_rname or settings.RPZ_SOA_RNAME
    zone_serial = serial or compute_zone_serial()

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        f"$TTL {zone_ttl}",
        f"$ORIGIN {zone_origin}.",
        "",
        "; ==============================================================================",
        "; GARUDA SOVEREIGN CTI - DNS RESPONSE POLICY ZONE (RPZ)",
        f"; Generated: {now_iso}",
        f"; Zone Serial: {zone_serial}",
        f"; Active Rules: {len(entries)}",
        "; Authority: National Threat Intelligence Gateway for Indian Cyberspace",
        "; ==============================================================================",
        "",
        f"@ IN SOA {mname} {rname} (",
        f"    {zone_serial} ; Serial number (YYYYMMDDNN)",
        "    3600       ; Refresh (1 hour)",
        "    600        ; Retry (10 minutes)",
        "    604800     ; Expire (1 week)",
        f"    {zone_ttl}        ; Minimum / Negative Cache TTL",
        ")",
        "",
        f"@ IN NS {mname}",
        "",
        "; ==============================================================================",
        "; RPZ Triggers (QNAME policy rules)",
        "; ==============================================================================",
        "",
    ]

    for entry in entries:
        domain = entry.get("domain", "").strip().rstrip(".")
        if not domain:
            continue

        action = (entry.get("action") or "nxdomain").lower().strip()
        confidence = entry.get("confidence", 0)
        source_id = entry.get("source_stix_object_id") or "automated"

        if action == "nxdomain":
            target = "."
        elif action == "passthru":
            target = RPZ_PASSTHRU_TARGET
        else:
            target = "."

        lines.append(f"; Threat Indicator: {domain} | Conf: {confidence} | Source: {source_id}")
        lines.append(f"{domain} CNAME {target}")
        lines.append(f"*.{domain} CNAME {target}")
        lines.append("")

    return "\n".join(lines) + "\n"


async def generate_active_rpz_zone() -> str:
    """Fetch all active RPZ entries from database and render complete BIND zone file."""
    entries = await get_active_rpz_entries()
    return render_rpz_zone_file(entries)


async def publish_domain_to_rpz(
    domain: str,
    confidence: int,
    source_stix_object_id: Optional[str] = None,
    action: str = "nxdomain",
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Publish a threat domain to the RPZ feed with complete validation and policy enforcement.

    Returns:
        Tuple[bool, str, Optional[Dict[str, Any]]]: (success, message, created_or_updated_row)
    """
    eligible, reason = validate_rpz_eligibility(
        domain=domain,
        confidence=confidence,
        action=action,
    )
    if not eligible:
        logger.warning(f"[rpz] Publication rejected for '{domain}': {reason}")
        return False, reason or "Validation failed", None

    row = await upsert_rpz_entry(
        domain=domain,
        confidence=confidence,
        source_stix_object_id=source_stix_object_id,
        action=action,
    )
    logger.info(f"[rpz] Successfully published '{domain}' (conf={confidence}, action={action}) to RPZ")
    return True, "Published to RPZ", row
