"""
GARUDA Data Quality & Truth Guards (PART 5)

Enforces strict input validation and source provenance across the ingestion pipeline.
Rejects synthetic, mock, or unverified data at the threshold.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from garuda.utils.honeypot_guard import is_own_honeypot


class DataQualityError(ValueError):
    """Raised when incoming data fails quality or provenance verification."""
    pass


VALID_SOURCES = frozenset({
    "crt.sh",
    "ct_log",
    "otx_pulse",
    "urlhaus",
    "malwarebazaar",
    "circl_pdns",
    "shodan",
    "censys",
    "robtex",
    "virustotal",
    "cisa_kev",
    "manual",
    "analyst_manual",
})


def validate_alert(domain: str, score: int, data_source: Optional[str] = None) -> None:
    """
    Validate alert before database insertion.
    Raises DataQualityError if data should be rejected.
    """
    if not domain:
        raise DataQualityError("Domain cannot be empty.")

    # Guard 1: Never accept own honeypot domains as hostile
    if is_own_honeypot(domain):
        raise DataQualityError(f"Rejected: '{domain}' is a GARUDA honeypot domain.")

    # Guard 2: Score must be computed in valid 0..100 range
    if score not in range(0, 101):
        raise DataQualityError(f"Invalid score {score} for {domain}. Must be between 0 and 100.")

    # Guard 3: Data source must be declared if provided
    if data_source and data_source.lower() not in VALID_SOURCES:
        raise DataQualityError(f"Unknown data source '{data_source}' for {domain}.")

    # Guard 4: Domain must be a valid FQDN
    clean = domain.strip().lower().lstrip("*.")
    if not re.match(
        r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$",
        clean,
    ):
        raise DataQualityError(f"Invalid domain format: {domain}")


def validate_ssh_fingerprint(fingerprint: str) -> bool:
    """
    Validate SSH SHA256 fingerprint format.
    Real format: SHA256:[A-Za-z0-9+/]{43}=
    Synthetic format: SHA256:[a-z0-9]+ (all lowercase, no special characters)
    """
    if not fingerprint:
        return False
    return bool(re.match(r"^SHA256:[A-Za-z0-9+/]{43}=$", fingerprint.strip()))


def validate_stix_object(obj: dict[str, Any], source_alert_id: Optional[str]) -> None:
    """STIX objects must have a backing alert. No orphaned STIX objects allowed."""
    if not source_alert_id:
        raise DataQualityError("STIX object rejected: missing backing source_alert_id.")
    if obj.get("spec_version") != "2.1":
        raise DataQualityError("STIX object rejected: must declare spec_version 2.1.")


def validate_rpz_entry(
    domain: str,
    confidence: int,
    source_alert_id: Optional[str] = None,
) -> None:
    """
    RPZ entries must meet strict criteria before publishing to DNS resolvers.
    Standards are absolute: no honeypots, minimum 80 confidence, and valid backing alert.
    """
    if not domain:
        raise DataQualityError("RPZ domain cannot be empty.")

    clean = domain.strip().lower().rstrip(".")
    if is_own_honeypot(clean):
        raise DataQualityError(f"RPZ rejected: '{clean}' is a GARUDA honeypot.")

    if confidence < 80:
        raise DataQualityError(
            f"RPZ rejected: '{clean}' confidence {confidence} is below the 80 threshold."
        )

    if not source_alert_id:
        raise DataQualityError(
            f"RPZ rejected: '{clean}' has no backing analyst-confirmed alert."
        )
