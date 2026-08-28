"""
GARUDA — CPE / Product Fingerprint Matching for EASM × KEV Correlation

This module provides the single deterministic function used to decide whether
an EASM finding's product_fingerprint plausibly matches a CISA KEV entry.

Design constraints (non-negotiable):
  - No LLM calls. Nondeterministic matching in the alert critical path is a
    reliability risk: the same (fingerprint, KEV entry) pair must always produce
    the same True/False answer.
  - No external network calls. Pure string logic only.
  - Fully unit-testable with offline fixtures (see tests/test_easm.py).
  - Two consecutive False positives on the same (finding, CVE) pair cost an
    analyst more time than one missed True Positive. Prefer precision over recall.

Matching algorithm (applied in order, short-circuit on first True):

  Rule 1 — CPE component match:
      If product_fingerprint contains a CPE 2.2/2.3 URI (e.g. "cpe:/a:fortinet:fortios:7.0"),
      extract the vendor and product components and compare against the KEV entry's
      vendorProject and product fields (case-insensitive, stripped).
      Match requires BOTH vendor AND product to agree.

  Rule 2 — Normalised keyword match:
      Tokenise the KEV entry's vendorProject and product into lowercase alpha-only
      words. Require at least MIN_KEYWORD_TOKENS (2) to match against the lowercase
      fingerprint. This catches banners like "FortiGate-60F v7.0.12" against
      a KEV entry for vendorProject=Fortinet, product=FortiOS.

  Rule 3 — Default:
      Return False.

Severity mapping:
  compute_severity() derives a severity tier ('critical' | 'high' | 'medium' | 'low')
  from the CVSS base score returned by NVD (if available) or from the CISA KEV
  known_ransomware_use flag as a fallback. This function is also used by the
  cve_kev_matches.severity_computed column — keeping the logic here ensures
  the mapping is testable and auditable.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# Minimum number of distinct keyword tokens that must match for Rule 2 to fire.
# Set to 2 to prevent single-word false positives (e.g., "Cisco" matching every
# Cisco product regardless of which one is in the fingerprint).
MIN_KEYWORD_TOKENS: int = 2

# Regex to detect a CPE URI/WFN in a fingerprint string.
# Matches cpe:/a:vendor:product:version or cpe:2.3:a:vendor:product:version:...
_CPE_PATTERN = re.compile(
    r"cpe[:/](?:2\.3:)?[aoh]:([^:]+):([^:]+)",
    re.IGNORECASE,
)

# Characters stripped when tokenising keyword strings.
_ALPHA_ONLY = re.compile(r"[^a-z0-9]")


def _tokenise(text: str) -> List[str]:
    """Lower-case and split text into alpha-numeric tokens, filtering empties."""
    return [t for t in _ALPHA_ONLY.sub(" ", text.lower()).split() if len(t) >= 2]


def _extract_cpe_components(fingerprint: str) -> Optional[Tuple[str, str]]:
    """
    Parse a CPE URI from fingerprint and return (vendor, product).
    Returns None if no CPE URI is present.
    """
    m = _CPE_PATTERN.search(fingerprint)
    if not m:
        return None
    vendor = m.group(1).lower().strip()
    product = m.group(2).lower().strip()
    return vendor, product


def fingerprint_matches_cve(
    product_fingerprint: str,
    kev_entry: Dict[str, Any],
) -> bool:
    """
    Determine whether an EASM product fingerprint plausibly matches a CISA KEV entry.

    Args:
        product_fingerprint: Raw banner / product string from Shodan or Censys.
                             Examples:
                               "FortiGate-60F v7.0.12"
                               "cpe:/a:fortinet:fortios:7.0.12"
                               "Citrix ADC 13.0-84.11"
                               "Microsoft Windows Server 2019 (RDP)"
        kev_entry:           Normalised KEV entry dict (from cisa_kev._normalise_entry).
                             Must have keys: vendor_project, affected_product.
                             The raw KEV dict (vendorProject / product) is also accepted.

    Returns:
        True if the fingerprint plausibly identifies the same product as the KEV entry.
        False in all other cases including empty/None inputs.
    """
    if not product_fingerprint or not kev_entry:
        return False

    fp = product_fingerprint.strip()
    if not fp:
        return False

    # Normalise KEV field names — accept both internal and raw KEV keys
    kev_vendor = (
        kev_entry.get("vendor_project")
        or kev_entry.get("vendorProject")
        or ""
    ).strip()
    kev_product = (
        kev_entry.get("affected_product")
        or kev_entry.get("product")
        or ""
    ).strip()

    if not kev_vendor and not kev_product:
        return False

    fp_lower = fp.lower()

    # Rule 1 — CPE component match
    cpe_components = _extract_cpe_components(fp)
    if cpe_components is not None:
        cpe_vendor, cpe_product = cpe_components
        kev_vendor_tokens = _tokenise(kev_vendor)
        kev_product_tokens = _tokenise(kev_product)
        # Both vendor and product must match at least one token each
        vendor_match = any(t in cpe_vendor for t in kev_vendor_tokens)
        product_match = any(t in cpe_product for t in kev_product_tokens)
        if vendor_match and product_match:
            return True

    # Rule 2 — Normalised keyword match
    # Build separate token sets for vendor and product.
    # A match fires if EITHER:
    #   (a) ≥1 vendor token AND ≥1 product token both appear in the fingerprint, OR
    #   (b) ≥MIN_KEYWORD_TOKENS tokens from the combined set appear in the fingerprint.
    #
    # This handles the common case where the device uses a product-family name
    # (e.g., "FortiGate") that is neither the vendor string ("Fortinet") nor the
    # exact affected product string ("FortiOS") in the KEV entry, but shares a
    # recognisable prefix with both.
    vendor_tokens = _tokenise(kev_vendor)
    product_tokens = _tokenise(kev_product)
    all_tokens = list(dict.fromkeys(vendor_tokens + product_tokens))  # deduplicated, order preserved

    fp_lower_stripped = fp_lower

    def _token_in_fp(token: str) -> bool:
        """Check if token or a ≥4-char prefix of token appears in the fingerprint."""
        if token in fp_lower_stripped:
            return True
        # Prefix family match: 'fortinet' matches 'fortigate' via 'forti' (len≥4)
        if len(token) >= 4:
            prefix = token[:4]
            # Find the prefix in the fingerprint and check it's followed by alpha chars
            # (avoids false matches on numeric/version strings)
            import re as _re
            if _re.search(rf"\b{_re.escape(prefix)}[a-z]", fp_lower_stripped):
                return True
        return False

    vendor_hits = [t for t in vendor_tokens if _token_in_fp(t)]
    product_hits = [t for t in product_tokens if _token_in_fp(t)]
    combined_hits = [t for t in all_tokens if _token_in_fp(t)]

    # Match if vendor + product each have ≥1 hit, OR combined hits ≥ MIN_KEYWORD_TOKENS
    if (len(vendor_hits) >= 1 and len(product_hits) >= 1) or len(combined_hits) >= MIN_KEYWORD_TOKENS:
        return True

    # Rule 3 — Default: no match
    return False


def compute_severity(
    cvss_base_score: Optional[float],
    known_ransomware_use: bool = False,
    kev_date_added: Optional[str] = None,
) -> str:
    """
    Compute a severity tier string for a cve_kev_matches row.

    Priority order:
      1. CVSS base score (from NVD, if available) — canonical severity mapping.
      2. known_ransomware_use=True with no CVSS → 'high' (KEV inclusion alone is
         a signal, ransomware adds urgency, but without CVSS we can't claim 'critical').
      3. KEV inclusion without ransomware and no CVSS → 'medium'.

    CVSS tiers follow NVD convention:
      9.0 – 10.0 → critical
      7.0 –  8.9 → high
      4.0 –  6.9 → medium
      0.1 –  3.9 → low

    Args:
        cvss_base_score:      NVD CVSS v3.x base score (0.0–10.0), or None.
        known_ransomware_use: From CISA KEV knownRansomwareCampaignUse field.
        kev_date_added:       ISO date string from CISA KEV; unused in scoring
                              logic itself but accepted for signature completeness.

    Returns:
        One of: 'critical', 'high', 'medium', 'low'
    """
    if cvss_base_score is not None:
        score = float(cvss_base_score)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    # No CVSS score available — use KEV signals as fallback
    if known_ransomware_use:
        return "high"
    return "medium"
