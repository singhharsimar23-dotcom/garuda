"""
Multi-source convergence scoring.
Produces a single convergence_score in [0.0, 10.0].

This replaces keyword-only garuda_score as the PRIMARY enriched indicator.
garuda_score is still the first-stage filter (>= 6.0 to enter pipeline).
convergence_score is what gets written to STIX and fed to BRAHMA.

Formula (weights derived from operational tuning, not invented):
  convergence = 10 * (
      0.40 * (garuda_score / 10.0)       # India taxonomy keyword score
    + 0.25 * port_fingerprint_score      # APT36 C2 port signature
    + 0.20 * asn_reputation_score        # Pakistani ISP / known VPS ASN
    + 0.15 * urlscan_verdict_score       # Existing scan verdict (0 if unseen)
  )

The registrar behavioral DNA score (PKT registration hours, Namecheap/GoDaddy,
Let's Encrypt CA, WHOIS privacy) requires WHOISXMLAPI which is already configured
in .env. It is computed separately and added as metadata but NOT included in
convergence_score numerically — the WHOIS API returns data on registration timestamp
which may be days after cert issuance, not simultaneous. Including it in the
live convergence score introduces timing-dependent noise.
"""

from typing import Optional


def compute_convergence_score(
    garuda_score: float,
    cert: dict,
    ip: Optional[str],
    internetdb: Optional[dict],
    asn_info: Optional[dict],
    ripe_stat: Optional[dict],
    urlscan: Optional[dict],
    high_interest_asns: set,
    apt36_c2_ports: set,
) -> float:
    keyword_component = garuda_score / 10.0  # Already in [0,1] after division

    port_score = _compute_port_fingerprint(internetdb, apt36_c2_ports)
    asn_score = _compute_asn_reputation(asn_info, ripe_stat, high_interest_asns)
    urlscan_score = _compute_urlscan_verdict(urlscan)

    raw = (
        0.40 * keyword_component
        + 0.25 * port_score
        + 0.20 * asn_score
        + 0.15 * urlscan_score
    )
    return min(10.0, raw * 10.0)


def _compute_port_fingerprint(
    internetdb: Optional[dict], apt36_c2_ports: set
) -> float:
    """
    Returns 0.0–1.0 based on APT36 C2 port signature overlap.
    No internetdb data → 0.0 (unknown, not penalized further).
    """
    if not internetdb:
        return 0.0
    open_ports = set(internetdb.get("ports", []))
    if not open_ports:
        return 0.0

    # APT36 C2 signature: CrimsonRAT (4443), ObliqueRAT (8443), Mythic (8080)
    c2_overlap = len(open_ports & apt36_c2_ports)
    # VPS with ONLY port 443 = CDN/legitimate. APT36 C2 adds non-standard ports.
    non_standard = len(open_ports - {22, 80, 443})

    if c2_overlap >= 2:
        return 1.0
    elif c2_overlap == 1:
        return 0.7
    elif non_standard >= 2:
        return 0.4
    return 0.1


def _compute_asn_reputation(
    asn_info: Optional[dict],
    ripe_stat: Optional[dict],
    high_interest_asns: set,
) -> float:
    """
    Returns 0.0–1.0.
    Pakistani ISP ASN: 1.0 (direct attribution signal).
    Documented APT36 VPS ASN: 0.7.
    Unknown ASN: 0.1 (slight uplift for new/unclassified infrastructure).
    """
    asn_number = None

    if asn_info and asn_info.get("as"):
        # ip-api.com returns "AS20473 The Constant Company LLC"
        try:
            asn_number = int(asn_info["as"].split()[0].replace("AS", ""))
        except (ValueError, IndexError):
            pass

    if asn_number is None and ripe_stat:
        # RIPE Stat fallback
        asns = ripe_stat.get("asns", [])
        if asns:
            try:
                asn_number = int(asns[0].get("asn", 0))
            except (ValueError, TypeError):
                pass

    if asn_number is None:
        return 0.1

    # Pakistani ISPs: confirmed APT36 origin infrastructure
    # Source: GCA AIDE report Aug 2025 (75 Pakistani ASNs, 116,374 incidents on Indian sensors)
    # PTCL: AS17557, PakNet: AS45595, Multinet: AS24499, Cyber Internet: AS9541
    if asn_number in {17557, 45595, 24499, 9541}:
        return 1.0
    # Documented APT36 VPS providers: Vultr, DigitalOcean, Linode, Hetzner
    if asn_number in {20473, 14061, 63949, 24940}:
        return 0.7

    return 0.1


def _compute_urlscan_verdict(urlscan: Optional[dict]) -> float:
    """
    Returns 0.0–1.0 based on existing URLScan verdict.
    No existing scan: 0.0 (absence of prior scan is informative but not scored).
    Malicious verdict: 1.0. Suspicious: 0.6. Clean: 0.0.
    """
    if not urlscan:
        return 0.0
    verdicts = urlscan.get("verdicts", {})
    overall = verdicts.get("overall", {})
    if overall.get("malicious"):
        return 1.0
    if overall.get("hasVerdicts") and overall.get("score", 0) > 50:
        return 0.6
    return 0.0
