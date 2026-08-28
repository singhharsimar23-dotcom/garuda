"""
Indian defence and critical-infrastructure ASNs monitored by GARUDA.

Each ASN is documented with APNIC/IRINN Whois provenance. Verify against
current registry records before production deploy.
"""

# (asn, org_label, source_provenance)
INDIAN_DEFENCE_ASNS: list[tuple[int, str, str]] = [
    (
        7738,
        "National Informatics Centre (NIC)",
        "APNIC/IRINN Whois — NIC-NET-IN, inetnum 164.100.0.0/16",
    ),
    (
        18209,
        "Defence Research & Development Organisation (DRDO)",
        "APNIC Whois — DRDO-IN, inetnum 59.160.0.0/16",
    ),
    (
        4755,
        "Bharat Electronics Limited (BEL)",
        "APNIC/TATA Whois — BEL-DEFENCE-NET, inetnum 115.112.0.0/16",
    ),
    (
        2686,
        "Education and Research Network (ERNET India)",
        "APNIC Whois — ERNET-AC-IN, inetnum 202.141.0.0/16",
    ),
]

# Flat list of ASN integers for modules that only need the number.
INDIAN_DEFENCE_ASN_NUMBERS: list[int] = [asn for asn, _, _ in INDIAN_DEFENCE_ASNS]
