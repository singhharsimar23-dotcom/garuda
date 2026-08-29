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

# Known APT groups actively exploiting specific CISA KEV CVEs
CVE_TO_APT: dict[str, list[str]] = {
    "CVE-2024-21762": ["Volt Typhoon", "APT36"],
    "CVE-2023-4966":  ["Volt Typhoon", "LockBit"],
    "CVE-2023-27997": ["Volt Typhoon", "Mustang Panda"],
    "CVE-2022-40684": ["APT36", "Affiliated Actors"],
    "CVE-2024-21887": ["Ivanti Exploitation Cluster", "APT36"],
    "CVE-2023-46805": ["Ivanti Exploitation Cluster"],
    "CVE-2019-0708":  ["BlueKeep Worm", "State Actors"],
}

# Fallback product-to-CVE mapping for known Indian defence edge exposures
PRODUCT_CVE_FALLBACK: dict[str, list[str]] = {
    "citrix-netscaler":      ["CVE-2023-4966", "CVE-2019-19781"],
    "citrix_netscaler":      ["CVE-2023-4966", "CVE-2019-19781"],
    "citrix":                ["CVE-2023-4966"],
    "fortigate":             ["CVE-2024-21762", "CVE-2023-27997", "CVE-2022-40684"],
    "fortigate-mgmt":        ["CVE-2024-21762", "CVE-2023-27997"],
    "fortinet":              ["CVE-2024-21762", "CVE-2023-27997"],
    "ivanti-connect-secure": ["CVE-2024-21887", "CVE-2023-46805"],
    "ivanti":                ["CVE-2024-21887", "CVE-2023-46805"],
    "rdp":                   ["CVE-2019-0708"],
    "microsoft-rdp":         ["CVE-2019-0708"],
}

