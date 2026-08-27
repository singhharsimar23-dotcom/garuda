from typing import Tuple
from garuda.config import settings
from garuda.detection.homoglyph import normalize_domain

# Sector classification keyword mappings
SECTOR_MAP = {
    "Ministry of Defence (MoD)": [
        "modgov", "mod-india", "modindia", "defencein", "defenceindia", "raksha",
        "mantralaya", "rakshamantralaya", "indianarmy", "army-hq", "armyhq",
        "armyindia", "indiannavy", "navyindia", "iafin", "iaf-india", "airforceindia",
        "cds-india", "cdsindia", "hq-ids", "hqids", "hqwesternair", "hqeasternair",
        "hqsouthernair", "hqtraining", "southernnaval", "easternnaval", "westernnaval",
        "andamannaval", "defenceresearch", "defenceprocurement"
    ],
    "National Informatics Centre (NIC)": [
        "nicin", "nic-in", "nicmail", "nicwebmail", "webmailnic", "niclogin",
        "nic-login", "nicindia", "mail.gov", "email.gov", "webmail.gov"
    ],
    "Defence R&D (DRDO)": [
        "drdo", "drdolab", "drdoresearch", "cair", "dlrl", "gtre", "diat", "mceme", "cer-drdo"
    ],
    "Space & Telecom (ISRO/BSNL)": [
        "isroin", "isro-india", "bsnl-india", "mtnl-india", "aerodynamics"
    ],
    "Paramilitary & Intelligence": [
        "bsf-india", "crpfindia", "ntro-in", "rawmail", "ibindia", "cbiin"
    ],
    "Cabinet & External Affairs": [
        "pmoindia", "cabinetindia", "ministryexternal", "meaindia", "homeaffairs"
    ],
    "Financial & Regulatory": [
        "financemin", "incoin", "sebi-india", "nabarindia", "rdbiindia", "rbi-india", "npclindia"
    ],
    "Citizen Services & Identity": [
        "uidaiin", "uidai-india", "covindia", "irctclogin", "railindia", "epfindia", "incometaxindia", "cbic-india"
    ],
    "Defence Public Sector (DPSU)": [
        "hal-india", "bel-india", "bdl-india", "mazagondock", "cochinshipyard", "grse-india", "midhani"
    ],
    "Critical Energy & Nuclear": [
        "ongcindia", "iocl-india", "bpcl-india", "ntpcindia", "powergridindia", "barc-india", "npcil-india"
    ],
    "Cybersecurity & Certifications": [
        "cert-in", "nciipc", "cdac-india", "parliamentofindia", "supremecourtofindia"
    ]
}


def extract_keyword_match(domain: str) -> Tuple[str, int]:
    """
    Check domain against Tier 1, Tier 2, and APT36 Suspicious TLD patterns.

    Performs fast heuristic matching for early triage:
      - Tier 1 match -> ('tier1', 30)
      - Tier 2 match -> ('tier2', 15)
      - Suspicious TLD match -> ('tld', 20)
      - No match -> ('none', 0)

    Args:
        domain: Target domain string.

    Returns:
        Tuple of (match_tier: str, base_score: int).
    """
    if not domain:
        return "none", 0

    norm_domain = normalize_domain(domain)

    # 1. Tier 1 Pattern Matching
    for pattern in settings.TIER_1_PATTERNS:
        if pattern.lower() in norm_domain:
            return "tier1", 30

    # 2. Tier 2 Pattern Matching
    for pattern in settings.TIER_2_PATTERNS:
        if pattern.lower() in norm_domain:
            return "tier2", 15

    # 3. APT36 Suspicious TLD Matching
    for tld in settings.APT36_SUSPICIOUS_TLDS:
        if norm_domain.endswith(tld.lower()):
            return "tld", 20

    return "none", 0


def extract_sector(domain: str) -> str:
    """
    Determine targeted government, defense, or infrastructure sector from domain indicators.

    Args:
        domain: Domain name to classify.

    Returns:
        String representing the identified sector or 'Unclassified Infrastructure'.
    """
    norm = normalize_domain(domain)
    for sector_name, keywords in SECTOR_MAP.items():
        if any(kw.lower() in norm for kw in keywords):
            return sector_name
    return "Unclassified Critical Sector"
