"""GARUDA Detection Engine Package."""

from garuda.detection.engine import process_domain
from garuda.detection.homoglyph import detect_homoglyph, normalize_domain
from garuda.detection.infra_fingerprint import (
    check_c2_ports,
    check_hosting_asn,
    check_registrar_fingerprint,
    check_virustotal_reputation,
    fetch_whois_record,
)
from garuda.detection.nic_ground_truth import compute_similarity, load_nic_domains
from garuda.detection.patterns import extract_keyword_match, extract_sector
from garuda.detection.scoring import assemble_score

__all__ = [
    "process_domain",
    "normalize_domain",
    "detect_homoglyph",
    "load_nic_domains",
    "compute_similarity",
    "extract_keyword_match",
    "extract_sector",
    "fetch_whois_record",
    "check_virustotal_reputation",
    "check_registrar_fingerprint",
    "check_hosting_asn",
    "check_c2_ports",
    "assemble_score",
]
