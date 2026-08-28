"""
GARUDA Threat Intelligence - IOC Confidence Scoring Engine
Calculates an algorithmic confidence score (0-100) and methodology provenance
for STIX 2.1 Threat Indicators and IOC bundles.
"""

from typing import Any, Dict, Tuple


def compute_ioc_confidence(signals: Dict[str, Any]) -> Tuple[int, str]:
    """
    Compute normalized confidence score (0-100) and methodology description
    for an IOC based on multi-vector intelligence signals.

    Args:
        signals: Extracted threat signals dict containing:
            - keyword_score / keyword_tier
            - nic_similarity / nic_match
            - homoglyph (bool)
            - registrar_score / registrar_match (bool)
            - domain_age_days (int)
            - asn_match (bool)
            - c2_ports (list[int])
            - otx_attributed (bool)
            - abuseipdb_reports (int/bool)
            - tension_index (float)

    Returns:
        Tuple[int, str]: (confidence_score, methodology_string)
    """
    if not signals:
        return 50, "GARUDA Default Baseline Heuristic (Unattributed)"

    base_score = 0.0
    contributing_detectors = []

    # 1. NIC / Brand impersonation similarity
    nic_sim = float(signals.get("nic_similarity", 0.0))
    if nic_sim >= 0.85:
        base_score += 35.0
        contributing_detectors.append(f"NIC High-Similarity ({nic_sim:.2f})")
    elif nic_sim >= 0.70:
        base_score += 20.0
        contributing_detectors.append(f"NIC Moderate-Similarity ({nic_sim:.2f})")
    elif nic_sim >= 0.50:
        base_score += 10.0
        contributing_detectors.append("NIC Pattern Match")

    # 2. Unicode homoglyphs
    if bool(signals.get("homoglyph", False)):
        base_score += 25.0
        contributing_detectors.append("Unicode Homoglyph Spoofing Detector")

    # 3. Keyword patterns
    kw_score = float(signals.get("keyword_score", 0.0))
    if kw_score > 0:
        base_score += min(25.0, kw_score)
        contributing_detectors.append(f"Gov/Defence Keyword Match (Tier {signals.get('keyword_tier', '1')})")

    # 4. Registrar affinity
    reg_score = float(signals.get("registrar_score", 0.0))
    if reg_score > 0 or bool(signals.get("registrar_match", False)):
        score_add = reg_score if reg_score > 0 else 15.0
        base_score += score_add
        contributing_detectors.append("APT36 Registrar Affinity Fingerprint")

    # 5. Domain age
    age_days = signals.get("domain_age_days")
    if age_days is not None and isinstance(age_days, (int, float)):
        if age_days <= 14:
            base_score += 20.0
            contributing_detectors.append(f"Fresh Registration ({age_days}d)")
        elif age_days <= 60:
            base_score += 10.0
            contributing_detectors.append(f"Recent Registration ({age_days}d)")

    # 6. Hosting ASN correlation
    if bool(signals.get("asn_match", False)):
        base_score += 20.0
        contributing_detectors.append("Known Threat Infrastructure ASN Correlation")

    # 7. C2 listening ports
    c2_ports = signals.get("c2_ports", [])
    if isinstance(c2_ports, list) and len(c2_ports) > 0:
        base_score += 25.0
        contributing_detectors.append(f"Active C2 Listener Ports ({','.join(map(str, c2_ports[:3]))})")

    # 8. External threat pulses (OTX, AbuseIPDB)
    if bool(signals.get("otx_attributed", False)):
        base_score += 30.0
        contributing_detectors.append("AlienVault OTX Threat Pulse Attribution")

    abuse_reports = signals.get("abuseipdb_reports", 0)
    if (isinstance(abuse_reports, int) and abuse_reports > 0) or bool(abuse_reports):
        base_score += 15.0
        contributing_detectors.append(f"AbuseIPDB Reputation Corroboration ({abuse_reports} reports)")

    # 9. Geopolitical tension multiplier
    tension_idx = float(signals.get("tension_index", 0.50))
    tension_mod = 0.0
    if base_score > 0 and tension_idx > 0.5:
        tension_mod = min(15.0, round(tension_idx * 0.20 * base_score, 2))
        base_score += tension_mod
        contributing_detectors.append(f"Geopolitical Tension Modifier (index={tension_idx:.2f})")

    confidence = int(min(100, max(10, round(base_score))))

    if contributing_detectors:
        methodology = "GARUDA Multi-Signal Engine: " + " + ".join(contributing_detectors)
    else:
        methodology = "GARUDA Multi-Signal Heuristic Engine (Baseline Assessment)"

    return confidence, methodology
