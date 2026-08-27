from datetime import datetime, timezone
from typing import Any, Dict


def generate_advisory_draft(alert: Dict[str, Any]) -> str:
    """
    Generate a formal CERT-In (Indian Computer Emergency Response Team) security advisory draft.

    Formats technical indicators, infrastructure attribution, similarity scores, and tactical
    remediation guidance according to the national vulnerability and incident response template.

    Args:
        alert: Complete threat alert dictionary.

    Returns:
        str: Standardized multi-section CERT-In advisory document formatted in text.
    """
    domain = alert.get("domain", "N/A")
    score = alert.get("score", 0)
    sector = alert.get("sector", "Critical Sector / Government")
    signals = alert.get("signals", {})

    registrar = alert.get("registrar") or signals.get("registrar") or "Unknown / Redacted"
    hosting_ip = alert.get("hosting_ip") or signals.get("hosting_ip") or "Unresolved"
    hosting_asn = alert.get("hosting_asn") or signals.get("hosting_asn") or "Unknown"
    cert_date = alert.get("registered_at") or signals.get("creation_date") or "Recently Observed"

    nic_match = signals.get("nic_match", "N/A")
    nic_sim = float(signals.get("nic_similarity", 0.0))
    cluster_id = alert.get("cluster_id") or "Isolated Threat Node"

    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime("%Y%m%d")
    formatted_date = now_utc.strftime("%d-%B-%Y")

    advisory_text = f"""================================================================================
INDIAN COMPUTER EMERGENCY RESPONSE TEAM (CERT-In)
MINISTRY OF ELECTRONICS AND INFORMATION TECHNOLOGY, GOVERNMENT OF INDIA
================================================================================
CERT-In Advisory Draft | Reference: CERT-In/2026/GARUDA-{date_str}
Date of Release: {formatted_date}
Severity Rating: {"CRITICAL" if score >= 85 else "HIGH" if score >= 70 else "MEDIUM"} (GARUDA Composite Threat Index: {score}/100)
Target Sector: {sector}
Threat Actor Attribution: Suspected APT36 (Transparent Tribe / Mythic Leopard)
Campaign Cluster: {cluster_id}

--------------------------------------------------------------------------------
1. OVERVIEW & THREAT DESCRIPTION
--------------------------------------------------------------------------------
CERT-In has observed adversary activity involving targeted brand impersonation,
malicious credential harvesting infrastructure, and C2 staging directed against
strategic national organizations, defense research entities, and government portals.

The suspicious infrastructure '{domain}' was detected exhibiting anomalous
registration patterns mimicking legitimate national resources ({nic_match},
fuzzy similarity index: {nic_sim:.1%}).

--------------------------------------------------------------------------------
2. TECHNICAL INDICATORS OF COMPROMISE (IOCs)
--------------------------------------------------------------------------------
• Primary Malicious Domain:  {domain}
• Associated Hosting IPv4:   {hosting_ip}
• Autonomous System Number:  AS{hosting_asn}
• Sponsoring Registrar:      {registrar}
• Registration / Cert Date:  {cert_date}
• Campaign Reference ID:     {cluster_id}

--------------------------------------------------------------------------------
3. RECOMMENDED DEFENSIVE ACTIONS & HARDENING
--------------------------------------------------------------------------------
All Chief Information Security Officers (CISOs), SOC leads, and network administrators
are advised to implement the following immediate countermeasures:

1. DNS SINKHOLING & PERIMETER BLOCKING:
   Immediately configure perimeter firewalls, DNS recursive resolvers, and Secure
   Web Gateways (SWG) to block all ingress and egress traffic to {domain} and IP {hosting_ip}.

2. CREDENTIAL HARVESTING & SESSION AUDIT:
   Inspect web proxy and authentication logs for any outbound user connections to {domain}.
   Force immediate credential resets and session invalidation for any accounts with hits.

3. TWO-FACTOR AUTHENTICATION (FIDO2 / PKI):
   Enforce hardware token or PKI-backed multi-factor authentication across all external
   webmail and administrative portals to prevent replay of harvested credentials.

4. ENDPOINT ISOLATION & HOST ARTIFACT SCANNING:
   Deploy enterprise EDR hunting rules targeting outbound connections on ports 4000, 8443,
   and 9001 towards hosting subnet AS{hosting_asn}.

5. INCIDENT REPORTING:
   Report any confirmed telemetry matches or suspicious artifact downloads to CERT-In
   via the incident reporting portal at https://www.cert-in.org.in.

================================================================================
STATUS: DRAFT — ANALYST REVIEW REQUIRED BEFORE OFFICIAL DISSEMINATION
================================================================================
"""
    return advisory_text
