"""
GARUDA Pre-Seeded CTI Telemetry.

Provides high-fidelity operational threat intelligence data representing
APT36 (Transparent Tribe) staging campaigns against Indian Critical National Infrastructure.
"""
import logging
from typing import Any, Dict, List
from datetime import datetime, timezone, timedelta

from garuda.database import get_supabase_client
from garuda.response.yara_generator import generate_yara_rule

logger = logging.getLogger("garuda.data.seed_telemetry")

DEFAULT_SEED_ALERTS: List[Dict[str, Any]] = [
    {
        "id": "e0a11001-0000-4000-8000-000000000001",
        "domain": "modgov-secure-portal.space",
        "score": 92,
        "sector": "Ministry of Defence (MoD)",
        "registrar": "Namecheap, Inc.",
        "hosting_ip": "185.220.101.45",
        "hosting_asn": 16276,
        "status": "pending",
        "cluster_id": "CAMP-APT36-2026-OP-TRIDENT",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.92,
            "nic_match": "mod.gov.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 25.0,
            "domain_age_days": 4,
            "asn_match": True,
            "c2_ports": [4000, 8443],
            "otx_attributed": True,
            "tension_index": 0.65,
            "latitude": 28.6139,
            "longitude": 77.2090,
            "city": "New Delhi",
        },
        "llm_narrative": "Critical threat: Target domain 'modgov-secure-portal.space' impersonates the Ministry of Defence portal (mod.gov.in) with 92% fuzzy similarity. Infrastructure is staged on OVH SAS (AS16276), a known APT36 CrimsonRAT staging network. Active C2 ports 4000 and 8443 indicate an operational command and control listener.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000002",
        "domain": "drdo-defence-procure.xyz",
        "score": 88,
        "sector": "Defence R&D (DRDO)",
        "registrar": "Namecheap, Inc.",
        "hosting_ip": "185.220.101.46",
        "hosting_asn": 16276,
        "status": "confirmed",
        "cluster_id": "CAMP-APT36-2026-CAPRAHING-SPACE",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=6)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.88,
            "nic_match": "drdo.gov.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 25.0,
            "domain_age_days": 6,
            "asn_match": True,
            "c2_ports": [8443],
            "otx_attributed": True,
            "tension_index": 0.65,
            "latitude": 28.6289,
            "longitude": 77.2065,
            "city": "DRDO Bhawan, New Delhi",
        },
        "llm_narrative": "High-confidence APT36 malware distribution vector targeting DRDO procurement personnel. Domain exhibits high lexical similarity to DRDO official infrastructure and correlates with known CapraHing spear-phishing campaigns.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000003",
        "domain": "indianarmy-pension-verify.online",
        "score": 95,
        "sector": "Indian Army",
        "registrar": "PDR Ltd",
        "hosting_ip": "185.220.101.47",
        "hosting_asn": 16276,
        "status": "confirmed",
        "cluster_id": "CAMP-APT36-2026-OP-TRIDENT",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.94,
            "nic_match": "indianarmy.nic.in",
            "homoglyph": True,
            "homoglyph_chars": ["а -> a (Cyrillic)"],
            "registrar_match": True,
            "registrar_score": 10.0,
            "domain_age_days": 2,
            "asn_match": True,
            "c2_ports": [4000, 9001],
            "otx_attributed": True,
            "tension_index": 0.65,
            "latitude": 34.0837,
            "longitude": 74.7973,
            "city": "Northern Command / Srinagar",
        },
        "llm_narrative": "Imminent threat: Cyrillic homoglyph spoofing observed in 'indianаrmy' credential harvesting vector. Targets defense service personnel with fraudulent pension portal lured via WhatsApp spear-phishing.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000004",
        "domain": "isro-telemetry-portal.site",
        "score": 84,
        "sector": "ISRO / Space Research",
        "registrar": "Namecheap, Inc.",
        "hosting_ip": "91.215.85.12",
        "hosting_asn": 24940,
        "status": "pending",
        "cluster_id": "CAMP-APT36-2026-CAPRAHING-SPACE",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.86,
            "nic_match": "isro.gov.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 25.0,
            "domain_age_days": 5,
            "asn_match": True,
            "c2_ports": [8443],
            "otx_attributed": False,
            "tension_index": 0.65,
            "latitude": 12.9716,
            "longitude": 77.5946,
            "city": "ISRO HQ, Bengaluru",
        },
        "llm_narrative": "Reconnaissance & credential harvesting campaign targeting ISRO aerospace telemetry data. Infrastructure hosted on Hetzner (AS24940) with active TLS certificates mimicking official government space telemetry portals.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000005",
        "domain": "hal-aero-procurements.space",
        "score": 78,
        "sector": "Hindustan Aeronautics (HAL)",
        "registrar": "Namecheap, Inc.",
        "hosting_ip": "91.215.85.15",
        "hosting_asn": 24940,
        "status": "pending",
        "cluster_id": "CAMP-APT36-2026-CAPRAHING-SPACE",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=16)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.79,
            "nic_match": "hal-india.co.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 25.0,
            "domain_age_days": 7,
            "asn_match": True,
            "c2_ports": [],
            "otx_attributed": False,
            "tension_index": 0.65,
            "latitude": 12.9611,
            "longitude": 77.6480,
            "city": "HAL Complex, Bengaluru",
        },
        "llm_narrative": "Supply chain cyber-espionage targeting HAL fighter aircraft sub-contractors. Correlates with historical Transparent Tribe targeting of indigenous aerospace manufacturing projects.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000006",
        "domain": "barc-nuclear-gateway.online",
        "score": 91,
        "sector": "Atomic Energy (BARC)",
        "registrar": "Namecheap, Inc.",
        "hosting_ip": "185.220.101.50",
        "hosting_asn": 16276,
        "status": "confirmed",
        "cluster_id": "CAMP-APT36-2026-POSEIDON-BOSS",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=18)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.89,
            "nic_match": "barc.gov.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 25.0,
            "domain_age_days": 3,
            "asn_match": True,
            "c2_ports": [4000, 8443],
            "otx_attributed": True,
            "tension_index": 0.65,
            "latitude": 18.9402,
            "longitude": 72.8356,
            "city": "Trombay, Mumbai",
        },
        "llm_narrative": "Critical national security infrastructure alert: Bhabha Atomic Research Centre spoofing infrastructure actively resolving. Dual open C2 ports match signature Poseidon payload distributions.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000007",
        "domain": "ntro-intel-relay.site",
        "score": 96,
        "sector": "National Technical Research (NTRO)",
        "registrar": "PDR Ltd",
        "hosting_ip": "185.220.101.52",
        "hosting_asn": 16276,
        "status": "confirmed",
        "cluster_id": "CAMP-APT36-2026-POSEIDON-BOSS",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.95,
            "nic_match": "ntro.gov.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 10.0,
            "domain_age_days": 1,
            "asn_match": True,
            "c2_ports": [4000, 8443, 9001],
            "otx_attributed": True,
            "tension_index": 0.65,
            "latitude": 28.5833,
            "longitude": 77.2167,
            "city": "New Delhi",
        },
        "llm_narrative": "Immediate danger: Domain configured with all 3 known APT36 C2 ports (4000, 8443, 9001). Pre-attack staging window estimated at less than 5 days. Emergency blocklist dispatched via CERT-In advisory.",
    },
    {
        "id": "e0a11001-0000-4000-8000-000000000008",
        "domain": "bel-radar-systems.xyz",
        "score": 76,
        "sector": "Bharat Electronics (BEL)",
        "registrar": "eNom, Inc.",
        "hosting_ip": "194.26.29.88",
        "hosting_asn": 63949,
        "status": "pending",
        "cluster_id": "CAMP-APT36-2026-OP-TRIDENT",
        "registered_at": (datetime.now(timezone.utc) - timedelta(days=8)).isoformat(),
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=22)).isoformat(),
        "signals": {
            "keyword_tier": "tier1",
            "keyword_score": 35.0,
            "nic_similarity": 0.77,
            "nic_match": "bel-india.in",
            "homoglyph": False,
            "registrar_match": True,
            "registrar_score": 10.0,
            "domain_age_days": 8,
            "asn_match": True,
            "c2_ports": [8443],
            "otx_attributed": False,
            "tension_index": 0.65,
            "latitude": 13.0827,
            "longitude": 80.2707,
            "city": "Chennai Defense Belt",
        },
        "llm_narrative": "Targeting radar and electronic warfare divisions of Bharat Electronics. Correlates with Linode (AS63949) proxy nodes previously attributed to SideWinder/Transparent Tribe cross-border reconnaissance.",
    }
]

DEFAULT_SEED_CAMPAIGNS: List[Dict[str, Any]] = [
    {
        "id": "c0a11001-0000-4000-8000-000000000001",
        "cluster_id": "CAMP-APT36-2026-OP-TRIDENT",
        "domain_count": 3,
        "registrar": "Namecheap / PDR Ltd",
        "hosting_asn": 16276,
        "sectors": ["Ministry of Defence (MoD)", "Indian Army", "Bharat Electronics (BEL)"],
        "estimated_attack_window_days": 14,
        "confidence": "high",
        "created_at": (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(),
    },
    {
        "id": "c0a11001-0000-4000-8000-000000000002",
        "cluster_id": "CAMP-APT36-2026-CAPRAHING-SPACE",
        "domain_count": 3,
        "registrar": "Namecheap, Inc.",
        "hosting_asn": 24940,
        "sectors": ["Defence R&D (DRDO)", "ISRO / Space Research", "Hindustan Aeronautics (HAL)"],
        "estimated_attack_window_days": 11,
        "confidence": "high",
        "created_at": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
    },
    {
        "id": "c0a11001-0000-4000-8000-000000000003",
        "cluster_id": "CAMP-APT36-2026-POSEIDON-BOSS",
        "domain_count": 2,
        "registrar": "Namecheap / PDR Ltd",
        "hosting_asn": 16276,
        "sectors": ["Atomic Energy (BARC)", "National Technical Research (NTRO)"],
        "estimated_attack_window_days": 7,
        "confidence": "critical",
        "created_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    }
]


async def seed_initial_telemetry(force: bool = False) -> int:
    """
    Ensure the Supabase database is pre-seeded with rich operational threat telemetry.
    """
    client = get_supabase_client()
    if not client:
        return 0

    try:
        # Check existing alert count
        res = client.table("alerts").select("id", count="exact").limit(1).execute()
        count = res.count or len(res.data or [])
        if count > 0 and not force:
            return count

        logger.info("[seed_telemetry] Seeding operational threat intelligence into Supabase...")

        # 1. Insert seed campaigns
        for camp in DEFAULT_SEED_CAMPAIGNS:
            try:
                client.table("campaigns").upsert(camp, on_conflict="cluster_id").execute()
            except Exception as ce:
                logger.warning(f"[seed_telemetry] Error seeding campaign {camp['cluster_id']}: {ce}")

        # 2. Insert seed alerts
        for alert in DEFAULT_SEED_ALERTS:
            try:
                alert_copy = dict(alert)
                alert_copy["yara_rule"] = generate_yara_rule(alert_copy)
                client.table("alerts").upsert(alert_copy, on_conflict="id").execute()
            except Exception as ae:
                logger.warning(f"[seed_telemetry] Error seeding alert {alert['domain']}: {ae}")

        logger.info(f"[seed_telemetry] Successfully seeded {len(DEFAULT_SEED_ALERTS)} alerts and {len(DEFAULT_SEED_CAMPAIGNS)} campaigns.")
        return len(DEFAULT_SEED_ALERTS)
    except Exception as e:
        logger.error(f"[seed_telemetry] Database seeding error: {e}")
        return 0
