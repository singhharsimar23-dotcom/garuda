"""
GARUDA Retroactive IOC Seeder.
Run once manually after deploy:
    cd <repo-root>
    python scripts/retroactive_seed.py

Populates stix_objects with historically confirmed APT36/APT41/Lazarus
infrastructure from published threat reports. These timestamps predate
the live hunt — when GARUDA later detects related infrastructure,
the DB shows correlation. This builds the retroactive case study.

Sources cited per IOC. Zero invented IOCs.
"""

import asyncio
import os
import sys
from datetime import timezone

from supabase import create_client

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("ERROR: Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in environment")
    sys.exit(1)

# All IOCs from public confirmed threat reports.
# Source field = publication reference. Never invent.
SEED_IOCs = [
    # APT36 / Transparent Tribe
    {
        "ioc_value": "46.30.188.13",
        "ioc_type": "confirmed_c2",
        "malware_family": "PATCHCORD",
        "actor": "APT36",
        "source": "THN_AUG2026",
        "first_seen": "2026-08-01T00:00:00+00:00",
        "confidence": 85,
    },
    {
        "ioc_value": "23.152.0.81",
        "ioc_type": "confirmed_c2",
        "malware_family": "CrystalShell",
        "actor": "APT36",
        "source": "BITDEFENDER_MAR2026",
        "first_seen": "2026-03-01T00:00:00+00:00",
        "confidence": 85,
    },
    {
        "ioc_value": "45.56.162.170",
        "ioc_type": "confirmed_c2",
        "malware_family": "ZigShell",
        "actor": "APT36",
        "source": "BITDEFENDER_MAR2026",
        "first_seen": "2026-03-01T00:00:00+00:00",
        "confidence": 85,
    },
    {
        "ioc_value": "143.198.64.151",
        "ioc_type": "confirmed_c2",
        "malware_family": "Mythic_C2",
        "actor": "APT36",
        "source": "CYFIRMA_OSINT_2024",
        "first_seen": "2024-06-01T00:00:00+00:00",
        "confidence": 80,
    },
    {
        "ioc_value": "206.189.134.185",
        "ioc_type": "confirmed_c2",
        "malware_family": "Mythic_C2",
        "actor": "APT36",
        "source": "CYFIRMA_OSINT_2024",
        "first_seen": "2024-06-01T00:00:00+00:00",
        "confidence": 80,
    },
    # Actor profile seeds — enable multi-actor BRAHMA posteriors
    {
        "ioc_value": "volt_typhoon_G1017_profile",
        "ioc_type": "actor_profile",
        "malware_family": "LOTL",
        "actor": "VOLT_TYPHOON",
        "source": "CISA_AA24-038A",
        "first_seen": "2024-02-07T00:00:00+00:00",
        "confidence": 95,
    },
    {
        "ioc_value": "apt41_G0096_profile",
        "ioc_type": "actor_profile",
        "malware_family": "HYBRID_ESPIONAGE",
        "actor": "APT41",
        "source": "MITRE_G0096",
        "first_seen": "2024-01-01T00:00:00+00:00",
        "confidence": 95,
    },
    {
        "ioc_value": "lazarus_G0032_profile",
        "ioc_type": "actor_profile",
        "malware_family": "DPRK_APT",
        "actor": "LAZARUS",
        "source": "MITRE_G0032",
        "first_seen": "2024-01-01T00:00:00+00:00",
        "confidence": 95,
    },
]


def seed():
    client = create_client(SUPABASE_URL, SUPABASE_KEY)
    success = 0
    failed = 0

    for ioc in SEED_IOCs:
        try:
            client.table("stix_objects").upsert(
                ioc, on_conflict="ioc_value"
            ).execute()
            print(f"  ✓ {ioc['ioc_value']} [{ioc['actor']}]")
            success += 1
        except Exception as exc:
            print(f"  ✗ {ioc['ioc_value']} FAILED: {exc}")
            failed += 1

    print(f"\nSeeded: {success} IOCs. Failed: {failed}.")
    if failed == 0:
        print("Database primed. GARUDA will correlate future detections against these.")
    else:
        print("Check Supabase stix_objects schema — ioc_value column must exist.")


if __name__ == "__main__":
    seed()
