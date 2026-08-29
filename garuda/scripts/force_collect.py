"""
GARUDA — Real CT Log Ingestion Trigger (PART 2.1)

Queries crt.sh Certificate Transparency logs in real-time for Indian government
and defence impersonation staging.
"""

import asyncio
from garuda.collector import run_collection
from garuda.sources.crtsh import fetch_new_certs

GARUDA_SEARCH_TERMS = [
    # High-value Indian government impersonation patterns
    "mod.gov.in", "modgov", "nic.in", "nicmail", "nic-login",
    "drdo", "drdo-gov", "army-hq", "indianarmy", "iaf-",
    "indiannavy", "isro-", "hal-aeronautics", "bel-india",
    "epfindia", "uidai", "aadhaar", "incometax-efiling",
    "cds-india", "afcert", "nciipc",
    # Known APT36 keyword patterns
    "kavach", "boss-linux", "bharat-os", "modgovin",
]


async def force_collect():
    print("================================================================")
    print("       GARUDA VAJRA — REAL LIVE CT LOG INGESTION                ")
    print("================================================================")
    print("Querying crt.sh Certificate Transparency logs in real-time...")

    try:
        certs = await fetch_new_certs(GARUDA_SEARCH_TERMS)
        print(f"[+] crt.sh returned {len(certs)} real certificate records.")
    except Exception as e:
        print(f"[-] crt.sh query notice: {e}")

    print("\nRunning complete scoring & ingestion pipeline...")
    summary = await run_collection()
    print("\nCollection Execution Summary:")
    for k, v in summary.items():
        print(f"  - {k}: {v}")

    print("\n================================================================")
    print("                REAL INGESTION CYCLE COMPLETE                   ")
    print("================================================================")


if __name__ == "__main__":
    asyncio.run(force_collect())
