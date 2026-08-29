"""
GARUDA — Master Synthetic Data Purge (PART 1)

Purges all synthetic seed records, mock fingerprints, test domains,
orphaned RPZ/STIX records, and fabricated metrics from Supabase database tables.
"""

import asyncio
from garuda.database import get_supabase_client
from garuda.utils.honeypot_guard import get_honeypot_domains

HONEYPOT_DOMAINS = [
    "army-hq-portal.space",
    "modgov-portal.space",
    "mod-india-portal.space",
    "modgov-secure.online",
    "raksha-mantralaya.site",
    "defenceindia-services.xyz",
    "nicmail-secure.space",
    "nic-webmail-login.online",
    "nicindia-portal.site",
    "drdo-research.space",
    "drdo-collaboration.online",
    "drdolab-access.site",
    "indianarmy-login.online",
    "iaf-services.space",
    "airforceindia-sso.online",
    "indiannavy-portal.space",
    "boss-linux-update.space",
    "india-sso.space",
    "govtindia-login.online",
    "pmoindia-secure.site",
    "iaf-recruitment-portal.site",
    "drdo-eprocurement.online",
    "indianarmy-welfare.xyz",
]

TEST_DOMAINS = [
    "c2-endpoint-test.space",
    "apt36-c2-realtime.space",
    "c2-active-01.space",
    "c2-active-02.space",
    "c2active-endpoint.space",
]


async def run_master_purge():
    client = get_supabase_client()
    if not client:
        print("ERROR: Supabase client unavailable.")
        return

    print("================================================================")
    print("       GARUDA VAJRA — MASTER SYNTHETIC DATA PURGE               ")
    print("================================================================")

    # 1.1 Purge Synthetic Alerts
    print("\n--- 1.1 Purging Synthetic & Honeypot Alerts ---")
    try:
        del_honeypots = client.table("alerts").delete().in_("domain", HONEYPOT_DOMAINS).execute()
        print(f"  [+] Cleared honeypot domains from alerts.")
    except Exception as e:
        print(f"  [-] Alerts honeypot purge note: {e}")

    try:
        del_test = client.table("alerts").delete().in_("domain", TEST_DOMAINS).execute()
        print(f"  [+] Cleared test/seed domains from alerts.")
    except Exception as e:
        print(f"  [-] Alerts test domain purge note: {e}")

    # Set data_source where missing
    try:
        client.table("alerts").update({"data_source": "ct_log"}).is_("data_source", "null").execute()
        print(f"  [+] Normalized data_source for active alerts.")
    except Exception as e:
        print(f"  [-] Alerts data_source normalization note: {e}")

    # 1.2 Purge Synthetic RPZ Entries
    print("\n--- 1.2 Purging Synthetic RPZ Entries ---")
    try:
        client.table("rpz_entries").delete().in_("domain", HONEYPOT_DOMAINS + TEST_DOMAINS).execute()
        print(f"  [+] Cleared test and honeypot domains from rpz_entries.")
    except Exception as e:
        print(f"  [-] RPZ test purge note: {e}")

    # 1.4 Purge Synthetic ORB Nodes
    print("\n--- 1.4 Purging Synthetic ORB Nodes ---")
    try:
        client.table("orb_nodes").delete().is_("latitude", "null").execute()
        print(f"  [+] Removed unlocated ORB nodes.")
    except Exception as e:
        print(f"  [-] ORB purge note: {e}")

    # 1.5 Purge Synthetic Malware Hunt / Fingerprint Signals
    print("\n--- 1.5 Purging Synthetic Malware Hunt Signals ---")
    try:
        client.table("compiler_fingerprints").delete().eq("source_report", "seed").execute()
        print(f"  [+] Purged synthetic compiler fingerprints.")
    except Exception as e:
        print(f"  [-] Compiler fingerprints note: {e}")

    # 1.8 Purge Synthetic Persona Graph Nodes
    print("\n--- 1.8 Purging Synthetic Persona Nodes ---")
    try:
        client.table("persona_nodes").delete().in_("source", ["seed", "mock", "test"]).execute()
        print(f"  [+] Purged synthetic persona nodes.")
    except Exception as e:
        print(f"  [-] Persona nodes note: {e}")

    # 1.10 Purge Synthetic Pre-Registration Candidates
    print("\n--- 1.10 Purging Synthetic Predictive Candidates ---")
    try:
        client.table("predictive_domains").delete().eq("generation_source", "seed").execute()
        print(f"  [+] Purged synthetic predictive domains.")
    except Exception as e:
        print(f"  [-] Predictive domains note: {e}")

    print("\n================================================================")
    print("               MASTER DATABASE PURGE COMPLETE                   ")
    print("================================================================")


if __name__ == "__main__":
    asyncio.run(run_master_purge())
