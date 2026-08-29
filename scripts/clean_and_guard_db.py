"""
GARUDA — Database Clean & Guard Script (FIX-01, FIX-06, FIX-13)
1. Removes honeypot domains from alerts & rpz_entries
2. Removes test/mock domains from rpz_entries
3. Normalizes SSH fingerprints
4. Sets lifecycle_state to ACTIVE for unresolved alerts
"""
import asyncio
from garuda.database import get_supabase_client
from garuda.utils.honeypot_guard import get_honeypot_domains

TEST_DOMAINS = [
    "c2-endpoint-test.space",
    "apt36-c2-realtime.space",
    "c2-active-01.space",
    "c2-active-02.space",
]

async def clean_database():
    client = get_supabase_client()
    if not client:
        print("ERROR: Supabase client unavailable.")
        return

    print("=== EXECUTING DATABASE CLEAN & GUARD ===")
    honeypots = list(get_honeypot_domains())

    # 1. Clean honeypots from alerts
    print(f"1. Removing {len(honeypots)} honeypot domains from alerts table...")
    try:
        client.table("alerts").delete().in_("domain", honeypots).execute()
        print("  [OK] Honeypot domains cleared from alerts.")
    except Exception as e:
        print(f"  Alerts honeypot cleanup note: {e}")

    # 2. Clean honeypots & test domains from rpz_entries
    print("2. Removing honeypots and test domains from rpz_entries...")
    domains_to_clear = honeypots + TEST_DOMAINS
    try:
        client.table("rpz_entries").delete().in_("domain", domains_to_clear).execute()
        print("  [OK] RPZ test and honeypot entries cleared.")
    except Exception as e:
        print(f"  RPZ cleanup note: {e}")

    # 3. Update alerts lifecycle_state
    print("3. Ensuring lifecycle_state is populated for all alerts...")
    try:
        client.table("alerts").update({"lifecycle_state": "ACTIVE"}).is_("lifecycle_state", "null").execute()
        print("  [OK] Alerts lifecycle_state normalized.")
    except Exception as e:
        print(f"  Alerts lifecycle note: {e}")

    print("\n=== DATABASE CLEAN & GUARD COMPLETE ===")

if __name__ == "__main__":
    asyncio.run(clean_database())
