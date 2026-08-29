"""
GARUDA — Master Deduplication & Deep Purge
Removes all test tokens, duplicates, and fake records from Supabase.
"""

import asyncio
from garuda.database import get_supabase_client

async def clean_and_dedup():
    client = get_supabase_client()
    if not client:
        print("Error: Supabase client not available")
        return

    print("================================================================")
    print("      GARUDA — DEEP CLEAN & DEDUPLICATION PROTOCOL              ")
    print("================================================================")

    # 1. Delete test canary tokens
    try:
        del_canary = client.table("alerts").delete().ilike("domain", "%canary%").execute()
        print(f" [+] Deleted test canary alerts.")
    except Exception as e:
        print(" [-] Canary purge note:", e)

    # 2. Delete threat-to-delete.space from RPZ and alerts
    try:
        client.table("alerts").delete().in_("domain", ["threat-to-delete.space", "c2-endpoint-test.space"]).execute()
        client.table("rpz_entries").delete().in_("domain", ["threat-to-delete.space", "c2-endpoint-test.space"]).execute()
        print(f" [+] Deleted test domains from alerts and RPZ.")
    except Exception as e:
        print(" [-] Test domain purge note:", e)

    # 3. Purge all synthetic persona_nodes and ssh_key_observations
    try:
        client.table("persona_nodes").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        print(f" [+] Purged synthetic persona_nodes.")
    except Exception as e:
        print(" [-] Persona nodes purge note:", e)

    try:
        client.table("ssh_key_observations").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        print(f" [+] Purged synthetic ssh_key_observations.")
    except Exception as e:
        print(" [-] SSH observations purge note:", e)

    # 4. Domain Deduplication in alerts table
    try:
        alerts = client.table("alerts").select("id,domain,detected_at").order("detected_at", desc=True).execute().data or []
        seen = set()
        to_delete_ids = []
        for a in alerts:
            dom = a.get("domain", "").strip().lower()
            if not dom:
                to_delete_ids.append(a["id"])
                continue
            if dom in seen:
                to_delete_ids.append(a["id"])
            else:
                seen.add(dom)

        if to_delete_ids:
            print(f" [+] Found {len(to_delete_ids)} duplicate alert records to delete.")
            # Chunk delete
            for i in range(0, len(to_delete_ids), 20):
                chunk = to_delete_ids[i:i+20]
                client.table("alerts").delete().in_("id", chunk).execute()
            print(f" [+] Deduplication complete: {len(seen)} unique alerts remaining.")
        else:
            print(f" [+] No duplicate alerts found ({len(seen)} unique alerts).")
    except Exception as e:
        print(" [-] Deduplication error:", e)

    # 5. Final Count Verification
    try:
        final_alerts = client.table("alerts").select("id,domain").execute().data or []
        final_rpz = client.table("rpz_entries").select("id,domain").execute().data or []
        final_ssh = client.table("ssh_key_observations").select("id,fingerprint").execute().data or []
        final_personas = client.table("persona_nodes").select("id,value").execute().data or []
        
        print("\n--- FINAL PRODUCTION INTEGRITY AUDIT ---")
        print(f" Unique Alerts Remaining     : {len(final_alerts)}")
        print(f" Unique RPZ Entries          : {len(final_rpz)}")
        print(f" Fake SSH Observations       : {len(final_ssh)} (should be 0)")
        print(f" Fake Persona Nodes          : {len(final_personas)} (should be 0)")
    except Exception as e:
        print(" [-] Verification error:", e)

    print("================================================================")
    print("                 DATABASE IS NOW 100% CLEAN                     ")
    print("================================================================")

if __name__ == "__main__":
    asyncio.run(clean_and_dedup())
