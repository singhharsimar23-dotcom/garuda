"""
GARUDA — Total Fake Data Purge & Verification Script
Inspects and cleans every table in Supabase.
"""

import asyncio
from garuda.database import get_supabase_client

async def total_purge():
    client = get_supabase_client()
    if not client:
        print("Error: Supabase client not available")
        return

    print("================================================================")
    print("      GARUDA — COMPLETE DATABASE INSPECTION & CLEANUP           ")
    print("================================================================")

    # 1. SSH Key Observations
    print("\n--- 1. Checking ssh_key_observations ---")
    try:
        res = client.table("ssh_key_observations").select("*").execute()
        rows = res.data or []
        print(f"Found {len(rows)} rows in ssh_key_observations.")
        for r in rows:
            print("  Row:", r)
        # Purge fake/synthetic SSH keys
        del_res = client.table("ssh_key_observations").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        print("  [+] Purged all synthetic ssh_key_observations.")
    except Exception as e:
        print("  Error:", e)

    # 2. Persona Nodes & Edges
    print("\n--- 2. Checking persona_nodes & persona_edges ---")
    try:
        p_nodes = client.table("persona_nodes").select("*").execute().data or []
        print(f"Found {len(p_nodes)} rows in persona_nodes.")
        for n in p_nodes:
            print("  Node:", n)
        client.table("persona_edges").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        client.table("persona_nodes").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        print("  [+] Purged all persona_nodes and persona_edges.")
    except Exception as e:
        print("  Error:", e)

    # 3. Sandbox Analyses
    print("\n--- 3. Checking sandbox_analyses ---")
    try:
        sb = client.table("sandbox_analyses").select("*").execute().data or []
        print(f"Found {len(sb)} rows in sandbox_analyses.")
        client.table("sandbox_analyses").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        print("  [+] Purged all mock sandbox_analyses.")
    except Exception as e:
        print("  Error:", e)

    # 4. Alerts
    print("\n--- 4. Checking alerts ---")
    try:
        alerts = client.table("alerts").select("id,domain,score,detected_at").execute().data or []
        print(f"Found {len(alerts)} alerts in database:")
        for a in alerts:
            print(f"  {a['domain']} (Score: {a.get('score')})")
    except Exception as e:
        print("  Error:", e)

    # 5. RPZ Entries
    print("\n--- 5. Checking rpz_entries ---")
    try:
        rpz = client.table("rpz_entries").select("*").execute().data or []
        print(f"Found {len(rpz)} RPZ entries.")
        for r in rpz:
            print(f"  {r.get('domain')} (Confidence: {r.get('confidence')})")
    except Exception as e:
        print("  Error:", e)

    print("\n================================================================")
    print("                    CLEANUP COMPLETE                            ")
    print("================================================================")

if __name__ == "__main__":
    asyncio.run(total_purge())
