"""
Verify all Supabase tables for Sessions 1-15:
1. alerts, campaigns, stix_objects, taxii_collections, subscribers
2. monitored_asn_ranges, easm_findings, cve_kev_matches
3. rpz_entries, monitored_defence_ips, passive_dns_observations
4. operator_clusters, campaign_infrastructure_fingerprints, cluster_review_queue
5. bgp_watchlist, bgp_incidents (Session 8)
6. orb_nodes (Session 9)
7. compiler_fingerprints, ssh_key_observations (Session 10)
8. predictive_domains (Session 12)
9. sandbox_analyses (Session 13)
10. canary_tokens, canary_fires, persona_nodes (Session 14)
"""
import asyncio
from garuda.database import get_supabase_client

ALL_TABLES = [
    "alerts",
    "campaigns",
    "stix_objects",
    "taxii_collections",
    "subscribers",
    "monitored_asn_ranges",
    "easm_findings",
    "cve_kev_matches",
    "rpz_entries",
    "monitored_defence_ips",
    "passive_dns_observations",
    "operator_clusters",
    "campaign_infrastructure_fingerprints",
    "cluster_review_queue",
    "bgp_watchlist",
    "bgp_incidents",
    "orb_nodes",
    "compiler_fingerprints",
    "ssh_key_observations",
    "predictive_domains",
    "sandbox_analyses",
    "canary_tokens",
    "canary_fires",
    "persona_nodes",
]

async def main():
    client = get_supabase_client()
    if not client:
        print("ERROR: Supabase client unavailable.")
        return

    print("=== CHECKING ALL 24 SUPABASE TABLES ===")
    missing = []
    present = []

    for table in ALL_TABLES:
        try:
            res = client.table(table).select("*").limit(1).execute()
            count = len(res.data) if res.data is not None else 0
            present.append((table, count))
            print(f"  [OK] Table '{table}' exists (sample rows: {count})")
        except Exception as e:
            missing.append(table)
            print(f"  [MISSING] Table '{table}': {e}")

    print(f"\nSummary: {len(present)}/{len(ALL_TABLES)} tables verified in Supabase.")
    if missing:
        print(f"Tables needing SQL creation: {missing}")

if __name__ == "__main__":
    asyncio.run(main())
