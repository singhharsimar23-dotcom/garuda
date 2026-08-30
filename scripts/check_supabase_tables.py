import os
import sys
sys.path.insert(0, ".")
from garuda.database import get_supabase_client

sb = get_supabase_client()
tables = ['alerts', 'threat_clusters', 'rpz_rules', 'stix_objects', 'anomaly_alerts_mirror', 'agent_heartbeats', 'monitored_agents', 'physics_observations']

print("=" * 60)
print("  SUPABASE PRODUCTION TABLES STATUS")
print("=" * 60)

for t in tables:
    try:
        res = sb.table(t).select('*').limit(1).execute()
        print(f"• Table '{t:<25}': EXISTS (rows: {len(res.data)})")
    except Exception as e:
        print(f"• Table '{t:<25}': NOT CREATED YET ({str(e)[:50]})")
