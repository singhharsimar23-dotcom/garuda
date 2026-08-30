"""
GARUDA — Automated Render Deployment via REST API
Provisions all 3 microservices on Render using an API key.
"""

import json
import os
import sys
import httpx

RENDER_API_BASE = "https://api.render.com/v1"

ENV_KEYS = [
    "PORT", "ENVIRONMENT", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_KEY",
    "UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN", "GEMINI_API_KEY",
    "CRON_SECRET", "AGENT_API_KEY", "INTER_SERVICE_SECRET", "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY",
    "NORTHFLANK_AXIOM_URL", "NORTHFLANK_BRAHMA_URL", "RENDER_UTNE_URL"
]

def get_env_vars():
    vars_list = []
    for k in ENV_KEYS:
        val = os.environ.get(k)
        if val:
            vars_list.append({"key": k, "value": val})
    return vars_list

SERVICES_CONFIG = [
    {
        "name": "garuda-axiom-service",
        "dockerfilePath": "./axiom-service/Dockerfile",
        "dockerContext": "./axiom-service",
    },
    {
        "name": "garuda-brahma-service",
        "dockerfilePath": "./brahma-service/Dockerfile",
        "dockerContext": "./brahma-service",
    },
    {
        "name": "garuda-utne-service",
        "dockerfilePath": "./network-service/Dockerfile",
        "dockerContext": "./network-service",
    },
]


def deploy(api_key: str, repo_url: str = "https://github.com/singhharsimar23-dotcom/garuda"):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # 1. Get Owner / User ID
    print("[1/4] Authenticating with Render API...")
    with httpx.Client(headers=headers, timeout=15.0) as client:
        owners_resp = client.get(f"{RENDER_API_BASE}/owners")
        if owners_resp.status_code != 200:
            print(f"[FAIL] Render authentication failed: {owners_resp.text}")
            return False

        owners = owners_resp.json()
        if not owners:
            print("[FAIL] No workspace/owner found in Render account.")
            return False

        owner_id = owners[0]["owner"]["id"]
        owner_name = owners[0]["owner"].get("name", "Default")
        print(f"[PASS] Authenticated as '{owner_name}' (ID: {owner_id})")

        # 2. Deploy Each Service
        for idx, svc in enumerate(SERVICES_CONFIG, 1):
            print(f"\n[{idx+1}/4] Creating Web Service '{svc['name']}'...")
            payload = {
                "type": "web_service",
                "name": svc["name"],
                "ownerId": owner_id,
                "repo": repo_url,
                "branch": "main",
                "autoDeploy": "yes",
                "serviceDetails": {
                    "env": "docker",
                    "plan": "free",
                    "region": "oregon",
                    "dockerfilePath": svc["dockerfilePath"],
                    "dockerContext": svc["dockerContext"],
                    "healthCheckPath": "/health",
                    "envVars": get_env_vars(),
                },
            }

            resp = client.post(f"{RENDER_API_BASE}/services", json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                svc_id = data.get("id") or data.get("service", {}).get("id")
                svc_url = data.get("serviceDetails", {}).get("url") or data.get("service", {}).get("serviceDetails", {}).get("url")
                print(f"  [SUCCESS] Service Created: {svc['name']}")
                print(f"     ID:  {svc_id}")
                print(f"     URL: {svc_url}")
            else:
                print(f"  [ERROR] Error creating {svc['name']}: {resp.status_code}")
                print(f"     Response: {resp.text}")

    print("\n" + "=" * 60)
    print("  RENDER DEPLOYMENT COMPLETED")
    print("=" * 60)
    return True


if __name__ == "__main__":
    key = os.environ.get("RENDER_API_KEY")
    if len(sys.argv) > 1:
        key = sys.argv[1]

    if not key:
        print("Usage: python scripts/deploy_render_api.py <YOUR_RENDER_API_KEY>")
        print("Or set RENDER_API_KEY environment variable.")
        sys.exit(1)

    deploy(key)
