"""
Render Autonomous Deployer Script
Triggers live production builds across all GARUDA microservices using the Render REST API.
"""

import json
import os
import sys
import httpx
from dotenv import load_dotenv

# Load local .env without hardcoding secrets in source code
load_dotenv()

RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "")
REPO_URL = "https://github.com/singhharsimar23-dotcom/garuda"
BRANCH = "main"

if not RENDER_API_KEY:
    print("Error: RENDER_API_KEY not found in environment.")
    sys.exit(1)

headers = {
    "Authorization": f"Bearer {RENDER_API_KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# 1. Fetch all active services
print("Fetching current Render services...")
r = httpx.get("https://api.render.com/v1/services?limit=20", headers=headers, timeout=15.0)
if r.status_code != 200:
    print(f"Failed to fetch services: {r.status_code} - {r.text}")
    sys.exit(1)

services_data = r.json()
active_services = {}
owner_id = None

for item in services_data:
    s = item.get("service", {})
    name = s.get("name")
    sid = s.get("id")
    owner_id = s.get("ownerId", owner_id)
    active_services[name] = sid
    print(f"  Found existing service: {name} ({sid})")

print(f"\nAccount Owner ID: {owner_id}")

# 2. Trigger fresh deployment for existing services
core_services = [
    ("garuda-axiom-service", "srv-da9seme7bikc73eqo7i0"),
    ("garuda-brahma-service", "srv-da9seme7bikc73eqo7hg"),
    ("garuda-utne-service", "srv-da9seme7bikc73eqo7ig"),
]

for name, sid in core_services:
    if name in active_services:
        actual_id = active_services[name]
        print(f"\nTriggering latest deploy for {name} ({actual_id})...")
        deploy_payload = {"clearCache": "do_not_clear"}
        dep_res = httpx.post(
            f"https://api.render.com/v1/services/{actual_id}/deploys",
            headers=headers,
            json=deploy_payload,
            timeout=15.0,
        )
        if dep_res.status_code in (200, 201):
            d = dep_res.json()
            print(f"  Deploy initiated! ID={d.get('id')} | Status={d.get('status')} | CreatedAt={d.get('createdAt')}")
        else:
            print(f"  Deploy failed: {dep_res.status_code} - {dep_res.text}")

# 3. Check if garuda-sentinel-service exists; if not, create it via Render API
if "garuda-sentinel-service" not in active_services:
    print("\nCreating new service: garuda-sentinel-service on Render...")
    service_payload = {
        "type": "web_service",
        "name": "garuda-sentinel-service",
        "ownerId": owner_id,
        "repo": REPO_URL,
        "branch": BRANCH,
        "autoDeploy": "yes",
        "serviceDetails": {
            "env": "docker",
            "dockerContext": "./sentinel-service",
            "dockerfilePath": "./sentinel-service/Dockerfile",
            "plan": "free",
            "region": "oregon",
            "healthCheckPath": "/health",
            "envVars": [
                {"key": "SUPABASE_URL", "value": os.environ.get("SUPABASE_URL", "")},
                {"key": "SUPABASE_SERVICE_ROLE_KEY", "value": os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")},
                {"key": "INTER_SERVICE_SECRET", "value": os.environ.get("INTER_SERVICE_SECRET", "")},
                {"key": "AXIOM_SERVICE_URL", "value": os.environ.get("AXIOM_SERVICE_URL", "")},
                {"key": "BRAHMA_SERVICE_URL", "value": os.environ.get("BRAHMA_SERVICE_URL", "")},
                {"key": "DHARMA_SERVICE_URL", "value": os.environ.get("DHARMA_SERVICE_URL", "")},
                {"key": "GROQ_API_KEY", "value": os.environ.get("GROQ_API_KEY", "")},
                {"key": "GROQ_MODEL", "value": os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")},
                {"key": "TELEGRAM_BOT_TOKEN", "value": os.environ.get("TELEGRAM_BOT_TOKEN", "")},
                {"key": "TELEGRAM_CHAT_ID", "value": os.environ.get("TELEGRAM_CHAT_ID", "")},
            ],
        },
    }
    create_res = httpx.post("https://api.render.com/v1/services", headers=headers, json=service_payload, timeout=20.0)
    if create_res.status_code in (200, 201):
        s_data = create_res.json()
        new_id = s_data.get("id")
        print(f"  Successfully created garuda-sentinel-service on Render! ID={new_id}")
    else:
        print(f"  Failed creating garuda-sentinel-service: {create_res.status_code} - {create_res.text}")
else:
    sentinel_id = active_services["garuda-sentinel-service"]
    print(f"\nTriggering latest deploy for garuda-sentinel-service ({sentinel_id})...")
    dep_res = httpx.post(f"https://api.render.com/v1/services/{sentinel_id}/deploys", headers=headers, json={"clearCache": "do_not_clear"}, timeout=15.0)
    print(f"  Response: {dep_res.status_code} - {dep_res.text}")

print("\nRender deployment dispatch complete.")
