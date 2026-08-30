import os
import sys
import httpx
from dotenv import load_dotenv

load_dotenv()

RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "rnd_iqkl9NrAsCrhh4EROGG6CfLNIpsT")
headers = {
    "Authorization": f"Bearer {RENDER_API_KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

SERVICES = {
    "garuda-sentinel-service": "srv-daa2hvdg1s2s73buh8q0",
    "garuda-brahma-service": "srv-da9seme7bikc73eqo7hg",
    "garuda-utne-service": "srv-da9seme7bikc73eqo7ig",
    "garuda-axiom-service": "srv-da9seme7bikc73eqo7i0",
}

env_payload = [
    {"key": "SUPABASE_URL", "value": os.environ.get("SUPABASE_URL", "https://sulnilwykmrosirbdvil.supabase.co")},
    {"key": "SUPABASE_SERVICE_ROLE_KEY", "value": os.environ.get("SUPABASE_SERVICE_ROLE_KEY", os.environ.get("SUPABASE_SERVICE_KEY", ""))},
    {"key": "SUPABASE_SERVICE_KEY", "value": os.environ.get("SUPABASE_SERVICE_KEY", "")},
    {"key": "INTER_SERVICE_SECRET", "value": os.environ.get("INTER_SERVICE_SECRET", "garuda_inter_sec_99e1f82c4b0d7a6e5f3c1b8a9e2d4f6c")},
    {"key": "AGENT_API_KEY", "value": os.environ.get("AGENT_API_KEY", "garuda_agent_sec_7a8f902b1c4e6d3a8e0f9b1c2d3e4f5a")},
    {"key": "AXIOM_SERVICE_URL", "value": "https://garuda-axiom-service.onrender.com"},
    {"key": "BRAHMA_SERVICE_URL", "value": "https://garuda-brahma-service.onrender.com"},
    {"key": "DHARMA_SERVICE_URL", "value": "https://garuda-brahma-service.onrender.com"},
    {"key": "SENTINEL_SERVICE_URL", "value": "https://garuda-sentinel-service.onrender.com"},
    {"key": "UTNE_SERVICE_URL", "value": "https://garuda-utne-service.onrender.com"},
    {"key": "GROQ_API_KEY", "value": os.environ.get("GROQ_API_KEY", "")},
    {"key": "GROQ_MODEL", "value": os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")},
    {"key": "GROQ_PREFERRED_MODEL", "value": os.environ.get("GROQ_PREFERRED_MODEL", "llama-3.3-70b-versatile")},
    {"key": "TELEGRAM_BOT_TOKEN", "value": os.environ.get("TELEGRAM_BOT_TOKEN", "")},
    {"key": "TELEGRAM_CHAT_ID", "value": os.environ.get("TELEGRAM_CHAT_ID", "")},
    {"key": "FEATURE_VIBEWARE_FEED", "value": "true"},
    {"key": "MALWAREBAZAAR_API_KEY", "value": os.environ.get("MALWAREBAZAAR_API_KEY", "680826f6932bcdcb5b489b2fe3b0ebd81e861a64098438d6")},
    {"key": "THREATFOX_API_KEY", "value": os.environ.get("THREATFOX_API_KEY", "680826f6932bcdcb5b489b2fe3b0ebd81e861a64098438d6")},
    {"key": "PORT", "value": "10000"},
]

for name, srv_id in SERVICES.items():
    print(f"Syncing environment variables to {name} ({srv_id})...")
    r = httpx.put(f"https://api.render.com/v1/services/{srv_id}/env-vars", headers=headers, json=env_payload, timeout=20.0)
    print(f"  -> Response: {r.status_code}")

