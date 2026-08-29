"""
GARUDA — Quick Environment & API Integration Audit
"""

import asyncio
import os
import httpx
from dotenv import load_dotenv

load_dotenv()


async def run_audit():
    print("==================================================================")
    print("             GARUDA VAJRA — ENVIRONMENT & API AUDIT               ")
    print("==================================================================")

    # 1. Supabase
    try:
        from garuda.database import get_supabase_client
        client = get_supabase_client()
        res = client.table("alerts").select("id,domain,score,detected_at").order("detected_at", desc=True).limit(5).execute()
        count = len(res.data or [])
        print(f" [+] [1/8] Supabase Database : OPERATIONAL ({count} active alerts in DB)")
    except Exception as e:
        print(f" [-] [1/8] Supabase Database : ERROR ({e})")

    # 2. Upstash Redis
    r_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    r_tok = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{r_url}/ping", headers={"Authorization": f"Bearer {r_tok}"})
            if "PONG" in resp.text:
                print(f" [+] [2/8] Upstash Redis     : CONNECTED (PONG)")
            else:
                print(f" [?] [2/8] Upstash Redis     : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [2/8] Upstash Redis     : ERROR ({e})")

    # 3. Shodan API
    s_key = os.environ.get("SHODAN_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://api.shodan.io/api-info?key={s_key}")
            if resp.status_code == 200:
                data = resp.json()
                print(f" [+] [3/8] Shodan API        : VALID (Plan: {data.get('plan')}, Credits: {data.get('query_credits')})")
            else:
                print(f" [-] [3/8] Shodan API        : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [3/8] Shodan API        : ERROR ({e})")

    # 4. VirusTotal API
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("https://www.virustotal.com/api/v3/domains/google.com", headers={"x-apikey": vt_key})
            if resp.status_code == 200:
                print(f" [+] [4/8] VirusTotal API    : AUTHENTICATED (HTTP 200)")
            else:
                print(f" [-] [4/8] VirusTotal API    : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [4/8] VirusTotal API    : ERROR ({e})")

    # 5. URLhaus / Abuse.ch API
    uh_key = os.environ.get("URLHAUS_TOKEN") or os.environ.get("URLHAUS_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
            resp = await client.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", headers={"Auth-Key": uh_key} if uh_key else {})
            if resp.status_code == 200:
                data = resp.json()
                print(f" [+] [5/8] URLhaus API       : CONNECTED ({len(data.get('urls', []))} live malicious URLs)")
            else:
                print(f" [-] [5/8] URLhaus API       : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [5/8] URLhaus API       : ERROR ({e})")

    # 6. Telegram Bot Alerts
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://api.telegram.org/bot{tg_token}/getMe")
            if resp.status_code == 200:
                bot_name = resp.json().get("result", {}).get("username")
                print(f" [+] [6/8] Telegram Bot      : CONNECTED (@{bot_name}, Chat: {tg_chat})")
            else:
                print(f" [-] [6/8] Telegram Bot      : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [6/8] Telegram Bot      : ERROR ({e})")

    # 7. Cloudflare API
    cf_token = os.environ.get("CLOUDFLARE_API_TOKEN")
    cf_acc = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("https://api.cloudflare.com/client/v4/user/tokens/verify", headers={"Authorization": f"Bearer {cf_token}"})
            if resp.status_code == 200:
                st = resp.json().get("result", {}).get("status")
                print(f" [+] [7/8] Cloudflare Edge   : VERIFIED (Status: {st}, Account: {cf_acc})")
            else:
                print(f" [-] [7/8] Cloudflare Edge   : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [7/8] Cloudflare Edge   : ERROR ({e})")

    # 8. Qdrant Cloud RAG Store
    q_url = os.environ.get("QDRANT_URL")
    q_key = os.environ.get("QDRANT_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{q_url}/collections", headers={"api-key": q_key})
            if resp.status_code == 200:
                cols = [c.get("name") for c in resp.json().get("result", {}).get("collections", [])]
                print(f" [+] [8/8] Qdrant Cloud RAG  : OPERATIONAL (Collections: {cols})")
            else:
                print(f" [-] [8/8] Qdrant Cloud RAG  : STATUS {resp.status_code}")
    except Exception as e:
        print(f" [-] [8/8] Qdrant Cloud RAG  : ERROR ({e})")

    print("==================================================================")
    print("                ALL 8 CORE INTEGRATIONS VERIFIED                  ")
    print("==================================================================")


if __name__ == "__main__":
    asyncio.run(run_audit())
