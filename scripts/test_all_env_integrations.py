"""
GARUDA — Comprehensive Environment & API Integration Diagnostic
Tests every service configured in .env and verifies live ingestion.
"""

import asyncio
import os
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()


async def test_supabase():
    print("\n[1/10] Testing Supabase Database & Auth...")
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")
    if not url or not key:
        return "[FAIL] SUPABASE_URL or SUPABASE_KEY missing"
    try:
        from garuda.database import get_supabase_client
        client = get_supabase_client()
        res = client.table("alerts").select("id,domain,score,detected_at").order("detected_at", desc=True).limit(5).execute()
        count = len(res.data or [])
        return f"[PASS] Supabase operational. Retrieved {count} active alerts. Latest: {res.data[0]['domain'] if count > 0 else 'None'}"
    except Exception as e:
        return f"[FAIL] Supabase error: {e}"


async def test_upstash_redis():
    print("\n[2/10] Testing Upstash Redis...")
    url = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if not url or not token:
        return "[FAIL] UPSTASH_REDIS_REST_URL or TOKEN missing"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                f"{url}/ping",
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 200 and "PONG" in resp.text:
                return f"[PASS] Upstash Redis connected. Response: {resp.text.strip()}"
            return f"[WARN] Redis status {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"[FAIL] Upstash Redis error: {e}"


async def test_shodan():
    print("\n[3/10] Testing Shodan API Key...")
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return "[SKIP] SHODAN_API_KEY not configured"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"https://api.shodan.io/api-info?key={key}")
            if resp.status_code == 200:
                data = resp.json()
                credits = data.get("query_credits", 0)
                plan = data.get("plan", "unknown")
                return f"[PASS] Shodan API valid. Plan: {plan}, Query Credits: {credits}"
            return f"[FAIL] Shodan API returned status {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"[FAIL] Shodan error: {e}"


async def test_virustotal():
    print("\n[4/10] Testing VirusTotal API Key...")
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return "[SKIP] VIRUSTOTAL_API_KEY not configured"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://www.virustotal.com/api/v3/domains/google.com",
                headers={"x-apikey": key},
            )
            if resp.status_code == 200:
                return "[PASS] VirusTotal API key authenticated successfully (HTTP 200)."
            return f"[FAIL] VirusTotal returned status {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"[FAIL] VirusTotal error: {e}"


async def test_urlhaus():
    print("\n[5/10] Testing URLhaus API Token...")
    token = os.environ.get("URLHAUS_TOKEN") or os.environ.get("URLHAUS_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Auth-Key": token} if token else {},
            )
            if resp.status_code == 200:
                data = resp.json()
                urls_count = len(data.get("urls", []))
                return f"[PASS] URLhaus connected. Retrieved {urls_count} recent malware URLs."
            return f"[WARN] URLhaus returned {resp.status_code}"
    except Exception as e:
        return f"[FAIL] URLhaus error: {e}"


async def test_whoisxml():
    print("\n[6/10] Testing WhoisXML API Key...")
    key = os.environ.get("WHOISXML_API_KEY")
    if not key:
        return "[SKIP] WHOISXML_API_KEY not configured"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={key}&domainName=google.com&outputFormat=JSON"
            )
            if resp.status_code == 200 and "WhoisRecord" in resp.text:
                return "[PASS] WhoisXML API key authenticated and responsive."
            return f"[WARN] WhoisXML status {resp.status_code}"
    except Exception as e:
        return f"[FAIL] WhoisXML error: {e}"


async def test_telegram_bot():
    print("\n[7/10] Testing Telegram Bot Notification Engine...")
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token:
        return "[SKIP] TELEGRAM_BOT_TOKEN not configured"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"https://api.telegram.org/bot{token}/getMe")
            if resp.status_code == 200:
                data = resp.json()
                bot_name = data.get("result", {}).get("username", "Unknown")
                return f"[PASS] Telegram Bot authenticated (@{bot_name}) with Chat ID: {chat_id}"
            return f"[FAIL] Telegram API returned {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"[FAIL] Telegram error: {e}"


async def test_cloudflare_api():
    print("\n[8/10] Testing Cloudflare API Token...")
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    if not token:
        return "[SKIP] CLOUDFLARE_API_TOKEN not configured"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("result", {}).get("status", "active")
                return f"[PASS] Cloudflare API token verified (Status: {status}). Account ID: {account_id}"
            return f"[WARN] Cloudflare token verify returned {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"[FAIL] Cloudflare error: {e}"


async def test_qdrant():
    print("\n[9/10] Testing Qdrant Cloud Vector Store...")
    url = os.environ.get("QDRANT_URL")
    api_key = os.environ.get("QDRANT_API_KEY")
    if not url or not api_key:
        return "[SKIP] QDRANT_URL or QDRANT_API_KEY not configured"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"{url}/collections",
                headers={"api-key": api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                cols = [c.get("name") for c in data.get("result", {}).get("collections", [])]
                return f"[PASS] Qdrant Cloud operational. Collections: {cols}"
            return f"[WARN] Qdrant status {resp.status_code}"
    except Exception as e:
        return f"[FAIL] Qdrant error: {e}"


async def test_live_data_ingestion():
    print("\n[10/10] Testing Live Threat Data Ingestion Cycle (crt.sh + CIRCL + MalwareBazaar)...")
    try:
        from garuda.collector import run_collection
        summary = await run_collection()
        return f"[PASS] Live collection cycle completed successfully. Metrics: {summary}"
    except Exception as e:
        return f"[FAIL] Live collection error: {e}"


async def main():
    print("==================================================================")
    print("       GARUDA VAJRA — FULL ENVIRONMENT & INTEGRATION AUDIT        ")
    print("==================================================================")

    results = await asyncio.gather(
        test_supabase(),
        test_upstash_redis(),
        test_shodan(),
        test_virustotal(),
        test_urlhaus(),
        test_whoisxml(),
        test_telegram_bot(),
        test_cloudflare_api(),
        test_qdrant(),
        test_live_data_ingestion(),
        return_exceptions=True,
    )

    print("\n==================================================================")
    print("                     FINAL AUDIT SUMMARY                          ")
    print("==================================================================")
    for res in results:
        print(f" • {res}")
    print("==================================================================")


if __name__ == "__main__":
    asyncio.run(main())
