"""
GARUDA — Master Production Connection & Environment Audit
Validates all Phase 1, Phase 2, and Phase 3 integrations.
"""

import asyncio
import json
import os
import urllib.request
import httpx
from dotenv import load_dotenv

load_dotenv()


async def check_all():
    print("=" * 80)
    print("  GARUDA PLATFORM — PRODUCTION READINESS & ENVIRONMENT DIAGNOSTIC")
    print("=" * 80)

    results = []

    # 1. Supabase
    print("\n[1] Checking Supabase...")
    sub_url = os.environ.get("SUPABASE_URL")
    sub_key = os.environ.get("SUPABASE_SERVICE_KEY") or os.environ.get("SUPABASE_KEY")
    if sub_url and sub_key:
        try:
            from supabase import create_client
            sb = create_client(sub_url, sub_key)
            res = sb.table("alerts").select("id").limit(1).execute()
            results.append(("Supabase PostgreSQL & Auth", "PASS", f"Connected to {sub_url[:30]}..."))
        except Exception as e:
            results.append(("Supabase PostgreSQL & Auth", "FAIL", str(e)[:100]))
    else:
        results.append(("Supabase PostgreSQL & Auth", "MISSING", "SUPABASE_URL or SUPABASE_KEY not set in .env"))

    # 2. Upstash Redis
    print("[2] Checking Upstash Redis...")
    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if redis_url and redis_token:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(f"{redis_url}/ping", headers={"Authorization": f"Bearer {redis_token}"})
                if r.status_code == 200 and "PONG" in r.text:
                    results.append(("Upstash Redis", "PASS", "PONG received (REST API valid)"))
                else:
                    results.append(("Upstash Redis", "FAIL", f"HTTP {r.status_code}: {r.text[:60]}"))
        except Exception as e:
            results.append(("Upstash Redis", "FAIL", str(e)[:100]))
    else:
        results.append(("Upstash Redis", "MISSING", "UPSTASH_REDIS_REST_URL or TOKEN not set in .env"))

    # 3. Gemini API (Primary AI Engine)
    print("[3] Checking Gemini API (Primary LLM)...")
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if gemini_key:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                url = f"https://generativelanguage.googleapis.com/v1beta/models?key={gemini_key}"
                r = await client.get(url)
                if r.status_code == 200:
                    results.append(("Gemini API (gemini-2.5-flash / generative-ai)", "PASS", "API Key Validated"))
                else:
                    results.append(("Gemini API", "FAIL", f"HTTP {r.status_code}: {r.text[:60]}"))
        except Exception as e:
            results.append(("Gemini API", "FAIL", str(e)[:100]))
    else:
        results.append(("Gemini API", "MISSING", "GEMINI_API_KEY not set in .env"))

    # 4. Groq API (Fallback LLM)
    print("[4] Checking Groq API (Fallback LLM)...")
    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {groq_key}"})
                if r.status_code == 200:
                    results.append(("Groq API (Fallback LLM)", "PASS", "API Key Validated"))
                else:
                    results.append(("Groq API", "FAIL", f"HTTP {r.status_code}: {r.text[:60]}"))
        except Exception as e:
            results.append(("Groq API", "FAIL", str(e)[:100]))
    else:
        results.append(("Groq API", "MISSING", "GROQ_API_KEY not set in .env"))

    # 5. Telegram Bot Alerting
    print("[5] Checking Telegram Bot...")
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID")
    if tg_token:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"https://api.telegram.org/bot{tg_token}/getMe")
                if r.status_code == 200 and r.json().get("ok"):
                    bot_name = r.json().get("result", {}).get("username", "bot")
                    results.append(("Telegram Bot Notification", "PASS", f"Bot @{bot_name} active (Chat: {tg_chat or 'Not Set'})"))
                else:
                    results.append(("Telegram Bot Notification", "FAIL", f"HTTP {r.status_code}: {r.text[:60]}"))
        except Exception as e:
            results.append(("Telegram Bot Notification", "FAIL", str(e)[:100]))
    else:
        results.append(("Telegram Bot Notification", "MISSING", "TELEGRAM_BOT_TOKEN not set in .env"))

    # 6. Northflank PostgreSQL (Phase 3 Almanac DB)
    print("[6] Checking Northflank PostgreSQL (NORTHFLANK_DB_URL)...")
    nf_db = os.environ.get("NORTHFLANK_DB_URL") or os.environ.get("DATABASE_URL")
    if nf_db:
        try:
            import psycopg2
            conn = psycopg2.connect(nf_db, connect_timeout=5)
            conn.close()
            results.append(("Northflank PostgreSQL (Almanac DB)", "PASS", "Direct DB connection verified"))
        except Exception as e:
            results.append(("Northflank PostgreSQL (Almanac DB)", "FAIL", str(e)[:100]))
    else:
        results.append(("Northflank PostgreSQL (Almanac DB)", "MISSING", "NORTHFLANK_DB_URL not set in .env"))

    # 7. Cloudflare DNS Sinkhole
    print("[7] Checking Cloudflare API...")
    cf_token = os.environ.get("CF_API_TOKEN")
    cf_zone = os.environ.get("CF_ZONE_ID")
    if cf_token:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get("https://api.cloudflare.com/client/v4/user/tokens/verify", headers={"Authorization": f"Bearer {cf_token}"})
                if r.status_code == 200 and r.json().get("success"):
                    results.append(("Cloudflare DNS Sinkhole", "PASS", f"Token verified (Zone ID: {cf_zone or 'Not Set'})"))
                else:
                    results.append(("Cloudflare DNS Sinkhole", "FAIL", f"HTTP {r.status_code}: {r.text[:60]}"))
        except Exception as e:
            results.append(("Cloudflare DNS Sinkhole", "FAIL", str(e)[:100]))
    else:
        results.append(("Cloudflare DNS Sinkhole", "MISSING", "CF_API_TOKEN not set in .env"))

    # 8. External Threat Intel Feeds (OTX, VirusTotal, AbuseIPDB, Shodan)
    print("[8] Checking Intel Feeds (OTX, VirusTotal, AbuseIPDB, Shodan)...")
    otx_key = os.environ.get("OTX_API_KEY")
    if otx_key:
        results.append(("AlienVault OTX", "PASS", "Key Configured"))
    else:
        results.append(("AlienVault OTX", "MISSING", "OTX_API_KEY not set in .env"))

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if vt_key:
        results.append(("VirusTotal API", "PASS", "Key Configured"))
    else:
        results.append(("VirusTotal API", "MISSING", "VIRUSTOTAL_API_KEY not set in .env"))

    abuse_key = os.environ.get("ABUSEIPDB_KEY")
    if abuse_key:
        results.append(("AbuseIPDB API", "PASS", "Key Configured"))
    else:
        results.append(("AbuseIPDB API", "MISSING", "ABUSEIPDB_KEY not set in .env"))

    shodan_key = os.environ.get("SHODAN_API_KEY")
    if shodan_key:
        results.append(("Shodan API", "PASS", "Key Configured"))
    else:
        results.append(("Shodan API", "MISSING", "SHODAN_API_KEY not set in .env"))

    # 9. Phase 3 Inter-Service Security
    print("[9] Checking Inter-Service & Agent Security Keys...")
    agent_key = os.environ.get("AGENT_API_KEY")
    secret = os.environ.get("INTER_SERVICE_SECRET")
    cron_sec = os.environ.get("CRON_SECRET")

    results.append(("AGENT_API_KEY (Host Agent Auth)", "PASS" if agent_key else "MISSING", "Configured" if agent_key else "Needs generated token"))
    results.append(("INTER_SERVICE_SECRET (AXIOM <-> BRAHMA)", "PASS" if secret else "MISSING", "Configured" if secret else "Needs generated token"))
    results.append(("CRON_SECRET (Scheduled Endpoints)", "PASS" if cron_sec else "MISSING", "Configured" if cron_sec else "Needs generated token"))

    # 10. Service Deployment URLs
    axiom_url = os.environ.get("NORTHFLANK_AXIOM_URL")
    brahma_url = os.environ.get("NORTHFLANK_BRAHMA_URL")
    koyeb_url = os.environ.get("KOYEB_UTNE_URL")

    results.append(("NORTHFLANK_AXIOM_URL (Service 1)", "PASS" if axiom_url else "OPTIONAL_UNTIL_DEPLOYED", axiom_url or "Fill after Northflank deploy"))
    results.append(("NORTHFLANK_BRAHMA_URL (Service 2)", "PASS" if brahma_url else "OPTIONAL_UNTIL_DEPLOYED", brahma_url or "Fill after Northflank deploy"))
    results.append(("KOYEB_UTNE_URL (Service 3)", "PASS" if koyeb_url else "OPTIONAL_UNTIL_DEPLOYED", koyeb_url or "Fill after Koyeb deploy"))

    print("\n" + "=" * 80)
    print("  SUMMARY AUDIT REPORT")
    print("=" * 80)
    for service, status, detail in results:
        badge = f"[{status}]"
        print(f"{badge:<10} | {service:<42} | {detail}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(check_all())
