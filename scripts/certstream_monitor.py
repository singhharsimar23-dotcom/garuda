"""
GARUDA CertStream CT Log Monitor
Runs for ~5 minutes in GitHub Actions, filters domain names against
APT36 Tier-1 and Tier-2 keyword patterns, and POSTs candidates to
the GARUDA /api/collect/webhook endpoint.
"""

import asyncio
import logging
import os
import signal
import sys
import time
import httpx
import certstream

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("certstream_monitor")

GARUDA_API_URL = os.environ.get("GARUDA_API_URL", "https://garud-intel.vercel.app")
CF_WORKER_URL = os.environ.get("CF_WORKER_URL", "https://garuda-ct-worker.garuda-ct-worker.workers.dev")
CRON_SECRET = os.environ.get("CRON_SECRET", "")
RUN_DURATION_SECONDS = 300  # 5 minutes per GH Actions run


TIER1_KEYWORDS = [
    "mod", "gov", "nic", "army", "navy", "airforce", "drdo", "isro",
    "mil", "defence", "defense", "hal", "bel", "barc", "ntro", "dae",
    "pmindia", "meity", "cert-in", "certin", "bhel", "sail", "iit",
    "aiims", "uidai", "incometax", "epfindia", "rbi", "sebi", "mea",
    "mha", "npcil", "nciipc", "sparsh", "sena", "raksha", "mantralaya",
]

SUSPICIOUS_TLDS = {
    ".space", ".online", ".site", ".xyz", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".top", ".pw", ".club", ".live", ".icu", ".vip",
    ".ws", ".cc", ".cv",
}

dispatched = 0
start_time = time.time()


def domain_matches(domain: str) -> bool:
    domain_lower = domain.lower()
    has_keyword = any(kw in domain_lower for kw in TIER1_KEYWORDS)
    has_suspicious_tld = any(domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS)
    return has_keyword and has_suspicious_tld


def callback(message, context):
    global dispatched

    if time.time() - start_time > RUN_DURATION_SECONDS:
        logger.info(f"Monitor window complete. Dispatched {dispatched} candidates.")
        sys.exit(0)

    if message.get("message_type") != "certificate_update":
        return

    domains = (
        message.get("data", {})
        .get("leaf_cert", {})
        .get("all_domains", [])
    )

    for domain in domains:
        if domain.startswith("*."):
            domain = domain[2:]
        if domain_matches(domain):
            logger.info(f"[MATCH] {domain}")
            asyncio.run(dispatch_domain(domain, message.get("data", {})))


async def dispatch_domain(domain: str, cert_data: dict):
    global dispatched
    payload = {
        "domain": domain,
        "source": "certstream_gha",
        "cert_data": cert_data.get("leaf_cert"),
        "data": cert_data,
    }

    # Tier 1: Try Cloudflare Edge Worker gateway
    if CF_WORKER_URL:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(CF_WORKER_URL, json=payload)
                if res.status_code == 200:
                    dispatched += 1
                    logger.info(f"[OK: CF EDGE] Dispatched {domain} to Cloudflare Worker ({dispatched} total)")
                    return
        except Exception as e:
            logger.debug(f"CF Worker dispatch failed ({e}). Falling back to direct API...")

    # Tier 2: Direct API Fallback
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(
                f"{GARUDA_API_URL}/api/collect/webhook",
                headers={
                    "Authorization": f"Bearer {CRON_SECRET}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if res.status_code == 200:
                dispatched += 1
                logger.info(f"[OK: DIRECT] Dispatched {domain} ({dispatched} total)")
    except Exception as e:
        logger.warning(f"[ERR] Direct dispatch failed for {domain}: {e}")



def on_error(instance, exception):
    logger.warning(f"CertStream error: {exception}")


if __name__ == "__main__":
    logger.info(f"Starting CertStream monitor for {RUN_DURATION_SECONDS}s -> {GARUDA_API_URL}")
    certstream.listen_for_events(callback, on_error=on_error, url="wss://certstream.calidog.io/")
