"""
GARUDA CertStream WebSocket Live Monitor.

Connects to wss://certstream.calidog.io, monitors certificate issuance streams,
filters domains matching Tier-1 national infrastructure keywords, and forwards
matching candidates to the GARUDA backend API (/api/collect/webhook).
"""
import asyncio
import json
import logging
import os
import sys
import httpx

try:
    import certstream
except ImportError:
    certstream = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("certstream_monitor")

GARUDA_API_URL = os.environ.get("GARUDA_API_URL", "https://garuda-ochre.vercel.app").rstrip("/")
CRON_SECRET = os.environ.get("CRON_SECRET", "")

TIER_1_KEYWORDS = [
    "mod", "gov", "nic", "army", "drdo", "isro", "mil", "defence", "defense",
    "hal", "bel", "barc", "ntro", "dae", "uidai", "incometax", "pmindia", "meity",
    "cert-in", "bhel", "sail", "iit", "aiims", "cbi", "ib", "raw", "bsf", "crpf",
    "raksha", "mantralaya", "indianarmy", "indiannavy", "iaf", "airforce",
]


def callback(message, context):
    """Callback triggered on each certificate update from CertStream."""
    if message["message_type"] != "certificate_update":
        return

    data = message.get("data", {})
    leaf_cert = data.get("leaf_cert", {})
    all_domains = leaf_cert.get("all_domains", [])

    for domain in all_domains:
        domain_lower = domain.lower().strip().lstrip("*.")
        if any(kw in domain_lower for kw in TIER_1_KEYWORDS):
            logger.info(f"Target keyword detected in certificate: {domain_lower}")
            try:
                headers = {"Content-Type": "application/json"}
                if CRON_SECRET:
                    headers["Authorization"] = f"Bearer {CRON_SECRET}"

                payload = {
                    "domain": domain_lower,
                    "source": "certstream_ws",
                    "cert_data": leaf_cert,
                }
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(f"{GARUDA_API_URL}/api/collect/webhook", json=payload, headers=headers)
                    logger.info(f"Forwarded {domain_lower} -> Status {resp.status_code}")
            except Exception as e:
                logger.error(f"Error forwarding candidate {domain_lower}: {e}")


def main():
    logger.info("Starting GARUDA CertStream WebSocket Client...")
    if certstream is None:
        logger.error("certstream library not installed. Install with: pip install certstream")
        sys.exit(1)

    certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")


if __name__ == "__main__":
    main()
