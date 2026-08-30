"""
Cloudflare DNS Sinkhole Execution Client
Executes real DNS redirection to 0.0.0.0 via Cloudflare API v4 for verified C2 domains.
"""

import logging
import os
from typing import Any, Dict, Optional, Tuple
import httpx

from .telegram_notifier import get_telegram_notifier

logger = logging.getLogger("brahma.dharma.cloudflare")

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareSinkholeExecutor:
    """
    Executes DNS sinkholing using official Cloudflare v4 DNS Records API endpoints.
    """

    def __init__(
        self,
        api_token: Optional[str] = None,
        zone_id: Optional[str] = None,
    ):
        self.api_token = api_token or os.environ.get("CF_API_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN")
        self.zone_id = zone_id or os.environ.get("CF_ZONE_ID") or os.environ.get("CLOUDFLARE_ZONE_ID")
        self.telegram = get_telegram_notifier()

    async def execute_sinkhole(
        self,
        domain: str,
        action_id: str,
        hostname: str,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Execute Cloudflare DNS sinkhole:
        Returns (status: 'EXECUTED' | 'ALREADY_APPLIED' | 'FAILED', execution_detail: dict)
        """
        if not self.api_token or not self.zone_id:
            logger.warning("Cloudflare credentials (CF_API_TOKEN / CF_ZONE_ID) not configured.")
            detail = {"error": "Missing Cloudflare credentials", "simulated": True}
            return "FAILED", detail

        endpoint = f"{CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        body = {
            "type": "A",
            "name": domain,
            "content": "0.0.0.0",
            "ttl": 300,
            "proxied": False,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(endpoint, headers=headers, json=body)
                resp_json = resp.json() if resp.text else {}

                # 1. Successful Creation (HTTP 200 / 201)
                if resp.status_code in (200, 201) and resp_json.get("success"):
                    result = resp_json.get("result", {})
                    # Verification check
                    if result.get("name") == domain and result.get("content") == "0.0.0.0":
                        logger.info(f"Successfully sinkholed {domain} on Cloudflare (Record ID: {result.get('id')}).")
                        return "EXECUTED", resp_json

                # 2. Scope / Permission Denied (HTTP 403)
                if resp.status_code == 403:
                    logger.error(f"CF_TOKEN_INSUFFICIENT_SCOPE: Cloudflare returned 403 Forbidden for {domain}.")
                    await self.telegram.notify_execution_failed(
                        action_id=action_id,
                        action_type="DNS_SINKHOLE",
                        hostname=hostname,
                        target=domain,
                        error_detail="CF_TOKEN_INSUFFICIENT_SCOPE: API token lacks DNS:Edit permissions on zone.",
                    )
                    return "FAILED", resp_json

                # 3. Conflict / Already Exists (HTTP 400 with existing record)
                errors = resp_json.get("errors", [])
                error_msgs = [e.get("message", "").lower() for e in errors]
                is_duplicate = any("already exists" in m or "duplicate" in m for m in error_msgs) or resp.status_code == 400

                if is_duplicate:
                    # Look up existing record to confirm if already pointing to 0.0.0.0
                    lookup_url = f"{CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records?name={domain}"
                    lookup_resp = await client.get(lookup_url, headers=headers)
                    if lookup_resp.status_code == 200:
                        lookup_json = lookup_resp.json()
                        records = lookup_json.get("result", [])
                        for rec in records:
                            if rec.get("name") == domain and rec.get("content") == "0.0.0.0":
                                logger.info(f"Domain {domain} already sinkholed (0.0.0.0).")
                                return "ALREADY_APPLIED", lookup_json

                # Other failures
                logger.warning(f"Cloudflare DNS sinkhole failed for {domain} (HTTP {resp.status_code}): {resp.text[:200]}")
                await self.telegram.notify_execution_failed(
                    action_id=action_id,
                    action_type="DNS_SINKHOLE",
                    hostname=hostname,
                    target=domain,
                    error_detail=f"Cloudflare API returned HTTP {resp.status_code}: {resp_json.get('errors')}",
                )
                return "FAILED", resp_json

        except Exception as e:
            logger.error(f"Network error executing Cloudflare sinkhole for {domain}: {e}")
            await self.telegram.notify_execution_failed(
                action_id=action_id,
                action_type="DNS_SINKHOLE",
                hostname=hostname,
                target=domain,
                error_detail=str(e),
            )
            return "FAILED", {"error": str(e)}


_cf_executor = CloudflareSinkholeExecutor()


def get_cloudflare_sinkhole_executor() -> CloudflareSinkholeExecutor:
    return _cf_executor
