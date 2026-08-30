"""
Domain Lifecycle State Machine.

APT36 infrastructure follows a measurable provisioning sequence.
From 10 years of documented campaigns (APTnotes corpus, MITRE G0134):

  CERT_ISSUED → DNS_RESOLVING → HTTP_LIVE → MX_CONFIGURED → WEAPONIZED
       T=0           T+2-8h        T+12-24h     T+24-48h       T+48-72h

GARUDA polls flagged domains every 30 minutes to track state transitions.
On each transition: Supabase update, Telegram alert at HTTP_LIVE+.
On WEAPONIZED: DHARMA Tier 1 pre-arms. No operator action required.

Table: domain_lifecycle (created in migration 013_hunt_tables.sql)
"""

import asyncio
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# dnspython is installed in garuda-agent; sentinel-service needs it added to requirements.txt
try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False
    logger.warning(
        "dnspython not installed — DNS lifecycle checks disabled. "
        "Add 'dnspython>=2.4.0' to sentinel-service/requirements.txt"
    )


class LifecycleStage(str, Enum):
    CERT_ISSUED = "CERT_ISSUED"
    DNS_RESOLVING = "DNS_RESOLVING"
    HTTP_LIVE = "HTTP_LIVE"
    MX_CONFIGURED = "MX_CONFIGURED"
    WEAPONIZED = "WEAPONIZED"
    SINKHOLED = "SINKHOLED"


class DomainLifecycleTracker:
    def __init__(self, supabase_client, telegram_alerter, dharma_prearm_fn):
        self.db = supabase_client
        self.telegram = telegram_alerter
        self.prearm = dharma_prearm_fn

    async def register(
        self,
        domain: str,
        ip: Optional[str],
        stix_id: str,
        cert_logged_at: datetime,
    ) -> None:
        """Called by EnrichmentPipeline when a new CT hit is processed."""
        stage = LifecycleStage.DNS_RESOLVING if ip else LifecycleStage.CERT_ISSUED
        try:
            if self.db:
                self.db.table("domain_lifecycle").upsert({
                    "domain": domain,
                    "stix_id": stix_id,
                    "current_stage": stage.value,
                    "cert_logged_at": cert_logged_at.isoformat(),
                    "resolved_ip": ip,
                    "last_checked_at": datetime.now(timezone.utc).isoformat(),
                }, on_conflict="domain").execute()
        except Exception as exc:
            logger.error(f"Failed to register domain lifecycle domain={domain}: {exc}")

    async def poll_loop(self) -> None:
        """
        Runs every 30 minutes alongside existing SENTINEL loops.
        Checks all domains in CERT_ISSUED or DNS_RESOLVING or HTTP_LIVE stages.
        """
        logger.info("Domain Lifecycle Poll loop started — 30-minute interval")
        while True:
            try:
                await self._poll_active_domains()
            except asyncio.CancelledError:
                logger.info("Domain Lifecycle Poll loop cancelled — shutting down")
                break
            except Exception as exc:
                logger.error(f"Lifecycle poll failed: {exc}", exc_info=True)
            await asyncio.sleep(1800)  # 30 minutes

    async def _poll_active_domains(self) -> None:
        if not self.db:
            return

        try:
            result = self.db.table("domain_lifecycle").select("*").in_(
                "current_stage",
                [
                    LifecycleStage.CERT_ISSUED.value,
                    LifecycleStage.DNS_RESOLVING.value,
                    LifecycleStage.HTTP_LIVE.value,
                ]
            ).execute()
        except Exception as exc:
            logger.error(f"Failed to fetch active lifecycle domains: {exc}")
            return

        for row in (result.data or []):
            try:
                await self._advance_stage(row)
                await asyncio.sleep(1)  # Rate limit DNS/HTTP queries
            except Exception as exc:
                logger.error(
                    f"Lifecycle advance failed domain={row.get('domain', '?')}: {exc}"
                )

    async def _advance_stage(self, row: dict) -> None:
        domain = row["domain"]
        stage = LifecycleStage(row["current_stage"])
        new_stage = stage

        if stage == LifecycleStage.CERT_ISSUED:
            if await self._check_dns(domain):
                new_stage = LifecycleStage.DNS_RESOLVING

        elif stage == LifecycleStage.DNS_RESOLVING:
            if await self._check_http(domain):
                new_stage = LifecycleStage.HTTP_LIVE
                if self.telegram:
                    await self.telegram.alert(
                        f"🔴 LIFECYCLE: {domain} HTTP_LIVE — "
                        f"phishing infrastructure becoming active"
                    )

        elif stage == LifecycleStage.HTTP_LIVE:
            has_mx = await self._check_mx(domain)
            if has_mx:
                new_stage = LifecycleStage.WEAPONIZED
                if self.telegram:
                    await self.telegram.alert(
                        f"🚨 WEAPONIZED: {domain} MX configured — "
                        f"phishing email infrastructure active"
                    )
                # Pre-arm DHARMA Tier 1 — no operator confirmation needed
                if self.prearm:
                    await self.prearm(domain=domain, stix_id=row.get("stix_id", ""))

        if new_stage != stage:
            try:
                if self.db:
                    self.db.table("domain_lifecycle").update({
                        "current_stage": new_stage.value,
                        "last_checked_at": datetime.now(timezone.utc).isoformat(),
                    }).eq("domain", domain).execute()
            except Exception as exc:
                logger.error(f"Failed to update lifecycle stage for {domain}: {exc}")
            logger.info(f"[LIFECYCLE] {domain}: {stage.value} → {new_stage.value}")

    async def _check_dns(self, domain: str) -> bool:
        if not _DNS_AVAILABLE:
            # Fallback to socket if dnspython unavailable
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, lambda: socket.getaddrinfo(domain, None)
                )
                return bool(result)
            except Exception:
                return False
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(domain, "A", lifetime=5.0)
            )
            return bool(result)
        except Exception:
            return False

    async def _check_http(self, domain: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.head(
                    f"https://{domain}",
                    follow_redirects=True,
                )
                return resp.status_code < 500
        except Exception:
            return False

    async def _check_mx(self, domain: str) -> bool:
        if not _DNS_AVAILABLE:
            return False
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(domain, "MX", lifetime=5.0)
            )
            return bool(result)
        except Exception:
            return False
