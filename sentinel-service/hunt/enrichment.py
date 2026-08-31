"""
Multi-source enrichment pipeline for CT hits.
All sources are free, no CC required.

Sources:
  1. DNS resolution — stdlib socket, zero cost
  2. Shodan InternetDB — https://internetdb.shodan.io/{ip}, no key, free
  3. ip-api.com — http://ip-api.com/json/{ip}?fields=..., 45 req/min, no key
  4. RIPE Stat — https://stat.ripe.net/data/prefix-overview/data.json, no key
  5. URLScan.io SEARCH (not scan) — search existing scans, no key needed for search

All enrichment tasks run in parallel with asyncio.gather().
Partial enrichment failure is acceptable — log and proceed with available signals.
Timeout per source: 10 seconds. Total enrichment budget: 30 seconds.
"""

import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Optional
import httpx

from .convergence import compute_convergence_score
from .lifecycle import DomainLifecycleTracker
from ..stix_writer import write_stix_indicator
from ..brahma_relay import notify_brahma_observe

logger = logging.getLogger(__name__)

# APT36 C2 port fingerprint from documented campaigns:
# CrimsonRAT: 4443, ObliqueRAT: 8443, ElizaRAT: 443, Mythic C2: 443+8080
# Source: MITRE G0134, CYFIRMA OSINT report (see citations in physics_likelihood.json)
APT36_C2_PORTS = {4443, 8443, 8080, 8008}
# Ports that together with APT36_C2_PORTS constitute high-confidence C2 fingerprint
C2_COMPANION_PORTS = {22, 80, 443}

# Pakistani ISP and historically documented APT36 VPS ASNs.
# Source: GCA AIDE report Aug 2025 (75 Pakistani ASNs, 116,374 incidents on Indian sensors)
# PTCL: AS17557, PakNet: AS45595, Multinet: AS24499, Cyber Internet: AS9541
# VPS providers confirmed in APT36 campaigns: Vultr AS20473, DigitalOcean AS14061
PAKISTANI_ISP_ASNS = {17557, 45595, 24499, 9541}
APT36_VPS_ASNS = {20473, 14061, 63949, 24940}  # Vultr, DigitalOcean, Linode, Hetzner
HIGH_INTEREST_ASNS = PAKISTANI_ISP_ASNS | APT36_VPS_ASNS


class EnrichmentPipeline:
    def __init__(self, supabase_client, lifecycle_tracker: "DomainLifecycleTracker"):
        self.db = supabase_client
        self.lifecycle = lifecycle_tracker

    async def process(
        self,
        domain: str,
        cert: dict,
        garuda_score: float,
        logged_at: datetime,
    ) -> None:
        """
        Runs all enrichment sources in parallel, computes convergence score,
        writes STIX indicator to Supabase, notifies BRAHMA.
        """
        ip = await self._resolve_domain(domain)

        # Parallel enrichment — partial failures acceptable
        internetdb, asn_info, ripe_stat, urlscan = await asyncio.gather(
            self._query_shodan_internetdb(ip) if ip else asyncio.sleep(0, None),
            self._query_ip_api(ip) if ip else asyncio.sleep(0, None),
            self._query_ripe_stat(ip) if ip else asyncio.sleep(0, None),
            self._search_urlscan(domain),
            return_exceptions=True,
        )

        # Replace exceptions with None — enrichment is best-effort
        internetdb = internetdb if not isinstance(internetdb, Exception) else None
        asn_info = asn_info if not isinstance(asn_info, Exception) else None
        ripe_stat = ripe_stat if not isinstance(ripe_stat, Exception) else None
        urlscan = urlscan if not isinstance(urlscan, Exception) else None

        convergence = compute_convergence_score(
            garuda_score=garuda_score,
            cert=cert,
            ip=ip,
            internetdb=internetdb,
            asn_info=asn_info,
            ripe_stat=ripe_stat,
            urlscan=urlscan,
            high_interest_asns=HIGH_INTEREST_ASNS,
            apt36_c2_ports=APT36_C2_PORTS,
        )

        logger.info(
            f"[ENRICHMENT] domain={domain} ip={ip} "
            f"garuda={garuda_score:.2f} convergence={convergence:.2f}"
        )

        # Write STIX 2.1 indicator to stix_objects table
        stix_id = await write_stix_indicator(
            self.db,
            domain=domain,
            ip=ip,
            cert=cert,
            convergence_score=convergence,
            garuda_score=garuda_score,
            logged_at=logged_at,
            enrichment={
                "internetdb": internetdb,
                "asn": asn_info,
                "ripe": ripe_stat,
                "urlscan": urlscan,
            },
        )

        # Fire catch alert — Telegram message if convergence >= 7.5
        await self._send_catch_alert(
            domain=domain,
            ip=ip,
            convergence_score=convergence,
            cert=cert,
            asn_info=asn_info,
            internetdb=internetdb,
        )

        # Register in domain lifecycle tracker
        await self.lifecycle.register(
            domain=domain,
            ip=ip,
            stix_id=stix_id,
            cert_logged_at=logged_at,
        )

        # Notify BRAHMA — feeds as real physical observation
        # Maps to initial_access tactic alpha update in Dirichlet model
        if convergence >= 7.0:
            await notify_brahma_observe(
                domain=domain,
                convergence_score=convergence,
                tactic="initial-access",
                evidence_type="ct_convergence",
            )

    async def _resolve_domain(self, domain: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.run_in_executor(
                None, socket.getaddrinfo, domain, None
            )
            if addr_info:
                return addr_info[0][4][0]
        except Exception:
            pass
        return None

    async def _query_shodan_internetdb(self, ip: str) -> Optional[dict]:
        """
        Shodan InternetDB — completely free, no API key, no CC.
        Endpoint: https://internetdb.shodan.io/{ip}
        Returns: {"ports": [...], "vulns": [...], "tags": [...], "cpes": [...]}
        Note: Dataset refreshed weekly — may be stale for new IPs.
        Fixture: sentinel-service/fixtures/shodan_internetdb_response.json
        VERIFY: Test against https://internetdb.shodan.io/8.8.8.8 before production
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"ports": [], "vulns": [], "tags": [], "cpes": []}
        return None

    async def _query_ip_api(self, ip: str) -> Optional[dict]:
        """
        ip-api.com — free, 45 req/min, no key.
        Endpoint: http://ip-api.com/json/{ip}?fields=status,as,asname,org,query
        Returns: {"as": "AS20473 The Constant Company LLC", "asname": "VULTR-AS", ...}
        NOTE: HTTP not HTTPS for the free tier.
        Fixture: sentinel-service/fixtures/ip_api_response.json
        VERIFY: ip-api.com free tier uses HTTP. HTTPS requires paid plan.
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,as,asname,org,isp,query"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
        return None

    async def _query_ripe_stat(self, ip: str) -> Optional[dict]:
        """
        RIPE Stat prefix overview — free, no auth, no rate limit documented.
        Endpoint: https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}
        Returns origin ASN, prefix, description.
        Fixture: sentinel-service/fixtures/ripe_stat_response.json
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
                headers={"User-Agent": "GARUDA-HUNT/1.0 (garuda-intel.vercel.app)"},
            )
            if resp.status_code == 200:
                return resp.json().get("data", {})
        return None

    async def _search_urlscan(self, domain: str) -> Optional[dict]:
        """
        URLScan.io SEARCH — no API key needed for searching existing scan database.
        Only searches existing scans, does NOT submit new scans (which needs key).
        Endpoint: https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1
        Returns: verdicts, IPs contacted, page title, screenshot URL.
        If domain has never been scanned: returns empty results, which is informative.
        Fixture: sentinel-service/fixtures/urlscan_search_response.json
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
                headers={"User-Agent": "GARUDA-HUNT/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    return results[0]
        return None

    async def _send_catch_alert(
        self,
        domain: str,
        ip: str,
        convergence_score: float,
        cert: dict,
        asn_info: dict,
        internetdb: dict,
    ) -> None:
        """
        Fires Telegram alert when convergence_score >= 7.5.
        This is the live catch notification.
        Threshold: 7.5 = high confidence, 1-3 per week maximum.
        9.0+ = near-certain, extremely rare.
        """
        if convergence_score < 7.5:
            return

        bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        if not bot_token or not chat_id:
            return

        issuer = cert.get("issuer_name", "unknown")
        logged_at = cert.get("logged_at", "unknown")
        asn_name = (asn_info or {}).get("asname", "unknown") if asn_info else "unknown"
        ports = (internetdb or {}).get("ports", []) if internetdb else []
        c2_ports = [p for p in ports if p in {4443, 8443, 8080, 8008}]

        tier = "🚨 CRITICAL" if convergence_score >= 9.0 else "⚠️ HIGH"

        message = (
            f"{tier} GARUDA CATCH — {convergence_score:.1f}/10\n\n"
            f"Domain: {domain}\n"
            f"IP: {ip or 'unresolved'}\n"
            f"ASN: {asn_name}\n"
            f"Cert Issuer: {issuer}\n"
            f"CT Logged: {logged_at}\n"
            f"C2 Ports Detected: {c2_ports or 'none'}\n\n"
            f"Verify now:\n"
            f"https://crt.sh/?q={domain}\n"
            f"https://urlscan.io/search/#{domain}\n"
            f"https://www.virustotal.com/gui/domain/{domain}\n\n"
            f"Dashboard: https://garuda-intel.vercel.app\n"
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n\n"
            f"Screenshot this timestamp. It is your case study."
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": message,
                    },
                )
        except Exception as exc:
            logger.error(f"Catch alert failed: {exc}")
