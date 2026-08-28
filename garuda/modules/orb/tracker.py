"""
ORB network sweep — weekly candidate IP analysis via Shodan InternetDB + RIPE Stat.

Runs via GitHub Actions (not Vercel — too slow).
DO NOT add FOFA — permanently removed.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from pydantic import BaseModel, Field, ValidationError

from garuda.config import settings
from garuda.modules.bgp.ripe_stat import extract_origin_asn_from_updates, get_bgp_updates
from garuda.modules.orb.signals import (
    ANCHOR_CHINESE_ASNS,
    confidence_label_from_score,
    get_defence_prefixes_cached,
    score_orb_probability,
)
from garuda.response.alerts import escape_md2
from garuda.sources.cisa_kev import get_cached_kev

logger = logging.getLogger("garuda.modules.orb.tracker")

INTERNETDB_BASE = "https://internetdb.shodan.io"
ORB_SCORE_THRESHOLD = 60
ORB_CRITICAL_THRESHOLD = 80


class InternetDbResponse(BaseModel):
    """Pydantic validator for Shodan InternetDB responses."""
    ip: Optional[str] = None
    ports: list[int] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    detail: Optional[str] = None
    product: Optional[str] = None


def _get_supabase_client():
    from garuda.database import get_supabase_client
    return get_supabase_client()


def _kev_cve_set() -> set[str]:
    return {(e.get("cve_id") or "").upper() for e in get_cached_kev() if e.get("cve_id")}


async def _fetch_internetdb(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Fetch Shodan InternetDB (free, no credits)."""
    try:
        resp = await client.get(f"{INTERNETDB_BASE}/{ip}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        if data.get("detail") == "No information available":
            return None
        parsed = InternetDbResponse.model_validate(data)
        return parsed.model_dump()
    except ValidationError as exc:
        logger.warning("[orb] InternetDB validation failed for %s: %s", ip, exc)
        return None
    except httpx.HTTPError as exc:
        logger.warning("[orb] InternetDB HTTP error for %s: %s", ip, exc)
        return None


async def _fetch_shodan_host(ip: str, api_key: str, client: httpx.AsyncClient) -> dict:
    """Fetch Shodan host detail (0 query credits for direct IP lookup)."""
    try:
        resp = await client.get(
            f"{settings.SHODAN_API_URL}/shodan/host/{ip}",
            params={"key": api_key},
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("[orb] Shodan host lookup failed for %s: %s", ip, exc)
        return {}


async def _check_otx_ioc(ip: str, client: httpx.AsyncClient) -> bool:
    """Check if IP appears in OTX indicator feed."""
    if not settings.OTX_API_KEY:
        return False
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return False
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return pulse_count > 0
    except Exception:
        return False


async def _upsert_orb_node(node: dict[str, Any]) -> Optional[str]:
    """Upsert flagged ORB node to orb_nodes table."""
    client = _get_supabase_client()
    if client:
        try:
            res = client.table("orb_nodes").upsert(node, on_conflict="ip").execute()
            if res.data:
                return res.data[0].get("id")
        except Exception as exc:
            logger.error("[orb] Failed to upsert orb_nodes: %s", exc)

    from garuda.database import _IN_MEMORY_ORB_NODES
    import uuid
    existing = next((i for i, n in enumerate(_IN_MEMORY_ORB_NODES) if n.get("ip") == node.get("ip")), None)
    if existing is not None:
        node["id"] = _IN_MEMORY_ORB_NODES[existing].get("id", str(uuid.uuid4()))
        _IN_MEMORY_ORB_NODES[existing] = dict(node)
    else:
        node["id"] = str(uuid.uuid4())
        _IN_MEMORY_ORB_NODES.append(dict(node))
    return node.get("id")


async def _dispatch_orb_alert(node_id: str, node: dict[str, Any]) -> None:
    """Dispatch CRITICAL Telegram alert for high-probability ORB targeting defence."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return

    anchor_found = node.get("anchor_asns_found") or []
    anchor_str = ", ".join(f"AS{a}" for a in anchor_found) if anchor_found else "none"
    signals_str = ", ".join(node.get("triggered_signals") or [])

    text = (
        f"🔴 HIGH\\-PROBABILITY ORB NODE — INDIAN DEFENCE TARGETING\n"
        f"IP: `{escape_md2(node.get('ip'))}` \\| ASN: {escape_md2(node.get('asn', 'unknown'))} "
        f"\\| Country: {escape_md2(node.get('country', 'unknown'))}\n"
        f"Device: {escape_md2(node.get('product', 'unknown'))} {escape_md2(node.get('firmware_version', ''))}\n"
        f"ORB Score: {escape_md2(node.get('orb_score'))}/130\n"
        f"Signals: {escape_md2(signals_str)}\n"
        f"BGP Path includes Chinese ASNs: {escape_md2(anchor_str)}\n"
        f"Assessment: {escape_md2(node.get('confidence_label', 'CONFIRMED_ORB'))}\n"
        f"Note: Attribution to specific APT requires additional SIGINT "
        f"— not available from external observation alone\\.\n"
        f"/orb\\_detail\\_{escape_md2(str(node_id)[:8])}"
    )

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json={
                "chat_id": settings.TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "MarkdownV2",
            })
    except Exception as exc:
        logger.error("[orb] Telegram alert failed: %s", exc)


async def get_candidate_ips_for_orb_sweep() -> list[str]:
    """
    Build candidate IP list for ORB sweep without wasting Shodan credits.
    Source 1: EASM findings — IPs with open services
    Source 2: monitored_defence_ips
    Source 3: passive_dns_observations with APT C2 overlap
    """
    candidates: set[str] = set()
    client = _get_supabase_client()

    if client:
        try:
            easm = client.table("easm_findings").select("ip").eq("status", "open").limit(2000).execute()
            for row in easm.data or []:
                if row.get("ip"):
                    candidates.add(str(row["ip"]))
        except Exception as exc:
            logger.warning("[orb] easm_findings query failed: %s", exc)

        try:
            defence = client.table("monitored_defence_ips").select("ip").limit(500).execute()
            for row in defence.data or []:
                if row.get("ip"):
                    candidates.add(str(row["ip"]))
        except Exception as exc:
            logger.warning("[orb] monitored_defence_ips query failed: %s", exc)

        try:
            pdns = (
                client.table("passive_dns_observations")
                .select("query_ip")
                .not_.is_("query_ip", "null")
                .limit(500)
                .execute()
            )
            for row in pdns.data or []:
                if row.get("query_ip"):
                    candidates.add(str(row["query_ip"]))
        except Exception as exc:
            logger.warning("[orb] passive_dns_observations query failed: %s", exc)

    return list(candidates)[:2000]


async def run_orb_sweep(
    shodan_api_key: Optional[str] = None,
    candidate_ips: Optional[list[str]] = None,
) -> list[dict]:
    """
    Weekly ORB sweep. Score candidate IPs and flag probable ORB nodes.
    """
    if not settings.ENABLE_ORB_TRACKER:
        logger.info("[orb] ENABLE_ORB_TRACKER=false — skipping sweep")
        return []

    api_key = shodan_api_key or settings.SHODAN_API_KEY
    ips = candidate_ips if candidate_ips is not None else await get_candidate_ips_for_orb_sweep()

    if not ips:
        logger.info("[orb] No candidate IPs for sweep")
        return []

    kev_cves = _kev_cve_set()
    defence_prefixes = await get_defence_prefixes_cached()
    flagged: list[dict] = []

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as http_client:
        for ip in ips:
            internetdb = await _fetch_internetdb(ip, http_client)
            if not internetdb:
                continue

            # Step 2: enrich with Shodan host if SOHO-like or suspect ports
            from garuda.modules.orb.signals import SOHO_KEYWORDS, ORB_SUSPECT_PORTS, _product_matches_soho
            ports = set(internetdb.get("ports") or [])
            needs_detail = _product_matches_soho(internetdb) or bool(ports & ORB_SUSPECT_PORTS)

            product = internetdb.get("product") or ""
            firmware = ""
            asn = None
            country = ""

            if needs_detail and api_key:
                host_data = await _fetch_shodan_host(ip, api_key, http_client)
                if host_data:
                    asn = host_data.get("asn")
                    country = host_data.get("country_name") or host_data.get("country_code")
                    for svc in host_data.get("data") or []:
                        product = product or svc.get("product") or ""
                        firmware = firmware or svc.get("version") or ""
                        if svc.get("product"):
                            internetdb["product"] = svc["product"]

            # Step 3: BGP path
            try:
                updates = await get_bgp_updates(ip, timespan_minutes=1440)
                bgp_path_asns = []
                for u in updates:
                    path = (u.get("attrs") or {}).get("path") or []
                    bgp_path_asns.extend(path)
                bgp_path_asns = list(dict.fromkeys(bgp_path_asns))
            except Exception:
                bgp_path_asns = []

            # Step 4: OTX check
            is_otx = await _check_otx_ioc(ip, http_client)

            score, triggered, targeting = score_orb_probability(
                ip=ip,
                internetdb_data=internetdb,
                bgp_path_asns=bgp_path_asns,
                is_in_otx_iocs=is_otx,
                kev_cves=kev_cves,
                defence_prefixes=defence_prefixes,
            )

            if score < ORB_SCORE_THRESHOLD:
                continue

            anchor_found = [a for a in bgp_path_asns if a in ANCHOR_CHINESE_ASNS]
            label = confidence_label_from_score(score)

            node = {
                "ip": ip,
                "asn": int(str(asn).replace("AS", "")) if asn and str(asn).replace("AS", "").isdigit() else None,
                "country": country,
                "product": product,
                "firmware_version": firmware,
                "open_ports": list(internetdb.get("ports") or []),
                "known_cves": list(internetdb.get("vulns") or []),
                "orb_score": score,
                "triggered_signals": triggered,
                "targeting_indian_defence": targeting,
                "confidence_label": label,
                "anchor_asns_found": anchor_found,
                "last_confirmed": datetime.now(timezone.utc).isoformat(),
            }

            node_id = await _upsert_orb_node(node)
            flagged.append(node)

            if score >= ORB_CRITICAL_THRESHOLD and targeting and node_id:
                await _dispatch_orb_alert(node_id, node)

    logger.info("[orb] Sweep complete — %d nodes flagged (threshold >= %d)", len(flagged), ORB_SCORE_THRESHOLD)
    return flagged


def main() -> None:
    parser = argparse.ArgumentParser(description="GARUDA ORB network sweep")
    parser.add_argument("--sweep", action="store_true", help="Run weekly ORB sweep")
    args = parser.parse_args()

    if args.sweep:
        result = asyncio.run(run_orb_sweep())
        print(f"Flagged {len(result)} ORB nodes")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
