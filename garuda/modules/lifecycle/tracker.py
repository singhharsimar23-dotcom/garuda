"""
Campaign lifecycle tracker — monitors confirmed APT36 domains after detection.

Tracks ACTIVE → PARKED → DEAD → TRANSFERRED → SINKHOLED transitions to measure
operator burn cadence and GARUDA operational effectiveness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import httpx
from pydantic import BaseModel, Field, ValidationError, ConfigDict

try:
    import dns.resolver
    from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers
except ImportError:
    dns = None  # type: ignore
    NXDOMAIN = Exception  # type: ignore
    NoAnswer = Exception  # type: ignore
    NoNameservers = Exception  # type: ignore

from garuda.cache import check_and_add_set, get_cached_json, set_cached_json
from garuda.config import settings
from garuda.response.alerts import escape_md2

logger = logging.getLogger("garuda.modules.lifecycle.tracker")

IP_API_BASE = "http://ip-api.com/json"
CLUSTER_BURN_WINDOW_HOURS = 48
_LIFECYCLE_ALERT_SET = "garuda:lifecycle:alerts_sent"

PARKING_FINGERPRINTS = [
    "domain for sale",
    "this domain is parked",
    "buy this domain",
    "domain parking",
    "parked by",
    "godaddy.com/domains/park",
    "sedo.com",
    "hugedomains.com",
]

_SINKHOLE_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "sinkhole_asns.json"
SINKHOLE_ASNS: set[int] = set()


class LifecycleState(str, Enum):
    ACTIVE = "active"
    PARKED = "parked"
    DEAD = "dead"
    TRANSFERRED = "transferred"
    SINKHOLED = "sinkholed"


class IpApiResponse(BaseModel):
    """Pydantic validator for ip-api.com JSON responses (RULE 1)."""

    model_config = ConfigDict(populate_by_name=True)

    status: str
    as_field: Optional[str] = Field(default=None, alias="as")
    asname: Optional[str] = None
    message: Optional[str] = None


def load_sinkhole_asns() -> set[int]:
    """Load sinkhole ASN set from garuda/data/sinkhole_asns.json at startup."""
    global SINKHOLE_ASNS
    if SINKHOLE_ASNS:
        return SINKHOLE_ASNS
    try:
        with open(_SINKHOLE_DATA_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        SINKHOLE_ASNS = {int(a) for a in data.get("asns", [])}
    except Exception as exc:
        logger.warning("[lifecycle] Failed to load sinkhole_asns.json: %s", exc)
        SINKHOLE_ASNS = set()
    return SINKHOLE_ASNS


def parse_asn_from_ip_api(as_field: Optional[str]) -> Optional[int]:
    """Extract integer ASN from ip-api 'as' field like 'AS15169 Google LLC'."""
    if not as_field:
        return None
    match = re.match(r"AS(\d+)", as_field.strip(), re.IGNORECASE)
    return int(match.group(1)) if match else None


def _get_supabase_client():
    from garuda.database import get_supabase_client
    return get_supabase_client()


async def _resolve_a_records(domain: str) -> tuple[list[str], bool]:
    """
    DNS resolve domain A records via dnspython in thread pool.
    Returns (ips, is_nxdomain).
    """
    if dns is None:
        return [], False

    def _sync_resolve() -> tuple[list[str], bool]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5.0
            resolver.lifetime = 5.0
            answers = resolver.resolve(domain, "A")
            return [str(r) for r in answers], False
        except NXDOMAIN:
            return [], True
        except (NoAnswer, NoNameservers, Exception):
            return [], False

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_resolve)


async def _fetch_ip_asn(ip: str, client: Optional[httpx.AsyncClient] = None) -> Optional[int]:
    """Fetch ASN for IP via ip-api.com (free, no auth). Cached TTL=900."""
    cache_key = f"garuda:lifecycle:ip_api:{ip}"
    cached = await get_cached_json(cache_key)
    if cached is not None:
        try:
            parsed = IpApiResponse.model_validate(cached)
            return parse_asn_from_ip_api(parsed.as_field)
        except ValidationError:
            pass

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        close_client = True

    try:
        resp = await client.get(f"{IP_API_BASE}/{ip}", params={"fields": "status,message,as,asname"})
        resp.raise_for_status()
        data = resp.json()
        parsed = IpApiResponse.model_validate(data)
        if parsed.status != "success":
            return None
        await set_cached_json(cache_key, data, ex=900)
        return parse_asn_from_ip_api(parsed.as_field)
    except (httpx.HTTPError, ValidationError) as exc:
        logger.warning("[lifecycle] ip-api lookup failed for %s: %s", ip, exc)
        return None
    finally:
        if close_client:
            await client.aclose()


def _detect_parking(body: str) -> bool:
    lower = body.lower()
    return any(fp in lower for fp in PARKING_FINGERPRINTS)


async def check_lifecycle(
    domain: str,
    last_known_ip: Optional[str],
    last_known_asn: Optional[int],
    detected_at: Optional[datetime] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> dict[str, Any]:
    """
    Determine current lifecycle state of a confirmed IOC domain.

    Returns dict with domain, current_state, current_ip, ip_changed, asn_changed,
    current_asn, days_alive, assessed_at.
    """
    load_sinkhole_asns()
    now = datetime.now(timezone.utc)
    assessed_at = now.isoformat()

    ips, is_nxdomain = await _resolve_a_records(domain)
    if is_nxdomain or not ips:
        days_alive = 0
        if detected_at:
            days_alive = max(0, (now - detected_at).days)
        return {
            "domain": domain,
            "current_state": LifecycleState.DEAD.value,
            "current_ip": None,
            "current_asn": None,
            "ip_changed": bool(last_known_ip),
            "asn_changed": bool(last_known_asn),
            "days_alive": days_alive,
            "assessed_at": assessed_at,
        }

    current_ip = ips[0]
    ip_changed = bool(last_known_ip and current_ip != last_known_ip)

    close_client = False
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        close_client = True

    try:
        current_asn = await _fetch_ip_asn(current_ip, http_client)
    finally:
        if close_client:
            await http_client.aclose()

    asn_changed = (
        current_asn is not None
        and last_known_asn is not None
        and current_asn != last_known_asn
    )

    days_alive = 0
    if detected_at:
        days_alive = max(0, (now - detected_at).days)

    # Step 2: IP/ASN change classification
    if current_asn is not None and current_asn in SINKHOLE_ASNS:
        return {
            "domain": domain,
            "current_state": LifecycleState.SINKHOLED.value,
            "current_ip": current_ip,
            "current_asn": current_asn,
            "ip_changed": ip_changed,
            "asn_changed": asn_changed,
            "days_alive": days_alive,
            "assessed_at": assessed_at,
        }

    if ip_changed and current_asn is not None:
        if last_known_asn is not None and current_asn != last_known_asn:
            return {
                "domain": domain,
                "current_state": LifecycleState.TRANSFERRED.value,
                "current_ip": current_ip,
                "current_asn": current_asn,
                "ip_changed": True,
                "asn_changed": True,
                "days_alive": days_alive,
                "assessed_at": assessed_at,
            }

    # Step 3: HTTP parking fingerprint (only if not transferred/sinkholed)
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as http:
            resp = await http.get(f"http://{domain}/")
            if resp.status_code < 500 and _detect_parking(resp.text):
                return {
                    "domain": domain,
                    "current_state": LifecycleState.PARKED.value,
                    "current_ip": current_ip,
                    "current_asn": current_asn,
                    "ip_changed": ip_changed,
                    "asn_changed": asn_changed,
                    "days_alive": days_alive,
                    "assessed_at": assessed_at,
                }
    except Exception:
        pass

    return {
        "domain": domain,
        "current_state": LifecycleState.ACTIVE.value,
        "current_ip": current_ip,
        "current_asn": current_asn,
        "ip_changed": ip_changed,
        "asn_changed": asn_changed,
        "days_alive": days_alive,
        "assessed_at": assessed_at,
    }


async def _lifecycle_alert_already_sent(alert_key: str) -> bool:
    """Return True if this lifecycle alert was already dispatched (idempotency)."""
    return not await check_and_add_set(_LIFECYCLE_ALERT_SET, alert_key, ttl=86400 * 30)


async def _dispatch_transferred_alert(
    alert_id: str,
    domain: str,
    old_asn: Optional[int],
    new_asn: Optional[int],
) -> None:
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return

    alert_key = f"transferred:{alert_id}"
    if await _lifecycle_alert_already_sent(alert_key):
        return

    old_str = f"AS{old_asn}" if old_asn else "unknown"
    new_str = f"AS{new_asn}" if new_asn else "unknown"
    text = (
        f"🟠 DOMAIN RELOCATED — POSSIBLE ACTIVE CAMPAIGN\n"
        f"Domain: `{escape_md2(domain)}` \\(was: {escape_md2(old_str)}, now: {escape_md2(new_str)}\\)\n"
        f"Indicator: C2 infrastructure actively moved — campaign may be ongoing\n"
        f"Action: /investigate\\_relocated\\_{escape_md2(str(alert_id)[:8])} "
        f"— check new IP for C2 activity"
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
        logger.error("[lifecycle] Transferred alert failed: %s", exc)


async def _dispatch_cluster_burn_alert(
    cluster_id: str,
    count: int,
    burn_days: int,
) -> None:
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return

    alert_key = f"cluster_burn:{cluster_id}"
    if await _lifecycle_alert_already_sent(alert_key):
        return

    text = (
        f"🟡 CLUSTER BURN — OPERATORS MAY KNOW THEY'RE WATCHED\n"
        f"Cluster: `{escape_md2(cluster_id)}` — {escape_md2(count)} domains went dark simultaneously\n"
        f"Burn pattern: {escape_md2(burn_days)} days from GARUDA detection to death\n"
        f"/cluster\\_burn\\_analysis\\_{escape_md2(cluster_id[:12])}"
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
        logger.error("[lifecycle] Cluster burn alert failed: %s", exc)


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


async def _fetch_sweep_candidates() -> list[dict[str, Any]]:
    """Fetch confirmed alerts not in terminal lifecycle states."""
    client = _get_supabase_client()
    terminal = {LifecycleState.DEAD.value, LifecycleState.SINKHOLED.value}

    if client:
        try:
            res = (
                client.table("alerts")
                .select("id,domain,hosting_ip,hosting_asn,cluster_id,detected_at,lifecycle_state,status")
                .eq("status", "confirmed")
                .execute()
            )
            rows = res.data or []
            return [r for r in rows if (r.get("lifecycle_state") or "active") not in terminal]
        except Exception as exc:
            logger.error("[lifecycle] Failed to fetch alerts: %s", exc)

    from garuda.database import _IN_MEMORY_LIFECYCLE_ALERTS
    return [
        r for r in _IN_MEMORY_LIFECYCLE_ALERTS
        if r.get("status") == "confirmed"
        and (r.get("lifecycle_state") or "active") not in terminal
    ]


async def _update_alert_lifecycle(alert_id: str, result: dict[str, Any]) -> None:
    """Persist lifecycle fields on alerts row."""
    update = {
        "lifecycle_state": result["current_state"],
        "lifecycle_updated_at": result["assessed_at"],
        "lifecycle_ip": result.get("current_ip"),
        "lifecycle_asn": result.get("current_asn"),
    }
    client = _get_supabase_client()
    if client:
        try:
            client.table("alerts").update(update).eq("id", alert_id).execute()
            return
        except Exception as exc:
            logger.warning("[lifecycle] Supabase update failed, using in-memory: %s", exc)

    from garuda.database import _IN_MEMORY_LIFECYCLE_ALERTS
    for row in _IN_MEMORY_LIFECYCLE_ALERTS:
        if str(row.get("id")) == str(alert_id):
            row.update(update)
            break


async def _detect_cluster_burns(
    dead_transitions: list[dict[str, Any]],
) -> None:
    """Fire cluster burn alert when 3+ domains in same cluster die within 48h."""
    if not dead_transitions:
        return

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=CLUSTER_BURN_WINDOW_HOURS)
    by_cluster: dict[str, list[dict]] = {}

    for t in dead_transitions:
        cluster_id = t.get("cluster_id")
        if not cluster_id:
            continue
        detected = _parse_datetime(t.get("detected_at"))
        if detected and detected >= window_start:
            by_cluster.setdefault(cluster_id, []).append(t)

    for cluster_id, members in by_cluster.items():
        if len(members) < 3:
            continue
        burn_days_list = [m.get("days_alive", 0) for m in members]
        median_burn = sorted(burn_days_list)[len(burn_days_list) // 2]
        await _dispatch_cluster_burn_alert(cluster_id, len(members), median_burn)


async def run_lifecycle_sweep() -> dict[str, Any]:
    """
    Daily sweep of confirmed IOC lifecycle states.
    Returns counts: {swept, dead, parked, transferred, sinkholed, active}
    """
    if not settings.ENABLE_LIFECYCLE_TRACKER:
        logger.info("[lifecycle] ENABLE_LIFECYCLE_TRACKER=false — skipping sweep")
        return {"status": "disabled", "swept": 0}

    load_sinkhole_asns()
    candidates = await _fetch_sweep_candidates()

    counts = {
        "swept": 0,
        "dead": 0,
        "parked": 0,
        "transferred": 0,
        "sinkholed": 0,
        "active": 0,
    }
    dead_transitions: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as http_client:
        for alert in candidates:
            alert_id = str(alert.get("id", ""))
            domain = alert.get("domain", "")
            if not domain:
                continue

            prev_state = alert.get("lifecycle_state") or LifecycleState.ACTIVE.value
            last_ip = alert.get("lifecycle_ip") or alert.get("hosting_ip")
            last_asn = alert.get("lifecycle_asn") or alert.get("hosting_asn")
            detected_at = _parse_datetime(alert.get("detected_at"))

            try:
                result = await check_lifecycle(
                    domain=domain,
                    last_known_ip=last_ip,
                    last_known_asn=last_asn,
                    detected_at=detected_at,
                    http_client=http_client,
                )
            except Exception as exc:
                logger.error("[lifecycle] check_lifecycle failed for %s: %s", domain, exc)
                continue

            new_state = result["current_state"]
            counts["swept"] += 1
            if new_state in counts:
                counts[new_state] += 1

            await _update_alert_lifecycle(alert_id, result)

            # Transition alerts
            if (
                prev_state != LifecycleState.TRANSFERRED.value
                and new_state == LifecycleState.TRANSFERRED.value
            ):
                await _dispatch_transferred_alert(
                    alert_id=alert_id,
                    domain=domain,
                    old_asn=last_asn,
                    new_asn=result.get("current_asn"),
                )

            if (
                prev_state != LifecycleState.DEAD.value
                and new_state == LifecycleState.DEAD.value
            ):
                dead_transitions.append({
                    "cluster_id": alert.get("cluster_id"),
                    "detected_at": alert.get("detected_at"),
                    "days_alive": result.get("days_alive", 0),
                })

    await _detect_cluster_burns(dead_transitions)

    # Refresh effectiveness metrics cache
    try:
        from garuda.modules.lifecycle.effectiveness import compute_lead_time_metrics
        client = _get_supabase_client()
        if client:
            await compute_lead_time_metrics(client)
    except Exception as exc:
        logger.warning("[lifecycle] Effectiveness metrics refresh failed: %s", exc)

    counts["status"] = "ok"
    logger.info("[lifecycle] Sweep complete: %s", counts)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="GARUDA campaign lifecycle sweep")
    parser.add_argument("--sweep", action="store_true", help="Run daily lifecycle sweep")
    args = parser.parse_args()

    if args.sweep:
        result = asyncio.run(run_lifecycle_sweep())
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
