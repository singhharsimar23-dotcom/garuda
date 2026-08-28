"""
BGP hijack detection via RPKI validation + BGP update anomaly signals.

RPKI watchlist — only add entries with confirmed ROA registration at APNIC.
DO NOT add prefixes that are "unknown" RPKI status — they will always false-alarm.
Verify current RPKI status at: https://rpki-validator.ripe.net/ before adding
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from garuda.config import settings
from garuda.modules.bgp.ripe_stat import (
    extract_origin_asn_from_updates,
    get_announced_prefixes,
    get_bgp_updates,
    validate_rpki,
)
from garuda.modules.easm.constants import INDIAN_DEFENCE_ASNS
from garuda.response.alerts import escape_md2

logger = logging.getLogger("garuda.modules.bgp.hijack_detector")

# (prefix, expected_asn, org_label)
# VERIFY these against current APNIC RPKI records before production deploy
RPKI_WATCHLIST: list[tuple[str, int, str]] = []


def _get_supabase_client():
    from garuda.database import get_supabase_client
    return get_supabase_client()


async def _dispatch_bgp_alert(
    incident_id: str,
    prefix: str,
    org: str,
    expected_asn: int,
    observed_asn: Optional[int],
    rpki_status: str,
    severity: str,
    signal_count: int,
) -> None:
    """Send Telegram alert for BGP hijack detection."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.warning("[bgp] Telegram not configured — alert not dispatched")
        return

    if severity == "CRITICAL":
        header = "🔴 BGP HIJACK — RPKI INVALID + UNEXPECTED ASN"
        action = "Immediate action: alert NIC NOC — do not delay"
    elif severity == "HIGH":
        header = "🟠 BGP HIJACK — RPKI INVALID"
        action = "Review RPKI invalidation — possible route hijack"
    else:
        header = "🟡 BGP ANOMALY — UNEXPECTED ORIGIN ASN"
        action = "Review BGP path change — may be legitimate routing update"

    observed_str = f"AS{observed_asn}" if observed_asn else "unknown"
    text = (
        f"{escape_md2(header)}\n"
        f"Prefix: `{escape_md2(prefix)}` \\({escape_md2(org)}\\)\n"
        f"Expected: AS{escape_md2(expected_asn)}\n"
        f"Observed: {escape_md2(observed_str)}\n"
        f"RPKI: {escape_md2(rpki_status.upper())}\n"
        f"Signals: {escape_md2(signal_count)}/2\n"
        f"{escape_md2(action)}\n"
        f"/bgp\\_resolve\\_{escape_md2(incident_id[:8])}"
    )

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": settings.TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "MarkdownV2",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                logger.error("[bgp] Telegram alert failed (%s): %s", resp.status_code, resp.text)
    except Exception as exc:
        logger.error("[bgp] Telegram dispatch error: %s", exc)


async def _write_incident(
    prefix: str,
    expected_asn: int,
    observed_asn: Optional[int],
    rpki_status: str,
    signal_count: int,
) -> Optional[str]:
    """Insert incident row into bgp_incidents; returns incident id."""
    client = _get_supabase_client()
    row = {
        "prefix": prefix,
        "expected_asn": expected_asn,
        "observed_asn": observed_asn,
        "rpki_status": rpki_status,
        "signal_count": signal_count,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
    if not client:
        from garuda.database import _IN_MEMORY_BGP_INCIDENTS
        import uuid
        row["id"] = str(uuid.uuid4())
        _IN_MEMORY_BGP_INCIDENTS.append(row)
        return row["id"]

    try:
        res = client.table("bgp_incidents").insert(row).execute()
        if res.data:
            return res.data[0].get("id")
    except Exception as exc:
        logger.error("[bgp] Failed to write incident: %s", exc)
        # Fall back to in-memory when Supabase table not yet migrated
        from garuda.database import _IN_MEMORY_BGP_INCIDENTS
        import uuid
        row["id"] = str(uuid.uuid4())
        _IN_MEMORY_BGP_INCIDENTS.append(row)
        return row["id"]
    return None


async def _load_watchlist() -> list[tuple[str, int, str]]:
    """Load watchlist from Supabase bgp_watchlist, falling back to in-memory list."""
    client = _get_supabase_client()
    if client:
        try:
            res = client.table("bgp_watchlist").select("*").eq("active", True).execute()
            if res.data:
                return [
                    (r["prefix"], int(r["expected_asn"]), r.get("org_label") or "")
                    for r in res.data
                ]
        except Exception as exc:
            logger.warning("[bgp] bgp_watchlist query failed, using in-memory list: %s", exc)
    return list(RPKI_WATCHLIST)


def _evaluate_signals(
    rpki_status: str,
    expected_asn: int,
    observed_asn: Optional[int],
) -> tuple[int, str, bool]:
    """
    Evaluate hijack signals.
    Returns (signal_count, severity, should_alert).
    """
    rpki_invalid = rpki_status == "invalid"
    unexpected_asn = observed_asn is not None and observed_asn != expected_asn

    if rpki_status == "unknown":
        if unexpected_asn:
            logger.info(
                "[bgp] Advisory only — RPKI unknown for prefix with unexpected ASN "
                "(not treated as hijack per RULE: do not alert on unknown)"
            )
        return 0, "NONE", False

    signal_count = int(rpki_invalid) + int(unexpected_asn)

    if rpki_invalid and unexpected_asn:
        return 2, "CRITICAL", True
    if rpki_invalid:
        return 1, "HIGH", True
    if unexpected_asn:
        return 1, "MEDIUM", True
    return 0, "NONE", False


async def run_bgp_hijack_check() -> list[dict]:
    """
    Called by GET /api/bgp/check (Vercel Cron, every 15 min).
    For each entry in RPKI_WATCHLIST:
      1. validate_rpki(asn, prefix)
      2. get_bgp_updates(prefix, timespan=15)
      3. Compare observed announcing ASN vs expected
      4. Alert on anomaly, write to bgp_incidents table
    """
    if not settings.ENABLE_BGP_MONITOR:
        logger.info("[bgp] ENABLE_BGP_MONITOR=false — skipping hijack check")
        return []

    watchlist = await _load_watchlist()
    if not watchlist:
        logger.info("[bgp] RPKI watchlist empty — nothing to check")
        return []

    incidents: list[dict] = []

    for prefix, expected_asn, org_label in watchlist:
        try:
            rpki_status = await validate_rpki(expected_asn, prefix)
            updates = await get_bgp_updates(prefix, timespan_minutes=15)
            observed_asn = extract_origin_asn_from_updates(updates)

            signal_count, severity, should_alert = _evaluate_signals(
                rpki_status, expected_asn, observed_asn
            )

            if not should_alert:
                continue

            incident_id = await _write_incident(
                prefix=prefix,
                expected_asn=expected_asn,
                observed_asn=observed_asn,
                rpki_status=rpki_status,
                signal_count=signal_count,
            )

            incident = {
                "id": incident_id,
                "prefix": prefix,
                "expected_asn": expected_asn,
                "observed_asn": observed_asn,
                "rpki_status": rpki_status,
                "signal_count": signal_count,
                "severity": severity,
                "org_label": org_label,
            }
            incidents.append(incident)

            if incident_id:
                await _dispatch_bgp_alert(
                    incident_id=incident_id,
                    prefix=prefix,
                    org=org_label,
                    expected_asn=expected_asn,
                    observed_asn=observed_asn,
                    rpki_status=rpki_status,
                    severity=severity,
                    signal_count=signal_count,
                )

        except Exception as exc:
            logger.error("[bgp] Error checking %s: %s", prefix, exc)

    return incidents


async def seed_rpki_watchlist_from_ripe(asns: Optional[list[int]] = None) -> list[dict]:
    """
    For each ASN in INDIAN_DEFENCE_ASNS:
      get_announced_prefixes(asn) → list of live prefixes
      For each prefix: validate_rpki(asn, prefix) → filter for "valid" only
    Store valid entries in RPKI_WATCHLIST + Supabase bgp_watchlist table.
    Only entries with RPKI status "valid" go in watchlist.
    """
    target_asns = asns or [asn for asn, _, _ in INDIAN_DEFENCE_ASNS]
    org_map = {asn: label for asn, label, _ in INDIAN_DEFENCE_ASNS}
    seeded: list[dict] = []

    client = _get_supabase_client()

    for asn in target_asns:
        try:
            prefixes = await get_announced_prefixes(asn)
        except Exception as exc:
            logger.error("[bgp/seed] Failed to fetch prefixes for AS%s: %s", asn, exc)
            continue

        org_label = org_map.get(asn, f"AS{asn}")

        for prefix in prefixes:
            try:
                rpki_status = await validate_rpki(asn, prefix)
            except Exception as exc:
                logger.warning("[bgp/seed] RPKI check failed for %s AS%s: %s", prefix, asn, exc)
                continue

            if rpki_status != "valid":
                logger.debug(
                    "[bgp/seed] Skipping %s AS%s — RPKI status %s (not valid)",
                    prefix, asn, rpki_status,
                )
                continue

            entry = {"prefix": prefix, "expected_asn": asn, "org_label": org_label, "active": True}
            seeded.append(entry)

            # Update in-memory watchlist
            if (prefix, asn, org_label) not in RPKI_WATCHLIST:
                RPKI_WATCHLIST.append((prefix, asn, org_label))

            if client:
                try:
                    client.table("bgp_watchlist").upsert(
                        entry, on_conflict="prefix"
                    ).execute()
                except Exception as exc:
                    logger.error("[bgp/seed] Failed to upsert watchlist row: %s", exc)

    logger.info("[bgp/seed] Seeded %d valid RPKI watchlist entries", len(seeded))
    return seeded


def main() -> None:
    parser = argparse.ArgumentParser(description="GARUDA BGP hijack monitor")
    parser.add_argument("--seed", action="store_true", help="Seed RPKI watchlist from RIPE Stat")
    args = parser.parse_args()

    if args.seed:
        result = asyncio.run(seed_rpki_watchlist_from_ripe())
        print(f"Seeded {len(result)} watchlist entries")
    else:
        incidents = asyncio.run(run_bgp_hijack_check())
        print(f"Detected {len(incidents)} incidents")


if __name__ == "__main__":
    main()
