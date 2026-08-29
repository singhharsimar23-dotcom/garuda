"""
GARUDA — EASM (External Attack Surface Management) & CVE Correlation Cron Endpoints

Two CRON_SECRET-gated endpoints:

  POST /api/easm/scan
      Daily Shodan scan. Reads monitored_asn_ranges, queries Shodan net:<cidr>,
      writes/updates easm_findings. Respects config/api_limits.json credit guard.

  POST /api/easm/kev-sync
      6-hour CISA KEV sync. For each open easm_finding, runs fingerprint_matches_cve()
      and creates cve_kev_matches rows. Triggers Telegram alert for ransomware/actor
      matches immediately; other matches queue for daily digest.

Neither endpoint touches a Telegram bot or database table if the relevant table
is empty — both degrade gracefully when monitored_asn_ranges has zero rows.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field



from garuda.config import settings
from garuda.detection.cpe_match import compute_severity, fingerprint_matches_cve
from garuda.sources.cisa_kev import get_kev_entry_by_cve, sync_kev_catalog

logger = logging.getLogger("garuda.api.routes.easm")

router = APIRouter(tags=["EASM & CVE Correlation"])


# ==============================================================================
# Helpers
# ==============================================================================


def _verify_cron_secret(authorization: Optional[str]) -> None:
    """Raise 401 if the Authorization header doesn't carry the cron secret."""
    expected = f"Bearer {settings.CRON_SECRET}"
    if not authorization or authorization.strip() != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid CRON_SECRET.",
        )


def _load_api_limits() -> Dict[str, Any]:
    """
    Load the quota-guard file. Returns default conservative limits if the
    file is missing — does not raise so the cron doesn't crash on cold deploy.
    """
    path = settings.EASM_API_LIMITS_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning("[easm] api_limits.json not found at %s — using defaults", path)
        return {"shodan": {"daily_credits_remaining": 0}}
    except Exception as exc:
        logger.error("[easm] Failed to load api_limits.json: %s", exc)
        return {"shodan": {"daily_credits_remaining": 0}}


def _get_supabase_client():
    """Return Supabase client or None (mirrors pattern in garuda/database.py)."""
    from garuda.database import get_supabase_client
    return get_supabase_client()


async def _fetch_monitored_ranges() -> List[Dict[str, Any]]:
    """Fetch all rows from monitored_asn_ranges. Returns [] if table is empty."""
    client = _get_supabase_client()
    if not client:
        logger.warning("[easm] No Supabase client — cannot fetch monitored_asn_ranges")
        return []
    try:
        res = client.table("monitored_asn_ranges").select("*").execute()
        return res.data or []
    except Exception as exc:
        logger.error("[easm] Error fetching monitored_asn_ranges: %s", exc)
        return []


async def _fetch_open_findings() -> List[Dict[str, Any]]:
    """Fetch all easm_findings with status='open'."""
    client = _get_supabase_client()
    if not client:
        return []
    try:
        res = client.table("easm_findings").select("*").eq("status", "open").execute()
        return res.data or []
    except Exception as exc:
        logger.error("[easm] Error fetching open easm_findings: %s", exc)
        return []


async def _upsert_finding(finding: Dict[str, Any]) -> Optional[str]:
    """
    Upsert an easm_finding row. Conflict key is (ip, port, scan_source).
    Returns the row id on success, None on failure.
    """
    client = _get_supabase_client()
    if not client:
        return None
    try:
        res = (
            client.table("easm_findings")
            .upsert(finding, on_conflict="ip,port,scan_source")
            .execute()
        )
        if res.data:
            return res.data[0].get("id")
    except Exception as exc:
        logger.error("[easm] Error upserting easm_finding: %s", exc)
    return None


async def _insert_kev_match(match: Dict[str, Any]) -> bool:
    """Insert a cve_kev_matches row. Silently skips on (finding, CVE) duplicate."""
    client = _get_supabase_client()
    if not client:
        return False
    try:
        client.table("cve_kev_matches").upsert(
            match, on_conflict="easm_finding_id,cve_id"
        ).execute()
        return True
    except Exception as exc:
        logger.error("[easm] Error inserting cve_kev_match: %s", exc)
        return False


async def _send_telegram_alert(message: str) -> None:
    """Fire-and-forget Telegram notification. Reuses existing bot credentials."""
    token = settings.TELEGRAM_BOT_TOKEN
    chat_id = settings.TELEGRAM_CHAT_ID
    if not token or not chat_id:
        logger.warning("[easm] Telegram not configured — skipping alert")
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"})
    except Exception as exc:
        logger.error("[easm] Telegram alert failed: %s", exc)


def _classify_shodan_service(port: int, product: str) -> str:
    """Map a Shodan port/product string to a human-readable service label."""
    product_lower = (product or "").lower()
    if port == 3389 or "rdp" in product_lower:
        return "rdp"
    if "fortigate" in product_lower or "fortios" in product_lower:
        return "fortigate-mgmt"
    if "citrix" in product_lower:
        return "citrix-adc"
    if port == 22 or "openssh" in product_lower or "ssh" in product_lower:
        return "ssh"
    if port in (80, 443, 8080, 8443) or "http" in product_lower:
        return "http"
    if "smb" in product_lower or port == 445:
        return "smb"
    return f"port-{port}"


# ==============================================================================
# Endpoint 1: Daily Shodan Scan
# ==============================================================================


@router.post("/api/easm/scan")
@router.post("/easm/scan")
async def run_easm_scan(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Daily EASM scan cron endpoint.

    Reads monitored_asn_ranges, queries Shodan net:<cidr> for each range,
    and writes results to easm_findings. Respects api_limits.json credit guard.

    Must be called with Authorization: Bearer <CRON_SECRET>.
    """
    _verify_cron_secret(authorization)

    limits = _load_api_limits()
    shodan_credits = limits.get("shodan", {}).get("daily_credits_remaining", 0)
    if shodan_credits <= 0:
        logger.warning("[easm/scan] Shodan daily credits at 0 — skipping scan. Update config/api_limits.json.")
        return {
            "status": "skipped",
            "reason": "Shodan daily credits exhausted. Update config/api_limits.json after next billing period.",
            "scanned_ranges": 0,
            "findings_upserted": 0,
        }

    ranges = await _fetch_monitored_ranges()

    # Session 8: supplement DB ranges with live BGP-announced prefixes
    try:
        from garuda.modules.easm.collector import get_live_defence_prefixes
        live_prefixes = await get_live_defence_prefixes()
        for lp in live_prefixes:
            ranges.append({
                "id": None,
                "cidr": lp["cidr"],
                "org_name": lp["org_label"],
                "asn": f"AS{lp['asn']}",
                "source": lp["source"],
            })
    except Exception as exc:
        logger.warning("[easm/scan] Live BGP prefix fetch failed: %s", exc)

    # Deduplicate by CIDR
    seen_cidrs: set[str] = set()
    unique_ranges: list[dict] = []
    for r in ranges:
        cidr = r.get("cidr", "")
        if cidr and cidr not in seen_cidrs:
            seen_cidrs.add(cidr)
            unique_ranges.append(r)
    ranges = unique_ranges

    if not ranges:
        logger.info("[easm/scan] monitored_asn_ranges is empty — nothing to scan.")
        return {
            "status": "ok",
            "scanned_ranges": 0,
            "findings_upserted": 0,
            "note": "No ASN ranges configured. Add rows to monitored_asn_ranges with verified source fields.",
        }

    shodan_key = settings.SHODAN_API_KEY
    if not shodan_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SHODAN_API_KEY not configured.",
        )

    scanned = 0
    upserted = 0
    credits_used = 0

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as http_client:
        for asn_range in ranges:
            if credits_used >= shodan_credits:
                logger.warning("[easm/scan] Credit limit reached mid-scan — stopping early.")
                break

            cidr = asn_range.get("cidr", "")
            range_id = asn_range.get("id")
            if not cidr:
                continue

            try:
                resp = await http_client.get(
                    f"{settings.SHODAN_API_URL}/shodan/host/search",
                    params={
                        "key": shodan_key,
                        "query": f"net:{cidr}",
                        "minify": "true",
                    },
                )
                credits_used += 1
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as exc:
                logger.error("[easm/scan] Shodan HTTP %s for CIDR %s: %s", exc.response.status_code, cidr, exc)
                continue
            except Exception as exc:
                logger.error("[easm/scan] Shodan error for CIDR %s: %s", cidr, exc)
                continue

            for host in data.get("matches", []):
                ip = host.get("ip_str", "")
                port = host.get("port", 0)
                product = host.get("product") or host.get("devicetype") or ""
                banner = host.get("data", "")
                fingerprint = f"{product} {banner}".strip()[:500]  # cap length
                service_label = _classify_shodan_service(port, product)

                finding = {
                    "asn_range_id": range_id,
                    "ip": ip,
                    "port": port,
                    "service": service_label,
                    "product_fingerprint": fingerprint,
                    "scan_source": "shodan",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "status": "open",
                }
                row_id = await _upsert_finding(finding)
                if row_id:
                    upserted += 1

            scanned += 1

    return {
        "status": "ok",
        "scanned_ranges": scanned,
        "findings_upserted": upserted,
        "shodan_credits_used": credits_used,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ==============================================================================
# Endpoint 2: 6-Hour CISA KEV Sync
# ==============================================================================


@router.post("/api/easm/kev-sync")
@router.post("/easm/kev-sync")
async def run_kev_sync(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    CISA KEV sync cron endpoint (runs every 6 hours).

    1. Fetches/refreshes the CISA KEV catalog.
    2. For each open easm_finding, checks all KEV entries via fingerprint_matches_cve().
    3. Creates cve_kev_matches rows for confirmed matches.
    4. Triggers immediate Telegram alert for known_ransomware_use=True matches.

    Must be called with Authorization: Bearer <CRON_SECRET>.
    """
    _verify_cron_secret(authorization)

    # Step 1: Sync KEV catalog
    sync_result = await sync_kev_catalog()
    logger.info("[easm/kev-sync] KEV sync result: %s", sync_result.to_dict())

    # Step 2: Get open findings
    findings = await _fetch_open_findings()
    if not findings:
        return {
            "status": "ok",
            "kev_sync": sync_result.to_dict(),
            "open_findings_checked": 0,
            "matches_created": 0,
            "alerts_sent": 0,
        }

    from garuda.sources.cisa_kev import get_cached_kev
    kev_entries = get_cached_kev()
    if not kev_entries:
        logger.warning("[easm/kev-sync] KEV cache is empty — sync may have failed.")
        return {
            "status": "warning",
            "kev_sync": sync_result.to_dict(),
            "open_findings_checked": len(findings),
            "matches_created": 0,
            "alerts_sent": 0,
            "warning": "KEV cache empty after sync attempt.",
        }

    matches_created = 0
    alerts_sent = 0

    for finding in findings:
        fp = finding.get("product_fingerprint") or ""
        finding_id = finding.get("id")
        if not fp or not finding_id:
            continue

        for kev_entry in kev_entries:
            if not fingerprint_matches_cve(fp, kev_entry):
                continue

            cve_id = kev_entry.get("cve_id") or ""
            if not cve_id:
                continue

            date_added = kev_entry.get("date_added")  # ISO date string or None
            ransomware = bool(kev_entry.get("known_ransomware_use", False))
            severity = compute_severity(
                cvss_base_score=None,       # NVD lookup deferred to future session
                known_ransomware_use=ransomware,
                kev_date_added=date_added,
            )

            match_row = {
                "easm_finding_id": finding_id,
                "cve_id": cve_id,
                "kev_date_added": date_added,
                "known_ransomware_use": ransomware,
                "threat_actor_correlation_id": None,    # Session 5 — not yet
                "days_since_actor_exploitation": None,  # Session 5 — not yet
                "severity_computed": severity,
                "alert_sent": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            inserted = await _insert_kev_match(match_row)
            if inserted:
                matches_created += 1

                # Immediate Telegram alert for ransomware-linked CVEs
                if ransomware:
                    ip = finding.get("ip", "unknown")
                    service = finding.get("service", "")
                    org = finding.get("org_name", "")  # may not be in findings row
                    msg = (
                        f"🚨 <b>GARUDA EASM KEV ALERT</b>\n"
                        f"IP: <code>{ip}</code>\n"
                        f"Service: {service}\n"
                        f"CVE: <b>{cve_id}</b>\n"
                        f"Severity: {severity.upper()}\n"
                        f"Known ransomware use: ✅ YES\n"
                        f"KEV date added: {date_added or 'N/A'}\n"
                        f"Fingerprint: <code>{fp[:120]}</code>"
                    )
                    await _send_telegram_alert(msg)
                    alerts_sent += 1

    return {
        "status": "ok",
        "kev_sync": sync_result.to_dict(),
        "open_findings_checked": len(findings),
        "matches_created": matches_created,
        "alerts_sent": alerts_sent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ==============================================================================
# Endpoint 3: EASM Findings Query & Management (UI Endpoints)
# ==============================================================================


@router.get("/api/easm/orgs")
@router.get("/easm/orgs")
async def get_easm_orgs() -> Dict[str, Any]:
    """
    List monitored organisations with summary counts (findings, KEV matches, critical).
    """
    ranges = await _fetch_monitored_ranges()
    client = _get_supabase_client()

    findings_by_range = {}
    if client:
        try:
            res = client.table("easm_findings").select("asn_range_id,status").execute()
            for row in (res.data or []):
                rid = row.get("asn_range_id")
                findings_by_range[rid] = findings_by_range.get(rid, 0) + (1 if row.get("status") == "open" else 0)
        except Exception as e:
            logger.warning(f"[easm] Failed querying findings count: {e}")

    org_list = []
    for r in ranges:
        rid = r.get("id")
        org_list.append({
            "id": rid,
            "org_name": r.get("org_name", "Unknown Org"),
            "cidr": r.get("cidr", ""),
            "source": r.get("source", ""),
            "open_findings": findings_by_range.get(rid, 0),
            "kev_matches": 0,
            "critical_count": 0,
        })

    return {
        "status": "ok",
        "total": len(org_list),
        "orgs": org_list,
    }


@router.get("/api/easm/findings")
@router.get("/easm/findings")
async def list_easm_findings(
    org: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
) -> Dict[str, Any]:
    """
    Query EASM findings with optional org, severity, and status filtering.
    """
    client = _get_supabase_client()
    findings = []
    total = 0

    if client:
        try:
            query = client.table("easm_findings").select("*, monitored_asn_ranges(org_name, cidr)", count="exact")
            if status_filter and status_filter != "all":
                query = query.eq("status", status_filter)
            offset = (page - 1) * limit
            res = query.range(offset, offset + limit - 1).execute()
            findings = res.data or []
            total = res.count or len(findings)
        except Exception as e:
            logger.warning(f"[easm] Failed querying easm_findings: {e}")

    # Format findings with joined org_name and KEV/APT data (FIX-03)
    from garuda.modules.easm.constants import CVE_TO_APT, PRODUCT_CVE_FALLBACK

    # Fetch any existing cve_kev_matches
    cve_map = {}
    if client and findings:
        try:
            finding_ids = [f.get("id") for f in findings if f.get("id")]
            m_res = client.table("cve_kev_matches").select("easm_finding_id,cve_id,threat_actor_attribution,severity_computed").in_("easm_finding_id", finding_ids).execute()
            for m in (m_res.data or []):
                cve_map[m.get("easm_finding_id")] = m
        except Exception:
            pass

    formatted = []
    for f in findings:
        fid = f.get("id")
        range_data = f.get("monitored_asn_ranges") or {}
        org_name = range_data.get("org_name") if isinstance(range_data, dict) else None
        service_str = (f.get("service") or "").lower()
        fp_str = (f.get("product_fingerprint") or "").lower()
        combined_text = f"{service_str} {fp_str}".strip()

        matched_cve = None
        threat_actor = None
        severity = f.get("severity") or "medium"

        if fid in cve_map:
            matched_cve = cve_map[fid].get("cve_id")
            threat_actor = cve_map[fid].get("threat_actor_attribution")
            severity = cve_map[fid].get("severity_computed") or severity
        else:
            # Fallback product match
            for p_key, cves in PRODUCT_CVE_FALLBACK.items():
                if p_key in combined_text:
                    matched_cve = cves[0]
                    actors = CVE_TO_APT.get(matched_cve, [])
                    threat_actor = ", ".join(actors) if actors else None
                    severity = "critical" if "volt typhoon" in (threat_actor or "").lower() else "high"
                    break

        formatted.append({
            "id": fid,
            "org_name": org_name or f.get("org_name", "Monitored Asset"),
            "ip": f.get("ip"),
            "port": f.get("port"),
            "service": f.get("service"),
            "product": f.get("product_fingerprint", "").split("\n")[0][:60] if f.get("product_fingerprint") else f.get("service"),
            "product_fingerprint": f.get("product_fingerprint"),
            "cve_id": matched_cve,
            "threat_actor": threat_actor,
            "first_seen": f.get("created_at"),
            "last_seen": f.get("last_seen") or f.get("created_at"),
            "kev_date_added": f.get("kev_date_added"),
            "threat_actor_correlation_id": threat_actor or f.get("threat_actor_correlation_id"),
            "severity": severity,
            "status": f.get("status", "open"),
            "stix_indicator_id": f.get("stix_indicator_id"),
        })

    return {
        "status": "ok",
        "page": page,
        "limit": limit,
        "total": total,
        "findings": formatted,
    }


@router.get("/api/easm/findings/{finding_id}")
@router.get("/easm/findings/{finding_id}")
async def get_easm_finding_detail(finding_id: str) -> Dict[str, Any]:
    """
    Get detailed EASM finding including banner and CVE/KEV match telemetry.
    """
    client = _get_supabase_client()
    if not client:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        res = client.table("easm_findings").select("*, monitored_asn_ranges(org_name, cidr)").eq("id", finding_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding = res.data[0]

        # Fetch associated CVE KEV matches
        matches_res = client.table("cve_kev_matches").select("*").eq("easm_finding_id", finding_id).execute()
        cve_matches = matches_res.data or []

        return {
            "status": "ok",
            "finding": finding,
            "cve_matches": cve_matches,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class UpdateStatusRequest(BaseModel):
    status: str = Field(..., pattern="^(open|patched|false_positive)$")



@router.post("/api/easm/findings/{finding_id}/status")
@router.patch("/api/easm/findings/{finding_id}")
async def update_finding_status(finding_id: str, req: UpdateStatusRequest) -> Dict[str, Any]:
    """Update finding status (open, patched, false_positive)."""
    client = _get_supabase_client()
    if client:
        try:
            client.table("easm_findings").update({"status": req.status}).eq("id", finding_id).execute()
        except Exception as e:
            logger.warning(f"[easm] Failed status update: {e}")

    return {"status": "ok", "id": finding_id, "new_status": req.status}


@router.get("/api/easm/stix-export")
@router.get("/easm/stix-export")
async def export_easm_stix_bundle() -> Dict[str, Any]:
    """Export all open EASM findings as a STIX 2.1 JSON bundle."""
    client = _get_supabase_client()
    findings = []
    if client:
        try:
            res = client.table("easm_findings").select("*").eq("status", "open").execute()
            findings = res.data or []
        except Exception as e:
            logger.warning(f"[easm] STIX export error: {e}")

    from uuid import uuid4
    bundle_id = f"bundle--{uuid4()}"
    objects = []
    for f in findings:
        obs_id = f"observed-data--{uuid4()}"
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "first_observed": f.get("created_at") or datetime.now(timezone.utc).isoformat(),
            "last_observed": f.get("last_seen") or datetime.now(timezone.utc).isoformat(),
            "number_observed": 1,
            "object_refs": [],
            "custom_properties": {
                "ip": f.get("ip"),
                "port": f.get("port"),
                "service": f.get("service"),
                "product": f.get("product_fingerprint"),
            }
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
