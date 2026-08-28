from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set
import httpx

from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.detection.infra_fingerprint import check_hosting_asn
from garuda.response.alerts import dispatch_alert

logger = logging.getLogger("garuda.intelligence.honeypot")

HONEYPOT_DOMAINS = [
    "army-hq-portal.space",
    "modindia-sso.online",
    "nicwebmail-secure.site",
    "drdo-vpn.online",
]

APT36_KNOWN_IPS: Set[str] = set()
APT36_KNOWN_ASNS: Set[int] = {16276, 24940, 63949, 14061, 20473}


async def init_known_actor_ips() -> None:
    """Load known APT36 / Transparent Tribe C2 and scanning IPs from database alerts on startup."""
    global APT36_KNOWN_IPS
    client = get_supabase_client()
    if client:
        try:
            res = (
                client.table("alerts")
                .select("hosting_ip")
                .gte("score", 70)
                .not_.is_("hosting_ip", "null")
                .limit(200)
                .execute()
            )
            data = res.data or []
            for item in data:
                ip = item.get("hosting_ip")
                if ip and "." in ip:
                    APT36_KNOWN_IPS.add(ip.strip())
            logger.info(f"[honeypot] Loaded {len(APT36_KNOWN_IPS)} known actor IPs from threat database.")
        except Exception as e:
            logger.warning(f"[honeypot] Error initializing known actor IPs: {e}")


async def fetch_cloudflare_dns_logs(zone_id: str, cf_token: str) -> List[Dict[str, Any]]:
    """
    Fetch DNS telemetry logs from Cloudflare DNS Analytics API.

    Queries GET https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_analytics/report.

    Args:
        zone_id: Target Cloudflare DNS Zone ID.
        cf_token: Cloudflare API Bearer token.

    Returns:
        List[dict]: Parsed DNS log queries containing source_ip, timestamp, domain_queried, query_type.
    """
    if not zone_id or not cf_token:
        return []

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_analytics/report"
    headers = {"Authorization": f"Bearer {cf_token}"}

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            # TODO: verify Cloudflare DNS analytics report dimensions
            rows = data.get("result", {}).get("data", [])
            entries: List[Dict[str, Any]] = []
            for row in rows:
                entries.append({
                    "source_ip": row.get("clientIP", ""),
                    "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "domain_queried": row.get("queryName", ""),
                    "query_type": row.get("queryType", "A"),
                })
            return entries
    except httpx.HTTPError as err:
        logger.error(f"[honeypot] HTTP error querying Cloudflare DNS analytics: {err}")
        return []
    except Exception as e:
        logger.error(f"[honeypot] Error parsing Cloudflare DNS report: {e}")
        return []


async def process_honeypot_logs(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Inspect incoming DNS and HTTP query logs to honeypot decoy domains for APT36 recon activity.

    Matches query source IPs against known actor IP telemetry (APT36_KNOWN_IPS) and ASN profiles
    (APT36_KNOWN_ASNS). Triggers immediate CRITICAL alerts (Score: 100) on positive hits.

    Args:
        log_entries: List of log records [{source_ip, timestamp, domain_queried, query_type}].

    Returns:
        List[Dict[str, Any]]: List of generated critical honeypot breach alerts.
    """
    if not APT36_KNOWN_IPS:
        await init_known_actor_ips()

    triggered_alerts: List[Dict[str, Any]] = []
    client = get_supabase_client()

    for entry in log_entries:
        source_ip = str(entry.get("source_ip", "")).strip()
        domain_queried = str(entry.get("domain_queried", "")).strip().lower()
        timestamp = entry.get("timestamp") or datetime.now(timezone.utc).isoformat()
        query_type = entry.get("query_type", "A")

        if not source_ip or source_ip in {"127.0.0.1", "0.0.0.0"}:
            continue

        # Check IP list match
        ip_matched = source_ip in APT36_KNOWN_IPS

        # Check ASN match
        is_asn_match, asn_number = await check_hosting_asn(source_ip)
        asn_matched = is_asn_match or (asn_number in APT36_KNOWN_ASNS)

        if ip_matched or asn_matched or any(h in domain_queried for h in HONEYPOT_DOMAINS):
            alert_payload = {
                "domain": domain_queried if domain_queried else f"honeypot-hit-{source_ip}",
                "score": 100,
                "sector": "Decoy Honeypot Reconnaissance",
                "status": "pending",
                "detected_at": timestamp,
                "hosting_ip": source_ip,
                "hosting_asn": asn_number,
                "signals": {
                    "honeypot_breach": True,
                    "query_type": query_type,
                    "ip_matched": ip_matched,
                    "asn_matched": asn_matched,
                    "target_honeypot_domain": domain_queried,
                    "source_ip": source_ip,
                },
                "source": "honeypot",
            }

            # Persist to Supabase
            if client:
                try:
                    client.table("alerts").insert({
                        "domain": alert_payload["domain"],
                        "score": 100,
                        "signals": alert_payload["signals"],
                        "detected_at": timestamp,
                        "hosting_ip": source_ip,
                        "hosting_asn": asn_number,
                        "sector": alert_payload["sector"],
                        "status": "pending",
                    }).execute()
                except Exception as e:
                    logger.error(f"[honeypot] Error persisting honeypot alert: {e}")

            # Dispatch immediate emergency notification
            await dispatch_alert(alert_payload)
            triggered_alerts.append(alert_payload)

    return triggered_alerts


def generate_canary_alert_copy(
    token_id: str,
    source_ip: str,
    timestamp: str,
) -> str:
    """
    Generate calibrated alert copy for canary token triggers.

    CRITICAL ATTRIBUTION POLICY:
    Canary token access data confirms TIMING ('campaign is in active preparation').
    It NEVER justifies a geographic location claim (e.g. 'operator in City X')
    because proxy, VPN, and commercial VPS egress make single-hit IP geolocation
    wholly unreliable.
    """
    clean_date = timestamp.split("T")[0] if "T" in str(timestamp) else str(timestamp)
    return (
        f"Canary token '{token_id}' accessed on {clean_date} from IP {source_ip}. "
        "Access timestamp indicates adversary campaign is in active preparation. "
        "Note: Egress infrastructure (VPN/VPS) prevents geographic location attribution from token access alone."
    )


async def handle_canary_token_trigger(
    token_id: str,
    source_ip: str,
    user_agent: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Process an activated canary token decoy.
    Dispatches timing alert without geographic overclaiming.
    """
    obs_time = timestamp or datetime.now(timezone.utc).isoformat()
    alert_text = generate_canary_alert_copy(
        token_id=token_id,
        source_ip=source_ip,
        timestamp=obs_time,
    )

    alert_payload = {
        "domain": f"canary-token-{token_id}",
        "score": 95,
        "sector": "Deception / Active Preparation Warning",
        "status": "pending",
        "detected_at": obs_time,
        "hosting_ip": source_ip,
        "signals": {
            "canary_token_triggered": True,
            "token_id": token_id,
            "timing_signal": "active_campaign_preparation",
            "geographic_attribution": "unverified_egress_infrastructure",
            "user_agent": user_agent,
            "source_ip": source_ip,
            "alert_copy": alert_text,
        },
        "source": "canary_token",
    }

    client = get_supabase_client()
    if client:
        try:
            client.table("alerts").insert({
                "domain": alert_payload["domain"],
                "score": 95,
                "signals": alert_payload["signals"],
                "detected_at": obs_time,
                "hosting_ip": source_ip,
                "sector": alert_payload["sector"],
                "status": "pending",
            }).execute()
        except Exception as e:
            logger.error(f"[honeypot] Error persisting canary token alert: {e}")

    await dispatch_alert(alert_payload)
    return alert_payload
