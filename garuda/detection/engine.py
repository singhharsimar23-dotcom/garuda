import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
try:
    import dns.resolver
except ImportError:
    dns = None
try:
    import whois
except ImportError:
    whois = None

from garuda.cache import get_cached_json, set_cached_json
from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.detection.homoglyph import detect_homoglyph, normalize_domain
from garuda.detection.infra_fingerprint import (
    check_hosting_asn,
    check_registrar_fingerprint,
)
from garuda.detection.nic_ground_truth import compute_similarity
from garuda.detection.patterns import extract_keyword_match, extract_sector
from garuda.detection.scoring import assemble_score
from garuda.enrichment import enrich_threat_indicators
from garuda.intelligence.tension_index import fetch_tension_index
from garuda.response.alerts import dispatch_alert

logger = logging.getLogger("garuda.detection.engine")

VALID_TLD_SUFFIXES = {
    "in", "com", "net", "org", "space", "online", "site", "xyz", "cv",
    "tk", "ml", "ga", "cf", "info", "pw", "gov.in", "nic.in", "co.in",
    "biz", "top", "club", "live", "app", "tech", "store", "io", "cc"
}


def _is_valid_domain(domain: str) -> bool:
    """Validate domain syntax and recognized TLD structure before DNS lookup."""
    if not domain or "." not in domain or len(domain) > 253:
        return False
    parts = domain.split(".")
    if any(len(p) == 0 for p in parts):
        return False
    tld = parts[-1].lower()
    return tld.isalpha() and 2 <= len(tld) <= 24


def _is_whitelisted(domain: str) -> bool:
    """Check if domain is explicitly whitelisted in the Supabase database."""
    client = get_supabase_client()
    if not client:
        return False
    try:
        res = client.table("whitelist").select("id").eq("domain", domain).execute()
        return bool(res.data)
    except Exception as e:
        logger.error(f"[engine] Error querying whitelist for '{domain}': {e}")
        return False


async def _resolve_ip(domain: str) -> Optional[str]:
    """Resolve A record using dnspython within an async thread pool."""
    if not _is_valid_domain(domain):
        return None

    def _sync_dns_query(target: str) -> Optional[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(target, "A")
            for rdata in answers:
                return str(rdata)
        except Exception:
            return None
        return None

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_dns_query, domain)


async def _fetch_whois_data(domain: str) -> Dict[str, Any]:
    """Fetch WHOIS record in an async executor and cache in Redis with TTL=86400s."""
    cache_key = f"garuda:whois:{domain}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, dict):
        return cached

    if whois is None:
        return {}

    def _sync_whois(target: str) -> Dict[str, Any]:
        try:
            w = whois.whois(target)
            if not w:
                return {}

            creation_date = w.creation_date
            if isinstance(creation_date, list) and len(creation_date) > 0:
                creation_date = creation_date[0]

            creation_iso = creation_date.isoformat() if isinstance(creation_date, datetime) else None

            return {
                "registrar": w.registrar,
                "registrar_url": getattr(w, "registrar_url", None),
                "creation_date": creation_iso,
                "country": getattr(w, "country", None),
            }
        except Exception:
            return {}

    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, _sync_whois, domain)
    if data:
        await set_cached_json(cache_key, data, ex=86400)
    return data


def _calculate_domain_age(creation_date_str: Optional[str]) -> Optional[int]:
    """Calculate age of domain in days from creation timestamp."""
    if not creation_date_str:
        return None
    try:
        created = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - created).days)
    except Exception:
        return None


async def process_domain(
    domain: str,
    source: str = "manual",
    conflict_mode: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    """
    Process, evaluate, score, and alert on a candidate domain through the full detection pipeline.

    Workflow:
        1. Check whitelist in database — returns None if whitelisted.
        2. Fast triage filter via keyword/TLD match — returns None if score == 0.
        3. Homoglyph detection & NIC ground truth fuzzy similarity scoring.
        4. Async WHOIS lookup in executor & domain age computation.
        5. DNS A record resolution to obtain hosting IP.
        6. Registrar & ASN infrastructure fingerprinting.
        7. Initial multi-vector score assembly.
        8. If initial score >= 40: trigger enrichment (Shodan C2 ports, OTX, AbuseIPDB) and rescore.
        9. Persist alert to Supabase 'alerts' table.
        10. If score >= 70: dispatch notifications via configured webhooks.
        11. Return final structured alert dictionary.

    Args:
        domain: Target candidate domain string (e.g. 'modgov-secure.space').
        source: Intelligence source origin (e.g. 'crtsh', 'otx', 'urlhaus').
        conflict_mode: Optional boolean flag for conflict mode elevation.

    Returns:
        Optional[Dict[str, Any]]: Alert payload dict or None if filtered/whitelisted.
    """
    domain = domain.strip().lower().lstrip("*.")
    if not domain or "." not in domain:
        return None

    # Step 1: Whitelist Check
    if _is_whitelisted(domain):
        logger.debug(f"[engine] Domain '{domain}' is whitelisted. Skipping.")
        return None

    # Step 2: Fast Heuristic Filter (90% of noise dropped here)
    kw_tier, kw_score = extract_keyword_match(domain)
    if kw_score == 0 and not domain.endswith(tuple(settings.APT36_SUSPICIOUS_TLDS)):
        # Check if domain has any homoglyphs or NIC similarity before dropping
        has_hg, _ = detect_homoglyph(domain)
        if not has_hg:
            return None

    sector = extract_sector(domain)

    # Step 3: Homoglyph Detection & NIC Ground Truth Similarity
    has_homoglyphs, detected_chars = detect_homoglyph(domain)
    nic_similarity, best_nic_match = compute_similarity(domain)

    # Step 4: WHOIS Query in Async Executor
    whois_data = await _fetch_whois_data(domain)
    domain_age_days = _calculate_domain_age(whois_data.get("creation_date"))
    registrar = whois_data.get("registrar")

    # Step 5: DNS Resolution
    hosting_ip = await _resolve_ip(domain)

    # Step 6: Infrastructure Fingerprinting
    reg_matched, reg_score = await check_registrar_fingerprint(domain, whois_data)
    is_apt36_asn, hosting_asn = await check_hosting_asn(hosting_ip) if hosting_ip else (False, 0)

    # Fetch Geopolitical Tension
    tension = await fetch_tension_index()

    # Step 7: Initial Score Assembly
    signals: Dict[str, Any] = {
        "keyword_tier": kw_tier,
        "keyword_score": kw_score,
        "nic_similarity": nic_similarity,
        "nic_match": best_nic_match,
        "homoglyph": has_homoglyphs,
        "homoglyph_chars": detected_chars,
        "registrar": registrar,
        "registrar_match": reg_matched,
        "registrar_score": reg_score,
        "domain_age_days": domain_age_days,
        "hosting_ip": hosting_ip,
        "hosting_asn": hosting_asn,
        "asn_match": is_apt36_asn,
        "c2_ports": [],
        "otx_attributed": False,
        "abuseipdb_reports": 0,
        "tension_index": tension,
        "source": source,
    }

    score, breakdown = assemble_score(signals)

    # Step 8: Enrichment Layer (if score >= SCORE_THRESHOLD_LOG)
    if score >= settings.SCORE_THRESHOLD_LOG:
        enrichment = await enrich_threat_indicators(domain, hosting_ip)
        signals.update(enrichment)
        # Re-assemble score with enriched signals
        score, breakdown = assemble_score(signals)

    detected_at = datetime.now(timezone.utc).isoformat()
    status_str = "pending" if score >= settings.SCORE_THRESHOLD_MEDIUM else "logged"

    alert_dict: Dict[str, Any] = {
        "domain": domain,
        "score": score,
        "signals": signals,
        "breakdown": breakdown,
        "registered_at": whois_data.get("creation_date"),
        "detected_at": detected_at,
        "registrar": registrar,
        "hosting_ip": hosting_ip,
        "hosting_asn": hosting_asn,
        "sector": sector,
        "status": status_str,
        "source": source,
    }

    # Step 9: Write Alert to Supabase
    client = get_supabase_client()
    if client is not None and score >= settings.SCORE_THRESHOLD_LOG:
        try:
            # TODO: verify Supabase insertion columns mapping
            client.table("alerts").insert({
                "domain": domain,
                "score": score,
                "signals": signals,
                "registered_at": whois_data.get("creation_date"),
                "detected_at": detected_at,
                "registrar": registrar,
                "hosting_ip": hosting_ip,
                "hosting_asn": hosting_asn,
                "sector": sector,
                "status": status_str,
            }).execute()
        except Exception as e:
            logger.error(f"[engine] Error persisting alert for '{domain}' to Supabase: {e}")

    # Step 10: Dispatch Alert Notification if score >= SCORE_THRESHOLD_MEDIUM
    if score >= settings.SCORE_THRESHOLD_MEDIUM:
        await dispatch_alert(alert_dict)

    # Step 11: Return Alert Dictionary
    return alert_dict
