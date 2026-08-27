import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Set

from garuda.cache import check_and_add_set
from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.detection.engine import process_domain
from garuda.intelligence.tension_index import fetch_tension_index
from garuda.sources.circl_pdns import query_pdns
from garuda.sources.crtsh import fetch_new_certs
from garuda.sources.malwarebazaar import fetch_boss_samples
from garuda.sources.otx import fetch_apt36_iocs
from garuda.sources.urlhaus import fetch_recent_malware_urls

logger = logging.getLogger("garuda.collector")
PROCESSED_DOMAINS_SET = "garuda:processed_domains"
PROCESSED_DOMAINS_TTL = 604800  # 7 days


async def run_collection() -> Dict[str, Any]:
    """
    Orchestrate multi-source threat intelligence ingestion and scoring pipeline.

    Workflow:
        1. Fetches current geopolitical tension index and dynamically sets CONFLICT_MODE.
        2. Dispatches all 5 intelligence source collectors concurrently via asyncio.gather:
           - Certificate Transparency (crt.sh)
           - AlienVault OTX APT36 Pulses
           - URLhaus Malware URL Feed
           - Passive DNS (CIRCL PDNS)
           - MalwareBazaar APT36 & BOSS Linux Samples
        3. Aggregates all extracted domain indicators.
        4. Filters out previously evaluated domains using Redis SET 'garuda:processed_domains'.
        5. Evaluates new domains through the detection engine (scoring & alert generation).
        6. Updates Redis processed set with 7-day TTL (604,800 seconds).
        7. Records collection execution summary to Supabase.

    Returns:
        Dict with collection execution metrics:
            - total_new (int): Number of newly discovered domains.
            - scored (int): Number of domains evaluated.
            - alerted_medium (int): Number of alerts with score >= SCORE_THRESHOLD_MEDIUM.
            - alerted_critical (int): Number of alerts with score >= SCORE_THRESHOLD_CRITICAL.
            - conflict_mode (bool): Active conflict mode state during collection.
            - tension_index (float): Measured tension index value.
    """
    logger.info("[collector] Starting GARUDA intelligence collection cycle...")

    # Step 1: Fetch tension index
    tension = await fetch_tension_index()
    logger.info(f"[collector] Current tension index: {tension:.2f}")

    # Step 2: Set CONFLICT_MODE if tension exceeds threshold
    if tension > settings.TENSION_THRESHOLD:
        settings.CONFLICT_MODE = True
        logger.warning(f"[collector] Tension {tension:.2f} > {settings.TENSION_THRESHOLD}. CONFLICT_MODE ENABLED.")
    else:
        settings.CONFLICT_MODE = False

    # Step 3: Run all 5 sources concurrently
    # Query sample Tier 1 seed for CIRCL PDNS baseline
    pdns_seed = settings.TIER_1_PATTERNS[0] if settings.TIER_1_PATTERNS else "nic.in"
    if not pdns_seed.endswith(".in") and not pdns_seed.endswith(".com"):
        pdns_seed = f"{pdns_seed}.in"

    results = await asyncio.gather(
        fetch_new_certs(settings.TIER_1_PATTERNS[:20]),  # Primary batch
        fetch_apt36_iocs(),
        fetch_recent_malware_urls(),
        query_pdns(pdns_seed),
        fetch_boss_samples(),
        return_exceptions=True,
    )

    crtsh_data = results[0] if isinstance(results[0], list) else []
    otx_data = results[1] if isinstance(results[1], list) else []
    urlhaus_data = results[2] if isinstance(results[2], list) else []
    pdns_data = results[3] if isinstance(results[3], list) else []
    malware_data = results[4] if isinstance(results[4], list) else []

    logger.info(
        f"[collector] Collected: {len(crtsh_data)} certs, {len(otx_data)} OTX IOCs, "
        f"{len(urlhaus_data)} URLs, {len(pdns_data)} PDNS records, {len(malware_data)} malware samples"
    )

    # Step 4: Extract and deduplicate candidate domains
    candidate_domains: Set[str] = set()

    for item in crtsh_data:
        if isinstance(item, dict) and item.get("domain"):
            candidate_domains.add(item["domain"].lower())

    for item in otx_data:
        if isinstance(item, dict) and item.get("domain"):
            candidate_domains.add(item["domain"].lower())

    for item in urlhaus_data:
        if isinstance(item, dict) and item.get("domain"):
            candidate_domains.add(item["domain"].lower())

    for item in pdns_data:
        if isinstance(item, dict):
            if item.get("rrname"):
                candidate_domains.add(item["rrname"].lower())
            if item.get("rrtype") == "NS" and isinstance(item.get("rdata"), str):
                candidate_domains.add(item["rdata"].lower())

    # Step 5 & 6: Filter unseen domains and evaluate them
    total_new = 0
    scored = 0
    alerted_medium = 0
    alerted_critical = 0

    for domain in candidate_domains:
        domain = domain.strip().lstrip("*.")
        if not domain or "." not in domain:
            continue

        # Check Redis SET 'garuda:processed_domains' — skip if seen
        is_new = await check_and_add_set(
            PROCESSED_DOMAINS_SET,
            domain,
            ttl=PROCESSED_DOMAINS_TTL,
        )

        if not is_new:
            continue

        total_new += 1

        # Call detection engine
        eval_result = await process_domain(domain, conflict_mode=settings.CONFLICT_MODE)
        scored += 1
        domain_score = eval_result.get("score", 0)

        if domain_score >= settings.SCORE_THRESHOLD_CRITICAL:
            alerted_critical += 1
        elif domain_score >= settings.SCORE_THRESHOLD_MEDIUM:
            alerted_medium += 1

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tension_index": tension,
        "conflict_mode": settings.CONFLICT_MODE,
        "candidate_domains_discovered": len(candidate_domains),
        "total_new": total_new,
        "scored": scored,
        "alerted_medium": alerted_medium,
        "alerted_critical": alerted_critical,
    }

    # Step 7: Log summary to Supabase
    client = get_supabase_client()
    if client:
        try:
            # Record execution telemetry in audit_log
            client.table("audit_log").insert({
                "action": "collector_run_summary",
                "justification": f"Completed feed collection cycle. Discovered {total_new} new domains, alerted: {alerted_medium} medium / {alerted_critical} critical.",
            }).execute()
        except Exception as e:
            logger.warning(f"[collector] Error writing collector audit log: {e}")

    logger.info(f"[collector] Collection completed: {summary}")
    return summary


if __name__ == "__main__":
    asyncio.run(run_collection())
