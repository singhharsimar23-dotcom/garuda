"""
GARUDA CT Hunt Loop — crt.sh persistent polling inside SENTINEL.
Replaces GitHub Actions cron permanently. Runs every 900 seconds (15 min).

API: https://crt.sh/?q=%25{pattern}%25&output=json&deduplicate=Y
Rate: ~10 patterns × 4/hr = 40 req/hr. Well within crt.sh community limits.
Auth: None required.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# India-specific patterns anchored to NIC taxonomy and DRDO lab names.
# DO NOT add generic patterns — false positive rate explodes.
# Source: NIC domain registry, DRDO lab list, confirmed APT36 lure taxonomy.
INDIA_CT_PATTERNS = [
    "drdo", "nic-in", "isro-gov", "hal-india",
    "mod-india", "bel-india", "defence-india",
    "army-portal", "cert-in-gov", "ntro-india",
]

# Keyword weights for garuda_score() — India taxonomy, confirmed APT36 lure targets
# Weights derived from historical lure domain corpus analysis.
# Higher weight = higher APT36 campaign relevance.
_SCORE_KEYWORDS: list[tuple[str, float]] = [
    ("drdo", 2.5),          # Defence Research & Development Organisation
    ("nic-in", 2.5),        # National Informatics Centre
    ("isro", 2.0),          # Indian Space Research Organisation
    ("hal-india", 2.0),     # Hindustan Aeronautics Limited
    ("defence", 1.5),       ("defense", 1.5),
    ("mod-india", 2.0),     # Ministry of Defence
    ("army", 1.5),          ("navy", 1.5), ("airforce", 1.5),
    ("bel-india", 1.8),     # Bharat Electronics Limited
    ("cert-in", 2.0),       ("certin", 2.0),
    ("ntro", 2.0),           # National Technical Research Organisation
    ("gov-in", 1.5),        ("gov.in", 1.5),
    ("mil", 1.2),
    ("sparsh", 1.5),        # SPARSH defence portal
    ("raksha", 1.5),        # Raksha Mantralaya (MoD)
]

# Suspicious TLDs — strong signal of phishing/lookalike infrastructure
_SUSPICIOUS_TLDS: set[str] = {
    ".space", ".online", ".site", ".xyz", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".top", ".pw", ".club", ".live", ".icu", ".vip",
    ".ws", ".cc", ".cv", ".info", ".biz",
}

# Minimum score threshold to enter the enrichment pipeline.
# Below this: log and discard. 6.0 chosen from operational tuning.
SCORE_THRESHOLD = 6.0

# Consider certs logged within this window as "new".
# 24h window catches overnight registrations on first morning poll.
FRESHNESS_HOURS = 24


def garuda_score(cert: dict) -> float:
    """
    Score a crt.sh certificate entry against India APT36 lure taxonomy.

    This is the single source of truth for CT domain scoring inside SENTINEL.
    The GitHub Actions certstream_monitor.py uses domain_matches() for its own
    binary pass/fail filter — this function provides a continuous [0.0, 10.0]
    score for enrichment pipeline gating.

    Returns float in [0.0, 10.0].
    """
    domain = (cert.get("common_name") or cert.get("name_value") or "").lower()
    if not domain:
        return 0.0

    score = 0.0

    # Keyword score: sum matching keyword weights
    for keyword, weight in _SCORE_KEYWORDS:
        if keyword in domain:
            score += weight

    # Suspicious TLD bonus: APT36 lure domains almost always use cheap/disposable TLDs
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 2.5
            break

    # Issuer: Let's Encrypt = automated cert on throwaway domain = +1.0
    issuer = (cert.get("issuer_name") or "").lower()
    if "let's encrypt" in issuer or "letsencrypt" in issuer or "r3" in issuer:
        score += 1.0

    # Wildcard suppression: handled at caller level (wildcards skipped before scoring)

    return min(10.0, score)


class CTHuntCollector:
    def __init__(self, garuda_scorer, enrichment_pipeline, supabase_client):
        """
        garuda_scorer: callable(cert: dict) -> float. Use the module-level
                       garuda_score() function defined above. DO NOT reimplement.
        enrichment_pipeline: EnrichmentPipeline instance from hunt/enrichment.py
        supabase_client: existing supabase client from sentinel-service
        """
        self.score = garuda_scorer
        self.enrich = enrichment_pipeline
        self.db = supabase_client
        self._seen_cert_ids: set[int] = set()  # In-memory dedup across polls
        self._seen_max_size = 50_000  # ~5MB RAM max

    async def hunt_loop(self) -> None:
        """Main 15-minute CT polling loop. Called from sentinel-service/sentinel_main.py."""
        logger.info("CT Hunt Loop started — polling crt.sh every 900s")
        while True:
            try:
                await self._poll_all_patterns()
            except asyncio.CancelledError:
                logger.info("CT Hunt Loop cancelled — shutting down")
                break
            except Exception as exc:
                logger.error(f"CT hunt cycle failed: {exc}", exc_info=True)
                # Never crash the loop. Log and wait.
            await asyncio.sleep(900)

    async def _poll_all_patterns(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=FRESHNESS_HOURS)
        async with httpx.AsyncClient(timeout=30.0) as client:
            for pattern in INDIA_CT_PATTERNS:
                try:
                    await self._poll_pattern(client, pattern, cutoff)
                    await asyncio.sleep(2)  # Polite inter-query delay
                except httpx.TimeoutException:
                    logger.warning(f"crt.sh timeout for pattern={pattern}, skipping")
                except Exception as exc:
                    logger.error(f"Pattern poll failed pattern={pattern}: {exc}")

    async def _poll_pattern(
        self, client: httpx.AsyncClient, pattern: str, cutoff: datetime
    ) -> None:
        url = f"https://crt.sh/?q=%25{pattern}%25&output=json&deduplicate=Y"
        resp = await client.get(url)
        if resp.status_code != 200:
            logger.warning(f"crt.sh returned {resp.status_code} for {pattern}")
            return

        certs = resp.json()
        if not isinstance(certs, list):
            return

        for cert in certs:
            cert_id = cert.get("id")
            if cert_id and cert_id in self._seen_cert_ids:
                continue

            # Parse logged_at — when it appeared in CT log, not cert notBefore.
            logged_at_str = cert.get("logged_at", "")
            if not logged_at_str:
                continue
            try:
                logged_at = datetime.fromisoformat(
                    logged_at_str.replace("Z", "+00:00")
                )
            except ValueError:
                continue

            if logged_at < cutoff:
                continue

            # Score via India taxonomy scorer.
            # garuda_score() returns float in [0.0, 10.0]
            domain = cert.get("common_name", "") or cert.get("name_value", "")
            if not domain or "*" in domain:
                continue

            score = self.score(cert)
            if score < SCORE_THRESHOLD:
                if cert_id:
                    self._dedup_add(cert_id)
                continue

            logger.info(
                f"[CT-HIT] domain={domain} score={score:.2f} logged_at={logged_at_str}"
            )

            # Fire enrichment pipeline asynchronously — do not block hunt loop.
            asyncio.create_task(
                self.enrich.process(
                    domain=domain,
                    cert=cert,
                    garuda_score=score,
                    logged_at=logged_at,
                )
            )
            if cert_id:
                self._dedup_add(cert_id)

    def _dedup_add(self, cert_id: int) -> None:
        if len(self._seen_cert_ids) >= self._seen_max_size:
            # Evict oldest 10% when full
            to_remove = list(self._seen_cert_ids)[:5_000]
            for x in to_remove:
                self._seen_cert_ids.discard(x)
        self._seen_cert_ids.add(cert_id)
