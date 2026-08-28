"""
GARUDA — Operator Cluster Similarity Scoring & Human-in-the-Loop Attribution

Provides deterministic, mathematically transparent similarity scoring between campaign
infrastructure fingerprints to support state-backed operator clustering.

CRITICAL METHODOLOGICAL DIRECTIVE:
---------------------------------
1. NO LLM PROMPTS for clustering decisions. Nondeterministic clustering cannot be
   defended to MEA, CERT-In, or military command.
2. Weighted deterministic scoring over concrete infrastructure observables:
   - Registrar account pattern & registrar: 0.25
   - Nameserver sequence overlap (Jaccard): 0.20
   - Hosting ASN alignment:                0.20
   - Target sector & lure theme alignment: 0.15
   - CVE exploitation overlap (Jaccard):   0.10
   - Certificate issuance timing proximity: 0.10
   Total weight = 1.00.
3. Two-step attribution workflow: candidate matches above threshold (default: 0.70)
   are staged into cluster_review_queue. An analyst must explicitly approve before
   a fingerprint is assigned a cluster_id.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from garuda.database import (
    get_campaign_fingerprints,
    get_operator_clusters,
    insert_cluster_review_item,
    update_cluster_review_decision,
)

logger = logging.getLogger("garuda.intelligence.cluster_similarity")


def _jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculate Jaccard similarity index between two string sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return float(intersection) / float(union) if union > 0 else 0.0


def _parse_iso_ts(val: Any) -> Optional[datetime]:
    """Parse ISO timestamp or datetime to UTC datetime."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def compute_fingerprint_similarity(
    fp1: Dict[str, Any],
    fp2: Dict[str, Any],
) -> Tuple[float, Dict[str, Any]]:
    """
    Compute deterministic weighted similarity score (0.0 to 1.0) between two
    campaign infrastructure fingerprints.

    Returns:
        Tuple[float, Dict[str, Any]]: (composite_score, signal_breakdown)
    """
    score = 0.0
    signals: Dict[str, Any] = {}

    # 1. Registrar & Account Pattern (Weight: 0.25)
    reg_score = 0.0
    p1 = (fp1.get("registrar_account_pattern") or "").strip().lower()
    p2 = (fp2.get("registrar_account_pattern") or "").strip().lower()
    r1 = (fp1.get("registrar") or "").strip().lower()
    r2 = (fp2.get("registrar") or "").strip().lower()

    if p1 and p2 and p1 == p2:
        reg_score = 0.25
        signals["registrar_pattern_match"] = "exact_pattern"
    elif r1 and r2 and r1 == r2:
        reg_score = 0.12
        signals["registrar_match"] = "same_registrar"
    else:
        signals["registrar_match"] = "none"
    score += reg_score

    # 2. Nameserver Sequence Overlap (Weight: 0.20)
    ns1 = set(str(n).strip().lower() for n in (fp1.get("nameserver_sequence") or []) if n)
    ns2 = set(str(n).strip().lower() for n in (fp2.get("nameserver_sequence") or []) if n)
    ns_jaccard = _jaccard_similarity(ns1, ns2)
    ns_score = round(ns_jaccard * 0.20, 4)
    score += ns_score
    signals["nameserver_jaccard"] = round(ns_jaccard, 3)

    # 3. Hosting ASN Alignment (Weight: 0.20)
    asn1 = str(fp1.get("hosting_asn") or "").strip().upper()
    asn2 = str(fp2.get("hosting_asn") or "").strip().upper()
    if asn1 and asn2 and asn1 == asn2:
        score += 0.20
        signals["hosting_asn_match"] = asn1
    else:
        signals["hosting_asn_match"] = None

    # 4. Target Sector & Lure Theme Alignment (Weight: 0.15)
    sec1 = (fp1.get("target_sector") or "").strip().lower()
    sec2 = (fp2.get("target_sector") or "").strip().lower()
    lure1 = (fp1.get("lure_theme") or "").strip().lower()
    lure2 = (fp2.get("lure_theme") or "").strip().lower()

    target_score = 0.0
    if sec1 and sec2 and sec1 == sec2:
        target_score += 0.10
        signals["target_sector_match"] = sec1
    if lure1 and lure2 and (lure1 in lure2 or lure2 in lure1):
        target_score += 0.05
        signals["lure_theme_match"] = lure1
    score += target_score

    # 5. CVE Exploitation Overlap (Weight: 0.10)
    cves1 = set(str(c).strip().upper() for c in (fp1.get("cves_used") or []) if c)
    cves2 = set(str(c).strip().upper() for c in (fp2.get("cves_used") or []) if c)
    cve_jaccard = _jaccard_similarity(cves1, cves2)
    cve_score = round(cve_jaccard * 0.10, 4)
    score += cve_score
    signals["cve_jaccard"] = round(cve_jaccard, 3)

    # 6. Certificate Timing Proximity (Weight: 0.10)
    dt1 = _parse_iso_ts(fp1.get("cert_issued_at"))
    dt2 = _parse_iso_ts(fp2.get("cert_issued_at"))
    timing_score = 0.0
    if dt1 and dt2:
        diff_days = abs((dt1 - dt2).total_seconds()) / 86400.0
        if diff_days <= 7.0:
            timing_score = 0.10
            signals["cert_timing_delta_days"] = round(diff_days, 1)
        elif diff_days <= 30.0:
            timing_score = 0.05
            signals["cert_timing_delta_days"] = round(diff_days, 1)
        else:
            signals["cert_timing_delta_days"] = round(diff_days, 1)
    else:
        signals["cert_timing_delta_days"] = None
    score += timing_score

    final_score = min(1.0, max(0.0, round(score, 4)))
    signals["composite_similarity"] = final_score

    return final_score, signals


async def propose_cluster_attribution(
    fingerprint_id: str,
    min_threshold: float = 0.70,
) -> List[Dict[str, Any]]:
    """
    Evaluate an unclustered fingerprint against all known clustered campaign infrastructure.
    If similarity >= min_threshold, inserts candidates into cluster_review_queue.
    DOES NOT automatically assign cluster_id (analyst approval required).
    """
    all_fps = await get_campaign_fingerprints()
    target_fp = next((f for f in all_fps if str(f.get("id")) == str(fingerprint_id)), None)
    if not target_fp:
        logger.warning(f"[cluster_similarity] Target fingerprint {fingerprint_id} not found")
        return []

    clusters = await get_operator_clusters()
    if not clusters:
        logger.info("[cluster_similarity] No operator clusters exist yet — nothing to compare against")
        return []

    # Map cluster_id -> list of fingerprints in that cluster
    cluster_fps_map: Dict[str, List[Dict[str, Any]]] = {}
    for fp in all_fps:
        cid = fp.get("cluster_id")
        if cid:
            cluster_fps_map.setdefault(str(cid), []).append(fp)

    review_candidates: List[Dict[str, Any]] = []

    for cluster in clusters:
        cid = str(cluster["id"])
        known_fps = cluster_fps_map.get(cid, [])
        if not known_fps:
            continue

        best_score = 0.0
        best_signals: Dict[str, Any] = {}

        for known_fp in known_fps:
            if str(known_fp.get("id")) == str(fingerprint_id):
                continue
            sim_score, sim_signals = compute_fingerprint_similarity(target_fp, known_fp)
            if sim_score > best_score:
                best_score = sim_score
                best_signals = {
                    "matched_fingerprint_domain": known_fp.get("domain"),
                    "cluster_label": cluster.get("label"),
                    **sim_signals,
                }

        if best_score >= min_threshold:
            # Stage into review queue
            review_item = await insert_cluster_review_item(
                fingerprint_id=fingerprint_id,
                suggested_cluster_id=cid,
                similarity_score=best_score,
                matched_signals=best_signals,
            )
            review_candidates.append(review_item)
            logger.info(
                f"[cluster_similarity] Staged review candidate: {target_fp.get('domain')} -> "
                f"{cluster.get('label')} (score: {best_score})"
            )

    return review_candidates
