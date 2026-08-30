"""
Test suite for Session O — GARUDA-HUNT: Active Intelligence Collection Engine

All tests must pass before committing to main.

Run with:
    cd garuda
    python -m pytest tests/test_hunt_and_vibeware.py -v
"""

import asyncio
import importlib.util
import os
import sys
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# Add sentinel-service to path for hunt module imports
_SENTINEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel-service")
if _SENTINEL_PATH not in sys.path:
    sys.path.insert(0, _SENTINEL_PATH)

# Add brahma-service to FRONT of path so brahma-service/kali takes priority over root kali/
_BRAHMA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "brahma-service")
if _BRAHMA_PATH not in sys.path:
    sys.path.insert(0, _BRAHMA_PATH)

from hunt.convergence import compute_convergence_score
from hunt.ct_collector import CTHuntCollector, garuda_score
from hunt.lifecycle import DomainLifecycleTracker

# KALI MCTS — import from brahma-service (now at front of sys.path)
# Force re-import if root kali was already cached
if "kali" in sys.modules:
    del sys.modules["kali"]
if "kali.mcts_engine" in sys.modules:
    del sys.modules["kali.mcts_engine"]
if "kali.attack_graph" in sys.modules:
    del sys.modules["kali.attack_graph"]
if "kali.detection_model" in sys.modules:
    del sys.modules["kali.detection_model"]

from kali.mcts_engine import KaliMCTSEngine, TECHNIQUE_PHYSICS


# ─── ACCEPTANCE TEST 1: KALI regression — trajectories produce DIFFERENT values ─────────
def test_kali_terminal_value_not_degenerate():
    """
    This test MUST pass before Session O is considered complete.
    The previous degenerate behavior (all 0.0942) is a disqualifying flaw.

    T1547.001 (Registry Run Keys) vs T1053.005 (Scheduled Task):
    - T1547.001: p_detection=0.22 (low RAPL delta, low cache pressure from registry writes)
    - T1053.005: p_detection=0.38 (schtasks.exe spawn creates moderate RAPL spike)
    These must produce different adversary utility AND detection probability.
    """
    engine = KaliMCTSEngine()
    utility_a, p_detect_a = engine._evaluate_trajectory(
        ["T1566.001", "T1547.001", "T1003.001"]
    )
    utility_b, p_detect_b = engine._evaluate_trajectory(
        ["T1566.001", "T1053.005", "T1003.001"]
    )
    assert utility_a != utility_b, (
        f"KALI terminal value function is still degenerate: "
        f"T1547.001 path ({utility_a}) and T1053.005 path ({utility_b}) returned same utility"
    )
    assert p_detect_a != p_detect_b, (
        f"P(Detection) identical for different trajectories: {p_detect_a}"
    )
    # Sanity check direction: T1547.001 has lower p_detection, so path A utility should be higher
    assert utility_a > utility_b, (
        f"T1547.001 (Registry Run, p_det=0.22) should have higher utility than "
        f"T1053.005 (Scheduled Task, p_det=0.38). Got {utility_a} vs {utility_b}"
    )


def test_kali_evaluate_trajectory_returns_different_for_different_techniques():
    """Additional regression: technique-level physics must not collapse to tactic-level mean."""
    engine = KaliMCTSEngine()
    # T1102 (vibeware web service, p_det=0.18) vs T1071.001 (web protocols C2, p_det=0.52)
    # Both are command-and-control — but very different detection probabilities.
    util_vibeware, p_vibeware = engine._evaluate_trajectory(["T1566.001", "T1102"])
    util_traditional, p_traditional = engine._evaluate_trajectory(["T1566.001", "T1071.001"])
    assert util_vibeware != util_traditional, (
        "Vibeware C2 (T1102) must score differently from traditional C2 (T1071.001)"
    )


def test_kali_evaluate_trajectory_empty():
    """Empty trajectory returns (0.0, 0.0)."""
    engine = KaliMCTSEngine()
    util, p = engine._evaluate_trajectory([])
    assert util == 0.0
    assert p == 0.0


def test_kali_technique_physics_completeness():
    """All techniques in the test trajectories must be in TECHNIQUE_PHYSICS."""
    required = ["T1566.001", "T1547.001", "T1053.005", "T1003.001", "T1102"]
    missing = [t for t in required if t not in TECHNIQUE_PHYSICS]
    assert not missing, f"Missing techniques in TECHNIQUE_PHYSICS: {missing}"


# ─── ACCEPTANCE TEST 2: Convergence score differentiates ASNs ───────────────
def test_convergence_pakistani_asn_scores_higher_than_unknown():
    """Pakistani ISP ASN (45595 PakNet) must score higher than unknown ISP on same domain."""
    score_paknet = compute_convergence_score(
        garuda_score=7.0,
        cert={"issuer_name": "Let's Encrypt"},
        ip="1.2.3.4",
        internetdb={"ports": [443, 4443], "vulns": [], "tags": [], "cpes": []},
        asn_info={"status": "success", "as": "AS45595 PakNet LLC"},
        ripe_stat=None,
        urlscan=None,
        high_interest_asns={17557, 45595, 24499, 9541, 20473, 14061, 63949, 24940},
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    score_unknown = compute_convergence_score(
        garuda_score=7.0,
        cert={"issuer_name": "Let's Encrypt"},
        ip="5.6.7.8",
        internetdb={"ports": [443], "vulns": [], "tags": [], "cpes": []},
        asn_info={"status": "success", "as": "AS12345 SomeISP"},
        ripe_stat=None,
        urlscan=None,
        high_interest_asns={17557, 45595, 24499, 9541, 20473, 14061, 63949, 24940},
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    assert score_paknet > score_unknown, (
        f"Pakistani ASN (AS45595) should score higher: {score_paknet} vs {score_unknown}"
    )


# ─── ACCEPTANCE TEST 3: APT36 C2 port fingerprint detected ──────────────────
def test_convergence_c2_ports_increase_score():
    """Ports 4443+8443 (APT36 C2) must score higher than ports 443+80 (clean VPS)."""
    score_c2 = compute_convergence_score(
        garuda_score=6.5, cert={}, ip="1.2.3.4",
        internetdb={"ports": [443, 4443, 8443], "vulns": [], "tags": [], "cpes": []},
        asn_info=None, ripe_stat=None, urlscan=None,
        high_interest_asns=set(),
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    score_clean = compute_convergence_score(
        garuda_score=6.5, cert={}, ip="1.2.3.4",
        internetdb={"ports": [443, 80], "vulns": [], "tags": [], "cpes": []},
        asn_info=None, ripe_stat=None, urlscan=None,
        high_interest_asns=set(),
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    assert score_c2 > score_clean, (
        f"C2 port fingerprint should increase score: {score_c2} vs {score_clean}"
    )


def test_convergence_urlscan_malicious_boosts_score():
    """Malicious URLScan verdict must push convergence score up."""
    score_malicious = compute_convergence_score(
        garuda_score=7.0, cert={}, ip="1.2.3.4",
        internetdb=None, asn_info=None, ripe_stat=None,
        urlscan={"verdicts": {"overall": {"malicious": True, "hasVerdicts": True, "score": 90}}},
        high_interest_asns=set(),
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    score_clean = compute_convergence_score(
        garuda_score=7.0, cert={}, ip="1.2.3.4",
        internetdb=None, asn_info=None, ripe_stat=None, urlscan=None,
        high_interest_asns=set(),
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    assert score_malicious > score_clean


# ─── ACCEPTANCE TEST 4: garuda_score() non-zero for India-lure domains ─────
def test_garuda_score_india_lure_domain():
    """DRDO domain on suspicious TLD must score above threshold."""
    cert = {
        "common_name": "drdo-portal.space",
        "issuer_name": "Let's Encrypt",
    }
    score = garuda_score(cert)
    assert score >= 6.0, f"Expected score >= 6.0 for DRDO lure domain, got {score}"


def test_garuda_score_wildcard_domain():
    """Wildcard domains are filtered before scoring — garuda_score still returns a value."""
    cert = {"common_name": "*.drdo-portal.space", "issuer_name": "ZeroSSL"}
    # garuda_score doesn't filter wildcards — caller does. But should still score.
    score = garuda_score(cert)
    assert isinstance(score, float)
    assert 0.0 <= score <= 10.0


def test_garuda_score_legitimate_domain():
    """Legitimate Google domain should score near zero."""
    cert = {"common_name": "google.com", "issuer_name": "GlobalSign"}
    score = garuda_score(cert)
    assert score < 4.0, f"Legitimate domain should score low, got {score}"


# ─── NEGATIVE TEST 1: CT collector handles crt.sh timeout without crashing ──
@pytest.mark.anyio
async def test_ct_collector_resilient_to_crtsh_timeout():
    """Hunt loop must never crash on crt.sh network errors."""
    mock_db = AsyncMock()
    mock_enrich = AsyncMock()
    collector = CTHuntCollector(
        garuda_scorer=lambda cert: 7.0,
        enrichment_pipeline=mock_enrich,
        supabase_client=mock_db,
    )
    with patch("httpx.AsyncClient.get", side_effect=Exception("simulated timeout")):
        # Must not raise — loop continues after exception
        await collector._poll_all_patterns()
    # Enrichment was never called because all patterns failed
    mock_enrich.process.assert_not_called()


# ─── NEGATIVE TEST 2: Vibeware feed disabled by default ─────────────────────
def test_vibeware_feed_disabled_by_default(monkeypatch):
    """FEATURE_VIBEWARE_FEED must default to false — zero cost unless explicitly enabled."""
    monkeypatch.delenv("FEATURE_VIBEWARE_FEED", raising=False)
    # Re-import to pick up env var change
    import importlib
    import hunt.vibeware_feed as vf
    importlib.reload(vf)
    assert not vf.ENABLED, "FEATURE_VIBEWARE_FEED must default to false"


# ─── NEGATIVE TEST 3: Lifecycle tracker handles DNS failure gracefully ───────
@pytest.mark.anyio
async def test_lifecycle_dns_failure_does_not_crash():
    """DNS NXDOMAIN must return False, not raise."""
    tracker = DomainLifecycleTracker(
        supabase_client=None,
        telegram_alerter=None,
        dharma_prearm_fn=None,
    )
    with patch("socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
        result = await tracker._check_dns("nonexistent-drdo-fake-domain-99999.example.com")
    assert result is False


# ─── NEGATIVE TEST 4: Convergence score bounded to [0, 10] ──────────────────
def test_convergence_score_never_exceeds_10():
    """Maximum signal on all dimensions must be capped at 10.0."""
    score = compute_convergence_score(
        garuda_score=10.0, cert={}, ip="1.2.3.4",
        internetdb={"ports": [443, 4443, 8443, 8080], "vulns": [], "tags": [], "cpes": []},
        asn_info={"status": "success", "as": "AS17557 PTCL"},
        ripe_stat=None,
        urlscan={"verdicts": {"overall": {"malicious": True, "hasVerdicts": True, "score": 100}}},
        high_interest_asns={17557, 45595, 24499, 9541, 20473, 14061, 63949, 24940},
        apt36_c2_ports={4443, 8443, 8080, 8008},
    )
    assert score <= 10.0, f"Convergence score exceeded 10.0: {score}"
    assert score >= 0.0, f"Convergence score below 0.0: {score}"
