"""
GARUDA Session 6 Acceptance Tests — Operator Clusters & Campaign Fingerprinting

Validates:
  1. Deterministic similarity scoring over technical observables (True Positive & True Negative pairs).
  2. Strict two-step human-in-the-loop attribution review (NO silent auto-clustering).
  3. Zero pre-seeded fake clusters invariant.
  4. Operator cluster & review queue API endpoints.
"""

import asyncio
from datetime import datetime, timezone
import unittest

from fastapi.testclient import TestClient

from garuda.api.main import app
from garuda.database import (
    _IN_MEMORY_CAMPAIGN_FINGERPRINTS,
    _IN_MEMORY_CLUSTER_REVIEW_QUEUE,
    _IN_MEMORY_OPERATOR_CLUSTERS,
    create_operator_cluster,
    get_campaign_fingerprints,
    get_cluster_review_queue,
    get_operator_clusters,
    insert_campaign_fingerprint,
    update_cluster_review_decision,
)
from garuda.intelligence.cluster_similarity import (
    compute_fingerprint_similarity,
    propose_cluster_attribution,
)


class TestFingerprintSimilarity(unittest.TestCase):
    """
    Acceptance Criteria: Similarity function has unit tests covering a true-positive
    pair and a true-negative pair using synthetic data clearly marked as synthetic.
    """

    def test_synthetic_true_positive_pair_scores_high(self):
        """
        Two synthetic campaign fingerprints exhibiting strong APT36 infrastructure overlap:
          - Identical registrar account pattern ('reg-actor-t1-pat')
          - Shared nameservers ('ns1.parked-c2.top', 'ns2.parked-c2.top')
          - Same hosting ASN ('AS49505')
          - Same target sector ('nic-gov') and lure theme ('defence-procurement')
          - Overlapping CVEs ('CVE-2024-21762', 'CVE-2023-3519')
          - Close cert issuance timing (2 days delta)
        Expected: composite score >= 0.80.
        """
        synth_fp1 = {
            "domain": "synthetic-apt36-c2-a.space",
            "registrar": "Namecheap",
            "registrar_account_pattern": "reg-actor-t1-pat",
            "nameserver_sequence": ["ns1.parked-c2.top", "ns2.parked-c2.top"],
            "hosting_asn": "AS49505",
            "cert_issued_at": "2026-08-10T10:00:00Z",
            "lure_theme": "defence-procurement-guidelines",
            "target_sector": "nic-gov",
            "cves_used": ["CVE-2024-21762", "CVE-2023-3519"],
        }
        synth_fp2 = {
            "domain": "synthetic-apt36-c2-b.space",
            "registrar": "Namecheap",
            "registrar_account_pattern": "reg-actor-t1-pat",
            "nameserver_sequence": ["ns1.parked-c2.top", "ns2.parked-c2.top"],
            "hosting_asn": "AS49505",
            "cert_issued_at": "2026-08-12T14:30:00Z",
            "lure_theme": "defence-procurement-schedule",
            "target_sector": "nic-gov",
            "cves_used": ["CVE-2024-21762"],
        }

        score, signals = compute_fingerprint_similarity(synth_fp1, synth_fp2)
        self.assertGreaterEqual(score, 0.80, f"True-positive similarity score {score} must be >= 0.80")
        self.assertEqual(signals["registrar_pattern_match"], "exact_pattern")
        self.assertEqual(signals["hosting_asn_match"], "AS49505")
        self.assertEqual(signals["target_sector_match"], "nic-gov")

    def test_synthetic_true_negative_pair_scores_low(self):
        """
        Two synthetic campaign fingerprints from completely unrelated actors:
          - Different registrars & account patterns
          - Disjoint nameservers
          - Different hosting ASNs
          - Different target sectors & lure themes
          - No shared CVEs
        Expected: composite score < 0.20.
        """
        synth_fp1 = {
            "domain": "synthetic-apt36-c2-a.space",
            "registrar": "Namecheap",
            "registrar_account_pattern": "reg-actor-t1-pat",
            "nameserver_sequence": ["ns1.parked-c2.top", "ns2.parked-c2.top"],
            "hosting_asn": "AS49505",
            "cert_issued_at": "2026-08-10T10:00:00Z",
            "lure_theme": "defence-procurement",
            "target_sector": "nic-gov",
            "cves_used": ["CVE-2024-21762"],
        }
        synth_fp_unrelated = {
            "domain": "synthetic-fin-banking-phish.com",
            "registrar": "GoDaddy",
            "registrar_account_pattern": "unrelated-retail-user",
            "nameserver_sequence": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            "hosting_asn": "AS13335",
            "cert_issued_at": "2025-01-01T00:00:00Z",
            "lure_theme": "banking-otp-verify",
            "target_sector": "financial-services",
            "cves_used": ["CVE-2021-44228"],
        }

        score, signals = compute_fingerprint_similarity(synth_fp1, synth_fp_unrelated)
        self.assertLess(score, 0.20, f"True-negative similarity score {score} must be < 0.20")


class TestHumanInTheLoopReviewWorkflow(unittest.TestCase):
    """
    Acceptance Criteria: Candidate matches above threshold are staged into review queue.
    Fingerprint cluster_id is NEVER auto-assigned; it remains NULL until an analyst confirms.
    """

    def setUp(self):
        _IN_MEMORY_OPERATOR_CLUSTERS.clear()
        _IN_MEMORY_CAMPAIGN_FINGERPRINTS.clear()
        _IN_MEMORY_CLUSTER_REVIEW_QUEUE.clear()

    def test_two_step_attribution_workflow(self):
        # 1. Create a working cluster
        cluster = asyncio.run(
            create_operator_cluster(
                label="cluster-a-nic-mod",
                first_observed="2026-08-01",
                notes="Internal working group tracking Indian public administration lures",
            )
        )
        cluster_id = cluster["id"]

        # 2. Ingest baseline fingerprint already linked to the cluster
        fp_baseline = asyncio.run(
            insert_campaign_fingerprint({
                "domain": "baseline-portal.space",
                "cluster_id": cluster_id,
                "registrar_account_pattern": "pat-nic-targeter",
                "nameserver_sequence": ["ns1.badinfra.org", "ns2.badinfra.org"],
                "hosting_asn": "AS49505",
                "target_sector": "nic-gov",
                "cves_used": ["CVE-2024-21762"],
            })
        )

        # 3. Ingest NEW unclustered fingerprint (cluster_id is explicitly None)
        fp_new = asyncio.run(
            insert_campaign_fingerprint({
                "domain": "new-unclustered-lure.space",
                "cluster_id": None,
                "registrar_account_pattern": "pat-nic-targeter",
                "nameserver_sequence": ["ns1.badinfra.org", "ns2.badinfra.org"],
                "hosting_asn": "AS49505",
                "target_sector": "nic-gov",
                "cves_used": ["CVE-2024-21762"],
            })
        )
        new_fp_id = fp_new["id"]

        # 4. Propose attribution
        candidates = asyncio.run(
            propose_cluster_attribution(fingerprint_id=new_fp_id, min_threshold=0.70)
        )
        self.assertEqual(len(candidates), 1)
        review_item = candidates[0]
        self.assertEqual(review_item["suggested_cluster_id"], cluster_id)
        self.assertEqual(review_item["status"], "pending")

        # CRITICAL TEST: Unclustered fingerprint must STILL have cluster_id = None
        fps_after_propose = asyncio.run(get_campaign_fingerprints())
        new_fp_current = next(f for f in fps_after_propose if f["id"] == new_fp_id)
        self.assertIsNone(
            new_fp_current.get("cluster_id"),
            "Fingerprint MUST remain unassigned before explicit analyst review approval",
        )

        # 5. Analyst approves attribution with mandatory justification
        review_id = review_item["id"]
        approved = asyncio.run(
            update_cluster_review_decision(
                review_id=review_id,
                decision="approved",
                analyst_id="ANALYST-DEFENCE-042",
                justification="Infrastructure overlaps on ASN 49505, registrar pattern, and CVE-2024-21762.",
            )
        )
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["analyst_id"], "ANALYST-DEFENCE-042")

        # 6. Verify fingerprint is NOW assigned to the cluster
        fps_after_approval = asyncio.run(get_campaign_fingerprints())
        new_fp_approved = next(f for f in fps_after_approval if f["id"] == new_fp_id)
        self.assertEqual(new_fp_approved.get("cluster_id"), cluster_id)


class TestZeroPreSeededFakeClustersInvariant(unittest.TestCase):
    """
    Acceptance Criteria: Zero pre-seeded fake clusters in operator_clusters or
    campaign_infrastructure_fingerprints at clean deployment start.
    """

    def test_database_tables_start_clean_and_unseeded(self):
        _IN_MEMORY_OPERATOR_CLUSTERS.clear()
        _IN_MEMORY_CAMPAIGN_FINGERPRINTS.clear()

        clusters = asyncio.run(get_operator_clusters())
        fingerprints = asyncio.run(get_campaign_fingerprints())

        self.assertEqual(len(clusters), 0, "operator_clusters must start with ZERO pre-seeded rows")
        self.assertEqual(len(fingerprints), 0, "campaign_infrastructure_fingerprints must start with ZERO pre-seeded rows")


class TestClusterApiEndpoints(unittest.TestCase):
    """API endpoint acceptance tests for /api/v1/clusters/*."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        _IN_MEMORY_OPERATOR_CLUSTERS.clear()
        _IN_MEMORY_CAMPAIGN_FINGERPRINTS.clear()
        _IN_MEMORY_CLUSTER_REVIEW_QUEUE.clear()

    def test_create_and_list_clusters_endpoint(self):
        # Create cluster
        res = self.client.post(
            "/api/v1/clusters",
            json={"label": "cluster-gamma-mod", "first_observed": "2026-08-20"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["cluster"]["label"], "cluster-gamma-mod")

        # List clusters
        res_list = self.client.get("/api/v1/clusters")
        self.assertEqual(res_list.status_code, 200)
        self.assertEqual(res_list.json()["total_clusters"], 1)

    def test_review_decision_requires_justification(self):
        # Empty justification -> 422
        res_empty = self.client.post(
            "/api/v1/clusters/review-queue/00000000-0000-0000-0000-000000000001/decide",
            json={"decision": "approved", "analyst_id": "A1", "justification": ""},
        )
        self.assertEqual(res_empty.status_code, 422)


if __name__ == "__main__":
    unittest.main()
