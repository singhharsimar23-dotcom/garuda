import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from garuda.detection.homoglyph import detect_homoglyph, normalize_domain
from garuda.detection.nic_ground_truth import compute_similarity, load_nic_domains
from garuda.detection.patterns import extract_keyword_match, extract_sector
from garuda.detection.infra_fingerprint import (
    check_c2_ports,
    check_hosting_asn,
    check_registrar_fingerprint,
)
from garuda.detection.scoring import assemble_score
from garuda.detection.engine import process_domain


class TestGarudaDetection(unittest.IsolatedAsyncioTestCase):

    def test_homoglyph_detection(self):
        # 'ο' is Greek omicron
        has_hg, detected = detect_homoglyph("mοd-india.space")
        self.assertTrue(has_hg)
        self.assertIn("ο", detected)

        normalized = normalize_domain("mοd-india.space")
        self.assertEqual(normalized, "mod-india.space")

        # Clean ASCII domain
        has_hg_clean, _ = detect_homoglyph("indianarmy.in")
        self.assertFalse(has_hg_clean)

    def test_nic_ground_truth_similarity(self):
        sim_score, matched = compute_similarity("indianarmy-portal.online")
        self.assertGreater(sim_score, 0.60)
        self.assertIn("indianarmy", matched)

    def test_pattern_and_sector_extraction(self):
        tier, score = extract_keyword_match("modgov-support.xyz")
        self.assertEqual(tier, "tier1")
        self.assertEqual(score, 30)

        sector = extract_sector("drdolab-secure.site")
        self.assertIn("DRDO", sector)

    async def test_registrar_fingerprint(self):
        matched, score = await check_registrar_fingerprint(
            "test.xyz", {"registrar": "Namecheap, Inc."}
        )
        self.assertTrue(matched)
        self.assertEqual(score, 25.0)

    def test_scoring_assembly(self):
        signals = {
            "keyword_tier": "tier1",
            "keyword_score": 30,
            "nic_similarity": 0.88,
            "nic_match": "mod.gov.in",
            "homoglyph": True,
            "registrar_match": True,
            "registrar_score": 25.0,
            "domain_age_days": 5,
            "asn_match": True,
            "tension_index": 0.70,
        }
        score, breakdown = assemble_score(signals)
        self.assertGreaterEqual(score, 85)
        self.assertIn("tension_modifier", breakdown)
        self.assertIn("keyword_pattern", breakdown)

    @patch("garuda.detection.engine._resolve_ip", new_callable=AsyncMock)
    @patch("garuda.detection.engine._fetch_whois_data", new_callable=AsyncMock)
    @patch("garuda.detection.engine.check_hosting_asn", new_callable=AsyncMock)
    @patch("garuda.detection.engine.enrich_threat_indicators", new_callable=AsyncMock)
    @patch("garuda.detection.engine.dispatch_alert", new_callable=AsyncMock)
    async def test_process_domain_pipeline(
        self,
        mock_dispatch,
        mock_enrich,
        mock_asn,
        mock_whois,
        mock_resolve,
    ):
        mock_resolve.return_value = "1.2.3.4"
        mock_whois.return_value = {
            "registrar": "Namecheap, Inc.",
            "creation_date": "2026-08-20T00:00:00",
        }
        mock_asn.return_value = (True, 16276)
        mock_enrich.return_value = {
            "c2_ports": [8443],
            "otx_attributed": True,
            "abuseipdb_reports": 1,
        }
        mock_dispatch.return_value = True

        result = await process_domain("modgov-portal.space", source="crtsh")
        self.assertIsNotNone(result)
        self.assertEqual(result["domain"], "modgov-portal.space")
        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["sector"], "Ministry of Defence (MoD)")
        self.assertEqual(result["status"], "pending")


if __name__ == "__main__":
    unittest.main()
