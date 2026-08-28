"""
GARUDA Session 9 Acceptance Tests — ORB Network Tracker

Tests cover SOHO detection, anchor ASN scoring, thresholds, and InternetDB edge cases.
"""

import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "orb"


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


class TestOrbSignals(unittest.TestCase):
    """Pure unit tests for score_orb_probability — fully offline."""

    def test_soho_keyword_detection(self):
        from garuda.modules.orb.signals import score_orb_probability

        data = {
            "cpes": ["cpe:2.3:h:draytek:vigor:*:*:*:*:*:*:*:*"],
            "ports": [8443],
            "vulns": [],
        }
        score, triggered, _ = score_orb_probability(
            ip="203.0.113.50",
            internetdb_data=data,
            bgp_path_asns=[],
            is_in_otx_iocs=False,
        )
        self.assertGreaterEqual(score, 25)
        self.assertIn("soho_device_with_suspect_port", triggered)

    def test_orb_port_detection(self):
        from garuda.modules.orb.signals import score_orb_probability

        data = {
            "product": "cisco rv320",
            "ports": [8443, 443],
            "vulns": [],
        }
        score, triggered, _ = score_orb_probability(
            ip="203.0.113.51",
            internetdb_data=data,
            bgp_path_asns=[],
            is_in_otx_iocs=False,
        )
        self.assertGreaterEqual(score, 25)
        self.assertTrue(any("soho" in s for s in triggered))

    def test_anchor_asn_detection(self):
        from garuda.modules.orb.signals import score_orb_probability

        data = {"ports": [443], "vulns": []}
        score, triggered, _ = score_orb_probability(
            ip="203.0.113.52",
            internetdb_data=data,
            bgp_path_asns=[9498, 37963, 18209],
            is_in_otx_iocs=False,
        )
        self.assertGreaterEqual(score, 35)
        self.assertTrue(any("chinese_anchor_asn" in s for s in triggered))

    def test_threshold_not_met(self):
        from garuda.modules.orb.signals import score_orb_probability

        data = {"ports": [443], "vulns": []}
        score, _, _ = score_orb_probability(
            ip="203.0.113.53",
            internetdb_data=data,
            bgp_path_asns=[9498],
            is_in_otx_iocs=False,
        )
        self.assertLess(score, 60)

    def test_threshold_met(self):
        from garuda.modules.orb.signals import confidence_label_from_score, score_orb_probability

        data = {
            "product": "DrayTek Vigor",
            "ports": [8443],
            "vulns": ["CVE-2020-8515"],
        }
        score, triggered, _ = score_orb_probability(
            ip="203.0.113.54",
            internetdb_data=data,
            bgp_path_asns=[37963],
            is_in_otx_iocs=False,
            kev_cves={"CVE-2020-8515"},
        )
        self.assertGreaterEqual(score, 60)
        self.assertIn(confidence_label_from_score(score), ("PROBABLE_ORB", "CONFIRMED_ORB"))
        self.assertTrue(len(triggered) >= 2)


class TestOrbSweepIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests with mocked external APIs."""

    async def asyncSetUp(self):
        from garuda.database import _IN_MEMORY_ORB_NODES
        _IN_MEMORY_ORB_NODES.clear()

    @patch("garuda.modules.orb.tracker._dispatch_orb_alert", new_callable=AsyncMock)
    @patch("garuda.modules.orb.tracker._check_otx_ioc", new_callable=AsyncMock, return_value=False)
    @patch("garuda.modules.orb.tracker.get_bgp_updates", new_callable=AsyncMock)
    @patch("garuda.modules.orb.tracker._fetch_internetdb", new_callable=AsyncMock)
    async def test_threshold_met_no_alert(self, mock_idb, mock_bgp, mock_otx, mock_alert):
        """Score=65 → upsert to orb_nodes, no alert."""
        from garuda.modules.orb.tracker import run_orb_sweep

        mock_idb.return_value = {
            "product": "DrayTek Vigor",
            "ports": [8443],
            "vulns": [],
            "cpes": ["cpe:2.3:h:draytek:vigor:*:*:*:*:*:*:*:*"],
        }
        mock_bgp.return_value = [{"type": "A", "attrs": {"path": [37963]}}]

        with patch("garuda.modules.orb.tracker.get_defence_prefixes_cached", new_callable=AsyncMock, return_value=[]):
            flagged = await run_orb_sweep(candidate_ips=["203.0.113.60"])

        self.assertEqual(len(flagged), 1)
        self.assertGreaterEqual(flagged[0]["orb_score"], 60)
        self.assertLess(flagged[0]["orb_score"], 80)
        mock_alert.assert_not_called()

    @patch("garuda.modules.orb.tracker._dispatch_orb_alert", new_callable=AsyncMock)
    @patch("garuda.modules.orb.tracker._check_otx_ioc", new_callable=AsyncMock, return_value=True)
    @patch("garuda.modules.orb.tracker.get_bgp_updates", new_callable=AsyncMock)
    @patch("garuda.modules.orb.tracker._fetch_internetdb", new_callable=AsyncMock)
    async def test_critical_threshold(self, mock_idb, mock_bgp, mock_otx, mock_alert):
        """Score=85 AND targeting_indian_defence → alert dispatched."""
        from garuda.modules.orb.tracker import run_orb_sweep

        mock_idb.return_value = {
            "product": "DrayTek Vigor",
            "ports": [8443, 9443],
            "vulns": ["CVE-2020-8515"],
            "cpes": ["cpe:2.3:h:draytek:vigor:*:*:*:*:*:*:*:*"],
        }
        mock_bgp.return_value = [{"type": "A", "attrs": {"path": [37963, 4134]}}]

        with patch(
            "garuda.modules.orb.tracker.get_defence_prefixes_cached",
            new_callable=AsyncMock,
            return_value=["59.160.0.0/16"],
        ):
            flagged = await run_orb_sweep(candidate_ips=["59.160.1.1"])

        self.assertEqual(len(flagged), 1)
        self.assertGreaterEqual(flagged[0]["orb_score"], 80)
        self.assertTrue(flagged[0]["targeting_indian_defence"])
        mock_alert.assert_called_once()

    @patch("garuda.modules.orb.tracker._fetch_internetdb", new_callable=AsyncMock, return_value=None)
    async def test_internetdb_no_info(self, mock_idb):
        """'No information available' → skip, no crash."""
        from garuda.modules.orb.tracker import run_orb_sweep

        flagged = await run_orb_sweep(candidate_ips=["203.0.113.99"])
        self.assertEqual(flagged, [])
        mock_idb.assert_called_once()


class TestInternetDbFixture(unittest.TestCase):
    """Fixture validation for InternetDB responses."""

    def test_soho_fixture_parses(self):
        from garuda.modules.orb.tracker import InternetDbResponse

        fixture = _load_fixture("internetdb_soho.json")
        parsed = InternetDbResponse.model_validate(fixture)
        self.assertIn(8443, parsed.ports)

    def test_no_info_fixture(self):
        fixture = _load_fixture("internetdb_no_info.json")
        self.assertEqual(fixture.get("detail"), "No information available")


if __name__ == "__main__":
    unittest.main()
