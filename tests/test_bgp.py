"""
GARUDA Session 8 Acceptance Tests — BGP RPKI REST Monitor

Tests cover RPKI validation signals, prefix parsing, negative API responses,
and the no-WebSocket invariant (RULE: Vercel serverless cannot use wss://).
"""

import asyncio
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "bgp"


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


class TestAnnouncedPrefixesParsing(unittest.TestCase):
    """Mock RIPE response → correct CIDR list returned."""

    def test_announced_prefixes_parsing(self):
        from garuda.modules.bgp.ripe_stat import AnnouncedPrefixesResponse, get_announced_prefixes

        fixture = _load_fixture("announced_prefixes_valid.json")
        parsed = AnnouncedPrefixesResponse.model_validate(fixture)
        prefixes = [e.prefix for e in parsed.data.prefixes]
        self.assertEqual(prefixes, ["59.160.0.0/16", "59.160.128.0/17"])

        with patch(
            "garuda.modules.bgp.ripe_stat._ripe_get",
            new_callable=AsyncMock,
            return_value=fixture,
        ):
            result = asyncio.run(get_announced_prefixes(18209))
        self.assertEqual(result, ["59.160.0.0/16", "59.160.128.0/17"])


class TestRpkiSignals(unittest.IsolatedAsyncioTestCase):
    """RPKI status drives alert severity correctly."""

    async def asyncSetUp(self):
        from garuda.database import _IN_MEMORY_BGP_INCIDENTS
        _IN_MEMORY_BGP_INCIDENTS.clear()

    @patch("garuda.modules.bgp.hijack_detector._dispatch_bgp_alert", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.get_bgp_updates", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.validate_rpki", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector._load_watchlist", new_callable=AsyncMock)
    async def test_rpki_valid_mock(self, mock_watchlist, mock_rpki, mock_updates, mock_alert):
        """RIPE returns 'valid' + expected ASN → no alert."""
        from garuda.modules.bgp import hijack_detector

        hijack_detector.RPKI_WATCHLIST.clear()
        mock_watchlist.return_value = [("59.160.0.0/16", 18209, "DRDO")]
        mock_rpki.return_value = "valid"
        mock_updates.return_value = [
            {"type": "A", "attrs": {"path": [9498, 18209], "prefix": "59.160.0.0/16"}},
        ]

        incidents = await hijack_detector.run_bgp_hijack_check()
        self.assertEqual(len(incidents), 0)
        mock_alert.assert_not_called()

    @patch("garuda.modules.bgp.hijack_detector._dispatch_bgp_alert", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.get_bgp_updates", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.validate_rpki", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector._load_watchlist", new_callable=AsyncMock)
    async def test_rpki_invalid_mock(self, mock_watchlist, mock_rpki, mock_updates, mock_alert):
        """RIPE returns 'invalid' → HIGH alert dispatched."""
        from garuda.modules.bgp import hijack_detector

        mock_watchlist.return_value = [("59.160.0.0/16", 18209, "DRDO")]
        mock_rpki.return_value = "invalid"
        mock_updates.return_value = [
            {"type": "A", "attrs": {"path": [9498, 18209], "prefix": "59.160.0.0/16"}},
        ]

        incidents = await hijack_detector.run_bgp_hijack_check()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "HIGH")
        mock_alert.assert_called_once()

    @patch("garuda.modules.bgp.hijack_detector._dispatch_bgp_alert", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.get_bgp_updates", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.validate_rpki", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector._load_watchlist", new_callable=AsyncMock)
    async def test_both_signals_critical(self, mock_watchlist, mock_rpki, mock_updates, mock_alert):
        """Invalid RPKI + unexpected ASN → CRITICAL."""
        from garuda.modules.bgp import hijack_detector

        mock_watchlist.return_value = [("59.160.0.0/16", 18209, "DRDO")]
        mock_rpki.return_value = "invalid"
        mock_updates.return_value = [
            {"type": "A", "attrs": {"path": [9498, 4134], "prefix": "59.160.0.0/16"}},
        ]

        incidents = await hijack_detector.run_bgp_hijack_check()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "CRITICAL")
        self.assertEqual(incidents[0]["signal_count"], 2)
        mock_alert.assert_called_once()

    @patch("garuda.modules.bgp.hijack_detector._dispatch_bgp_alert", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.get_bgp_updates", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector.validate_rpki", new_callable=AsyncMock)
    @patch("garuda.modules.bgp.hijack_detector._load_watchlist", new_callable=AsyncMock)
    async def test_unknown_not_hijack(self, mock_watchlist, mock_rpki, mock_updates, mock_alert):
        """'unknown' RPKI status → no alert, advisory only."""
        from garuda.modules.bgp import hijack_detector

        mock_watchlist.return_value = [("59.160.0.0/16", 18209, "DRDO")]
        mock_rpki.return_value = "unknown"
        mock_updates.return_value = [
            {"type": "A", "attrs": {"path": [9498, 4134], "prefix": "59.160.0.0/16"}},
        ]

        incidents = await hijack_detector.run_bgp_hijack_check()
        self.assertEqual(len(incidents), 0)
        mock_alert.assert_not_called()


class TestRipEStatNegative(unittest.TestCase):
    """RULE 4: API down / rate-limited / garbage response."""

    def test_garbage_response_rejected(self):
        from garuda.modules.bgp.ripe_stat import AnnouncedPrefixesResponse

        with self.assertRaises(ValidationError):
            AnnouncedPrefixesResponse.model_validate({"status": "ok", "data": {"prefixes": "not-a-list"}})

    def test_rpki_fixture_validates(self):
        from garuda.modules.bgp.ripe_stat import RpkiValidationResponse

        for name in ("rpki_valid.json", "rpki_invalid.json", "rpki_unknown.json"):
            fixture = _load_fixture(name)
            parsed = RpkiValidationResponse.model_validate(fixture)
            self.assertIn(parsed.data.status, ("valid", "invalid", "unknown"))

    @patch("garuda.modules.bgp.ripe_stat.httpx.AsyncClient")
    def test_api_down_raises(self, mock_client_cls):
        import httpx
        from garuda.modules.bgp.ripe_stat import get_announced_prefixes

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.ConnectError("connection refused")
        mock_client_cls.return_value = mock_client

        with patch("garuda.modules.bgp.ripe_stat.get_cached_json", new_callable=AsyncMock, return_value=None):
            with self.assertRaises(httpx.ConnectError):
                asyncio.run(get_announced_prefixes(18209))


class TestNoWebsocketInCodebase(unittest.TestCase):
    """No websockets package or ris-live WebSocket endpoint in Python source."""

    def test_no_websocket_in_codebase(self):
        root = Path(__file__).resolve().parent.parent / "garuda"
        hits = []
        banned_patterns = ("import websockets", "from websockets", "ris-live.ripe.net", "wss://ris-live")
        for path in root.rglob("*.py"):
            if "node_modules" in str(path) or ".venv" in str(path):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(p in text for p in banned_patterns):
                hits.append(str(path.relative_to(root.parent)))

        self.assertEqual(
            hits,
            [],
            f"Found WebSocket references (Module 15 must use REST only): {hits}",
        )

    def test_no_websockets_package_in_requirements(self):
        req = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text()
        self.assertNotIn("websockets", req.lower())


if __name__ == "__main__":
    unittest.main()
