"""
GARUDA Session 14 Acceptance Tests — Canary Document Factory
"""

import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from garuda.modules.canary.webhook import (
    CanaryTokenNotFoundError,
    build_canary_alert_text,
    process_canary_webhook,
    score_canary_fire,
)


class TestCanaryWebhookScoring(unittest.IsolatedAsyncioTestCase):
    """Canary webhook scoring and alert dispatch logic."""

    async def asyncSetUp(self):
        from garuda.database import _IN_MEMORY_CANARY_TOKENS, _IN_MEMORY_PERSONA_NODES
        _IN_MEMORY_CANARY_TOKENS.clear()
        _IN_MEMORY_PERSONA_NODES.clear()

        from garuda.database import upsert_canary_token
        self.token_record = await upsert_canary_token({
            "token": "test-token-abc",
            "token_type": "pdf",
            "memo": "GARUDA canary: test.pdf",
            "document_theme": "NIC_Security_Advisory_Critical_Systems_Aug2026.pdf",
            "sector": "NIC",
            "webhook_url": "https://example.com/api/canary/webhook",
        })

    @patch("garuda.database.ip_matches_confirmed_alert", new_callable=AsyncMock, return_value=False)
    @patch("garuda.database.ip_in_passive_dns", new_callable=AsyncMock, return_value=False)
    @patch("garuda.modules.canary.webhook.lookup_ip_asn", new_callable=AsyncMock)
    async def test_webhook_pakistani_asn(self, mock_asn, _pdns, _infra):
        mock_asn.return_value = {"as": "AS17557 PTCL", "org": "PTCL", "country": "Pakistan"}
        score, _ = await score_canary_fire("203.0.113.10", supabase_client=None)
        self.assertGreaterEqual(score, 40)

        payload = {
            "token": "test-token-abc",
            "src_ip": "203.0.113.10",
            "useragent": "Mozilla/5.0",
            "time": "2026-08-28T10:00:00Z",
        }
        result = await process_canary_webhook(payload, supabase_client=None)
        self.assertIn(result["severity"], ("HIGH", "CRITICAL"))
        self.assertGreaterEqual(result["score"], 40)

    @patch("garuda.database.ip_in_passive_dns", new_callable=AsyncMock, return_value=False)
    @patch("garuda.database.ip_matches_confirmed_alert", new_callable=AsyncMock, return_value=True)
    @patch("garuda.modules.canary.webhook.lookup_ip_asn", new_callable=AsyncMock, return_value={})
    async def test_webhook_known_infra(self, _asn, _infra, _pdns):
        payload = {
            "token": "test-token-abc",
            "src_ip": "185.220.101.45",
            "useragent": "curl/7.68.0",
        }
        with patch("garuda.modules.canary.webhook.settings.TELEGRAM_BOT_TOKEN", None):
            result = await process_canary_webhook(payload, supabase_client=None)
        self.assertGreaterEqual(result["score"], 60)
        self.assertEqual(result["severity"], "CRITICAL")

    @patch("garuda.modules.canary.webhook.greynoise_targeted", new_callable=AsyncMock, return_value=False)
    @patch("garuda.database.ip_in_passive_dns", new_callable=AsyncMock, return_value=False)
    @patch("garuda.database.ip_matches_confirmed_alert", new_callable=AsyncMock, return_value=False)
    @patch(
        "garuda.modules.canary.webhook.lookup_ip_asn",
        new_callable=AsyncMock,
        return_value={"as": "AS15169 Google", "org": "Google"},
    )
    async def test_webhook_public_scanner(self, _asn, _infra, _pdns, _gn):
        payload = {
            "token": "test-token-abc",
            "src_ip": "8.8.8.8",
            "useragent": "ScannerBot/1.0",
        }
        result = await process_canary_webhook(payload, supabase_client=None)
        self.assertLess(result["score"], 40)
        self.assertEqual(result["severity"], "LOG")

    @patch("garuda.database.ip_in_passive_dns", new_callable=AsyncMock, return_value=False)
    @patch("garuda.database.ip_matches_confirmed_alert", new_callable=AsyncMock, return_value=True)
    @patch("garuda.modules.canary.webhook.lookup_ip_asn", new_callable=AsyncMock, return_value={})
    async def test_persona_node_created(self, _asn, _infra, _pdns):
        from garuda.database import _IN_MEMORY_PERSONA_NODES

        payload = {
            "token": "test-token-abc",
            "src_ip": "185.220.101.45",
            "useragent": "Mozilla/5.0",
        }
        with patch("garuda.modules.canary.webhook.settings.TELEGRAM_BOT_TOKEN", None):
            await process_canary_webhook(payload, supabase_client=None)

        self.assertTrue(any(n.get("value") == "185.220.101.45" for n in _IN_MEMORY_PERSONA_NODES))

    async def test_unknown_token(self):
        with self.assertRaises(CanaryTokenNotFoundError):
            await process_canary_webhook(
                {"token": "nonexistent-token", "src_ip": "1.2.3.4"},
                supabase_client=None,
            )


class TestCanaryFactory(unittest.IsolatedAsyncioTestCase):
    async def test_canary_disabled_flag(self):
        import garuda.modules.canary.factory as factory

        original = factory.CANARY_API_ENABLED
        factory.CANARY_API_ENABLED = False
        try:
            result = await factory.create_canary_token("pdf", "test memo", "https://example.com/hook")
            self.assertIsNone(result)
        finally:
            factory.CANARY_API_ENABLED = original


class TestCanaryAlertLanguage(unittest.TestCase):
    def test_egress_ip_language(self):
        text = build_canary_alert_text(
            token_record={"id": "tok-1", "document_theme": "test.pdf", "token_type": "pdf"},
            payload={"useragent": "Mozilla/5.0", "time": "2026-08-28T10:00:00Z"},
            score=85,
            context={"src_ip": "203.0.113.1", "asn": 17557, "asn_org": "PTCL", "pakistani_isp": "PTCL"},
        )
        self.assertIn("Egress IP", text)
        self.assertNotIn("Operator location:", text)


class TestCanaryWebhookEndpoint(unittest.TestCase):
    def test_unknown_token_http_404(self):
        from garuda.api.routes.canary import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        res = client.post("/api/canary/webhook", json={"token": "missing", "src_ip": "1.2.3.4"})
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()
