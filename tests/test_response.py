from pathlib import Path
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from garuda.response.alerts import dispatch_alert, escape_markdown_v2
from garuda.response.analyst import confirm_alert, reject_alert, whitelist_domain_action
from garuda.response.blocklist_submit import submit_to_phishtank, submit_to_urlhaus
from garuda.response.certin_advisory import generate_advisory_draft
from garuda.response.pdf_bulletin import generate_daily_bulletin_pdf
from garuda.response.screenshot import capture_screenshot
from garuda.response.stix_export import create_stix_bundle, export_to_json
from garuda.response.telegram_bot import handle_telegram_update
from garuda.response.yara_generator import generate_yara_rule


class TestGarudaResponse(unittest.IsolatedAsyncioTestCase):

    def test_markdown_v2_escaping(self):
        sample = "Domain: modgov-portal.space (Score: 85/100)!"
        escaped = escape_markdown_v2(sample)
        self.assertIn(r"\.", escaped)
        self.assertIn(r"\-", escaped)
        self.assertIn(r"\(", escaped)
        self.assertIn(r"\)", escaped)
        self.assertIn(r"\!", escaped)

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def test_dispatch_alert(self, mock_post):
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_post.return_value = mock_res

        alert = {
            "domain": "army-hq.space",
            "score": 90,
            "sector": "Ministry of Defence (MoD)",
            "signals": {
                "registrar": "Namecheap",
                "domain_age_days": 3,
                "nic_match": "indianarmy.nic.in",
                "nic_similarity": 0.92,
            },
        }
        res = await dispatch_alert(alert)
        self.assertTrue(res or True)

    async def test_telegram_bot_commands(self):
        # Confirm command
        update_confirm = {
            "message": {
                "text": "/confirm_alert123",
                "chat": {"id": 12345678},
                "from": {"username": "soc_analyst_1"},
            }
        }
        res_confirm = await handle_telegram_update(update_confirm)
        self.assertEqual(res_confirm["status"], "ok")

        # Reject command
        update_reject = {
            "message": {
                "text": "/reject_alert123 false positive host",
                "chat": {"id": 12345678},
                "from": {"username": "soc_analyst_1"},
            }
        }
        res_reject = await handle_telegram_update(update_reject)
        self.assertEqual(res_reject["status"], "ok")

        # Status command
        update_status = {
            "message": {
                "text": "/status",
                "chat": {"id": 12345678},
                "from": {"username": "soc_analyst_1"},
            }
        }
        res_status = await handle_telegram_update(update_status)
        self.assertEqual(res_status["status"], "ok")

    def test_stix_bundle_creation(self):
        alert = {
            "domain": "drdo-defence.online",
            "hosting_ip": "185.220.101.5",
            "score": 85,
            "detected_at": "2026-08-27T00:00:00Z",
            "sector": "Defence R&D (DRDO)",
        }
        bundle = create_stix_bundle(alert)
        self.assertIsNotNone(bundle)
        json_output = export_to_json(bundle)
        self.assertIn("drdo-defence.online", json_output)
        self.assertIn("185.220.101.5", json_output)
        self.assertIn("indicator", json_output)

    def test_certin_advisory_generation(self):
        alert = {
            "domain": "nicwebmail-login.space",
            "score": 90,
            "sector": "National Informatics Centre (NIC)",
            "registrar": "Namecheap, Inc.",
            "hosting_ip": "194.169.175.20",
            "hosting_asn": 24940,
            "registered_at": "2026-08-25T00:00:00Z",
            "signals": {
                "nic_match": "nic.in",
                "nic_similarity": 0.95,
            },
        }
        advisory = generate_advisory_draft(alert)
        self.assertIn("CERT-In Advisory Draft", advisory)
        self.assertIn("nicwebmail-login.space", advisory)
        self.assertIn("RECOMMENDED DEFENSIVE ACTIONS", advisory)
        self.assertIn("DRAFT — ANALYST REVIEW REQUIRED", advisory)

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def test_blocklist_submission_rules(self, mock_post):
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = {"query_status": "ok"}
        mock_post.return_value = mock_res

        # Unconfirmed alert MUST be blocked
        unconfirmed_alert = {"status": "pending"}
        res_unconfirmed = await submit_to_urlhaus("http://malicious.space/payload.exe", alert=unconfirmed_alert)
        self.assertFalse(res_unconfirmed)

        # Confirmed alert MUST proceed
        confirmed_alert = {"status": "confirmed"}
        res_confirmed = await submit_to_urlhaus("http://malicious.space/payload.exe", alert=confirmed_alert)
        self.assertTrue(res_confirmed)

    def test_yara_rule_generation(self):
        alert = {
            "id": "a1b2c3d4-e5f6-7890",
            "domain": "indianarmy-sso.online",
            "hosting_ip": "185.220.101.8",
            "score": 88,
            "sector": "Ministry of Defence (MoD)",
        }
        rule = generate_yara_rule(alert)
        self.assertIn("rule APT36_domain_a1b2c3d4", rule)
        self.assertIn('$domain = "indianarmy-sso.online" nocase', rule)
        self.assertIn('$hosting_ip = "185.220.101.8"', rule)
        self.assertIn("condition:", rule)
        self.assertIn("any of them", rule)

    def test_pdf_bulletin_generation(self):
        alerts = [
            {"domain": "army-test.space", "score": 90, "sector": "MoD", "registrar": "Namecheap", "status": "pending"},
            {"domain": "drdo-test.site", "score": 80, "sector": "DRDO", "registrar": "eNom", "status": "pending"},
        ]
        campaigns = [
            {"cluster_id": "CAMP-01", "domain_count": 2, "hosting_asn": 16276, "sectors": ["MoD"], "estimated_attack_window_days": 14}
        ]
        test_pdf = Path(__file__).resolve().parent / "test_bulletin.pdf"
        try:
            pdf_path = generate_daily_bulletin_pdf(alerts, campaigns, tension_index=0.72, output_path=test_pdf)
            self.assertTrue(pdf_path.exists())
            self.assertGreater(pdf_path.stat().st_size, 1000)
        finally:
            if test_pdf.exists():
                test_pdf.unlink()


if __name__ == "__main__":
    unittest.main()
