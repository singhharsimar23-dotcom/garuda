import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from garuda.api.main import app


class TestGarudaAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("conflict_mode", data)
        self.assertIn("tension_index", data)

    def test_list_alerts(self):
        response = self.client.get("/api/alerts?page=1&limit=10")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("alerts", data)
        self.assertIn("total", data)
        self.assertIn("page", data)

    def test_alert_graph_and_yara(self):
        # Graph
        res_graph = self.client.get("/api/alerts/test-alert-id/graph")
        self.assertEqual(res_graph.status_code, 200)
        data_graph = res_graph.json()
        self.assertIn("nodes", data_graph)
        self.assertIn("edges", data_graph)

        # YARA
        res_yara = self.client.get("/api/alerts/test-alert-id/yara")
        self.assertEqual(res_yara.status_code, 200)
        self.assertIn("rule APT36_domain_", res_yara.text)

    def test_analyst_confirm_and_reject(self):
        # Confirm
        confirm_payload = {
            "alert_id": "a1b2c3d4",
            "analyst_id": "test_analyst_1",
            "justification": "Confirmed active malware C2 infrastructure hosting payload.",
        }
        res_confirm = self.client.post("/api/analyst/confirm", json=confirm_payload)
        self.assertEqual(res_confirm.status_code, 200)
        data_conf = res_confirm.json()
        self.assertTrue(data_conf["success"])
        self.assertEqual(data_conf["status"], "confirmed")
        self.assertIn("advisory_draft", data_conf)

        # Reject
        reject_payload = {
            "alert_id": "a1b2c3d4",
            "analyst_id": "test_analyst_1",
            "justification": "Legitimate government vendor domain.",
            "reason_code": "legitimate_domain",
        }
        res_reject = self.client.post("/api/analyst/reject", json=reject_payload)
        self.assertEqual(res_reject.status_code, 200)
        data_rej = res_reject.json()
        self.assertTrue(data_rej["success"])
        self.assertEqual(data_rej["status"], "false_positive")

        # Whitelist
        whitelist_payload = {
            "domain": "legit-partner.in",
            "reason": "Authorized research vendor",
            "analyst_id": "test_analyst_1",
        }
        res_wl = self.client.post("/api/analyst/whitelist", json=whitelist_payload)
        self.assertEqual(res_wl.status_code, 200)

        # Audit trail
        res_audit = self.client.get("/api/analyst/audit/a1b2c3d4")
        self.assertEqual(res_audit.status_code, 200)

    def test_campaigns_routes(self):
        res = self.client.get("/api/campaigns")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("campaigns", data)

    def test_stix_routes(self):
        # STIX Feed
        res_feed = self.client.get("/api/stix/feed")
        self.assertEqual(res_feed.status_code, 200)
        self.assertIn("bundle", res_feed.json().get("type", ""))

        # Single STIX
        res_single = self.client.get("/api/stix/alert-12345")
        self.assertEqual(res_single.status_code, 200)

    @patch("garuda.api.routes.collect.run_collection", new_callable=AsyncMock)
    def test_collector_trigger(self, mock_run):
        mock_run.return_value = {"status": "ok"}
        res = self.client.post("/api/collect")
        self.assertEqual(res.status_code, 202)
        data = res.json()
        self.assertEqual(data["status"], "collection_started")
        self.assertIn("timestamp", data)

    def test_stats_route(self):
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_alerts_24h", data)
        self.assertIn("tension_index", data)
        self.assertIn("conflict_mode", data)

    def test_telegram_webhook(self):
        update_payload = {
            "message": {
                "text": "/status",
                "chat": {"id": 12345},
                "from": {"username": "tester"},
            }
        }
        res = self.client.post("/api/telegram_webhook", json=update_payload)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json().get("ok"))


if __name__ == "__main__":
    unittest.main()
