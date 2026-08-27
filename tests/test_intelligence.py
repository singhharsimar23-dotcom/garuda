import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from garuda.intelligence.cluster import detect_campaigns, encode_features
from garuda.intelligence.dga_detector import extract_dga_features, predict_dga
from garuda.intelligence.graph_builder import build_ioc_graph
from garuda.intelligence.honeypot import process_honeypot_logs
from garuda.intelligence.llm_enrichment import generate_threat_narrative
from garuda.intelligence.retrohunt import run_retrohunt
from garuda.intelligence.tension_index import compute_tension_index


class TestGarudaIntelligence(unittest.IsolatedAsyncioTestCase):

    def test_dga_feature_extraction_and_prediction(self):
        # Benign-looking domain
        features_legit = extract_dga_features("modgov-portal.in")
        self.assertEqual(len(features_legit), 8)
        is_dga_legit, conf_legit = predict_dga("modgov-portal.in")
        self.assertFalse(is_dga_legit)

        # High entropy DGA domain
        is_dga_bad, conf_bad = predict_dga("xkz984jqpvw73rtlm.xyz")
        self.assertTrue(is_dga_bad)
        self.assertGreater(conf_bad, 0.5)

    def test_cluster_feature_encoding(self):
        mock_alerts = [
            {
                "registrar": "Namecheap, Inc.",
                "hosting_asn": 16276,
                "hosting_ip": "185.220.101.5",
                "sector": "Ministry of Defence (MoD)",
                "detected_at": "2026-08-27T00:00:00Z",
            },
            {
                "registrar": "PDR Ltd",
                "hosting_asn": 24940,
                "hosting_ip": "194.169.175.10",
                "sector": "National Informatics Centre (NIC)",
                "detected_at": "2026-08-27T01:00:00Z",
            },
        ]
        matrix = encode_features(mock_alerts)
        self.assertEqual(matrix.shape, (2, 5))
        self.assertEqual(matrix[0][0], 1.0)  # Namecheap
        self.assertEqual(matrix[0][1], 16276.0)  # ASN

    @patch("garuda.intelligence.cluster.get_supabase_client")
    @patch("garuda.intelligence.cluster.dispatch_alert", new_callable=AsyncMock)
    async def test_campaign_detection(self, mock_dispatch, mock_supabase):
        mock_client = MagicMock()
        mock_client.table.return_value.select.return_value.gte.return_value.neq.return_value.execute.return_value.data = [
            {
                "id": "alert-1",
                "domain": "army-1.space",
                "registrar": "Namecheap",
                "hosting_asn": 16276,
                "hosting_ip": "185.220.101.5",
                "sector": "MoD",
                "detected_at": "2026-08-27T00:00:00Z",
                "signals": {"domain_age_days": 4},
            },
            {
                "id": "alert-2",
                "domain": "army-2.space",
                "registrar": "Namecheap",
                "hosting_asn": 16276,
                "hosting_ip": "185.220.101.6",
                "sector": "MoD",
                "detected_at": "2026-08-27T01:00:00Z",
                "signals": {"domain_age_days": 5},
            },
        ]
        mock_supabase.return_value = mock_client
        mock_dispatch.return_value = True

        campaigns = await detect_campaigns(window_hours=72)
        self.assertIsInstance(campaigns, list)
        self.assertGreaterEqual(len(campaigns), 1)
        self.assertIn("cluster_id", campaigns[0])
        self.assertIn("estimated_attack_window_days", campaigns[0])

    @patch("garuda.intelligence.honeypot.dispatch_alert", new_callable=AsyncMock)
    async def test_honeypot_log_processing(self, mock_dispatch):
        mock_dispatch.return_value = True
        log_entries = [
            {
                "source_ip": "185.220.101.99",
                "domain_queried": "army-hq-portal.space",
                "query_type": "A",
            }
        ]
        alerts = await process_honeypot_logs(log_entries)
        self.assertIsInstance(alerts, list)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["score"], 100)
        self.assertEqual(alerts[0]["source"], "honeypot")

    @patch("garuda.intelligence.graph_builder._pivot_ssl_sans", new_callable=AsyncMock)
    @patch("garuda.intelligence.graph_builder._pivot_reverse_ip", new_callable=AsyncMock)
    @patch("garuda.intelligence.graph_builder._pivot_pdns_nameservers", new_callable=AsyncMock)
    async def test_graph_builder(self, mock_pdns, mock_revip, mock_sans):
        mock_sans.return_value = ["san1-modgov.space", "san2-modgov.space"]
        mock_revip.return_value = ["cohost-drdo.site"]
        mock_pdns.return_value = [{"domain": "other-mod.xyz", "nameserver": "ns1.hoster.com"}]

        alert_data = {
            "hosting_ip": "185.220.101.5",
            "score": 85,
            "registrar": "Namecheap",
            "registered_at": "2026-08-01T00:00:00Z",
        }

        graph = await build_ioc_graph("modgov-portal.space", alert_data)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreater(len(graph["nodes"]), 3)
        self.assertGreater(len(graph["edges"]), 2)

    async def test_llm_narrative_generation_fallback(self):
        alert_sample = {
            "domain": "defenceindia-portal.online",
            "score": 85,
            "sector": "Ministry of Defence (MoD)",
            "signals": {"otx_attributed": False},
        }
        narrative = await generate_threat_narrative(alert_sample)
        self.assertIsInstance(narrative, str)
        self.assertTrue(narrative.endswith("AI-ASSISTED DRAFT — ANALYST REVIEW REQUIRED."))
        self.assertIn("defenceindia-portal.online", narrative)

    @patch("garuda.detection.engine.process_domain", new_callable=AsyncMock)
    async def test_retrohunt_simulation(self, mock_process):
        mock_process.return_value = {"domain": "army-updates-secure.space", "score": 85, "status": "pending"}
        summary = await run_retrohunt()
        self.assertIsInstance(summary, dict)
        self.assertIn("recall", summary)
        self.assertIn("mean_time_saved_hours", summary)
        self.assertGreater(summary["total_evaluated"], 0)
        self.assertGreaterEqual(summary["recall"], 0.80)


if __name__ == "__main__":
    unittest.main()
