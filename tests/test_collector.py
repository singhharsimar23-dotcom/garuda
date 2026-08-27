import unittest
from unittest.mock import AsyncMock, patch, MagicMock

from garuda.collector import run_collection


class TestGarudaCollector(unittest.IsolatedAsyncioTestCase):

    @patch("garuda.collector.fetch_tension_index", new_callable=AsyncMock)
    @patch("garuda.collector.fetch_new_certs", new_callable=AsyncMock)
    @patch("garuda.collector.fetch_apt36_iocs", new_callable=AsyncMock)
    @patch("garuda.collector.fetch_recent_malware_urls", new_callable=AsyncMock)
    @patch("garuda.collector.query_pdns", new_callable=AsyncMock)
    @patch("garuda.collector.fetch_boss_samples", new_callable=AsyncMock)
    @patch("garuda.collector.process_domain", new_callable=AsyncMock)
    @patch("garuda.collector.check_and_add_set", new_callable=AsyncMock)
    async def test_run_collection_pipeline(
        self,
        mock_check_set,
        mock_process_domain,
        mock_fetch_boss,
        mock_query_pdns,
        mock_fetch_urlhaus,
        mock_fetch_otx,
        mock_fetch_crtsh,
        mock_tension,
    ):
        mock_tension.return_value = 0.72  # Conflict mode trigger
        mock_fetch_crtsh.return_value = [{"domain": "modgov-fake.space", "source": "crtsh"}]
        mock_fetch_otx.return_value = [{"domain": "transparent-target.site", "source": "otx"}]
        mock_fetch_urlhaus.return_value = [{"domain": "nicindia-phish.xyz", "source": "urlhaus"}]
        mock_query_pdns.return_value = [{"rrname": "nic.in", "rrtype": "NS", "rdata": "ns1.nic.in"}]
        mock_fetch_boss.return_value = [{"sha256": "abcdef123456", "source": "malwarebazaar"}]
        
        mock_check_set.return_value = True  # New domain
        mock_process_domain.return_value = {"domain": "test.space", "score": 85, "status": "pending"}

        summary = await run_collection()
        self.assertIsInstance(summary, dict)
        self.assertTrue(summary["conflict_mode"])
        self.assertEqual(summary["tension_index"], 0.72)
        self.assertGreaterEqual(summary["candidate_domains_discovered"], 3)
        self.assertEqual(summary["alerted_critical"], summary["scored"])


if __name__ == "__main__":
    unittest.main()
