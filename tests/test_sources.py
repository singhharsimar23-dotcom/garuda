import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from garuda.sources.crtsh import fetch_new_certs
from garuda.sources.otx import fetch_apt36_iocs
from garuda.sources.urlhaus import fetch_recent_malware_urls
from garuda.sources.circl_pdns import query_pdns
from garuda.sources.malwarebazaar import fetch_boss_samples


class TestGarudaSources(unittest.IsolatedAsyncioTestCase):

    async def test_crtsh_fetch(self):
        mock_response = [
            {
                "id": 12345,
                "name_value": "test-modgov.space\ntest2-modgov.space",
                "not_before": "2026-08-01T00:00:00",
                "serial_number": "1a2b3c4d",
            }
        ]
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mock_response
            mock_res.raise_for_status = MagicMock()
            mock_get.return_value = mock_res

            results = await fetch_new_certs(["modgov"])
            self.assertIsInstance(results, list)
            if results:
                self.assertEqual(results[0]["source"], "crtsh")
                self.assertIn("domain", results[0])

    async def test_otx_fetch(self):
        mock_pulse_data = {
            "results": [
                {
                    "id": "pulse-123",
                    "name": "APT36 Campaign",
                    "tags": ["apt36", "pakistan"],
                    "indicators": [
                        {"type": "domain", "indicator": "modgov-portal.xyz"},
                    ],
                }
            ]
        }
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mock_pulse_data
            mock_res.raise_for_status = MagicMock()
            mock_get.return_value = mock_res

            results = await fetch_apt36_iocs()
            self.assertIsInstance(results, list)
            if results:
                self.assertEqual(results[0]["source"], "otx")
                self.assertEqual(results[0]["domain"], "modgov-portal.xyz")

    async def test_urlhaus_fetch(self):
        mock_urlhaus_data = {
            "urls": [
                {
                    "url": "http://modindia-login.online/payload.exe",
                    "host": "modindia-login.online",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["apt36"],
                }
            ]
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mock_urlhaus_data
            mock_res.raise_for_status = MagicMock()
            mock_post.return_value = mock_res

            results = await fetch_recent_malware_urls()
            self.assertIsInstance(results, list)
            if results:
                self.assertEqual(results[0]["source"], "urlhaus")
                self.assertIn("modindia-login.online", results[0]["domain"])

    async def test_circl_pdns(self):
        ndjson_data = '{"rrname": "nic.in", "rrtype": "NS", "rdata": "ns1.nic.in", "time_first": 1500000000, "time_last": 1600000000}\n'
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.text = ndjson_data
            mock_res.raise_for_status = MagicMock()
            mock_get.return_value = mock_res

            results = await query_pdns("nic.in")
            self.assertIsInstance(results, list)
            self.assertTrue(len(results) >= 1)
            self.assertEqual(results[0]["rrtype"], "NS")


    async def test_malwarebazaar_fetch(self):
        mb_data = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "file_name": "boss_update.elf",
                    "file_type": "elf",
                    "tags": ["apt36", "bosslinux"],
                    "first_seen": "2026-08-01 12:00:00",
                }
            ],
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mb_data
            mock_res.raise_for_status = MagicMock()
            mock_post.return_value = mock_res

            results = await fetch_boss_samples()
            self.assertIsInstance(results, list)
            self.assertGreaterEqual(len(results), 1)
            self.assertEqual(results[0]["source"], "malwarebazaar")


if __name__ == "__main__":
    unittest.main()
