"""
GARUDA Session 13 Acceptance Tests — ANY.RUN Sandbox Integration
"""

import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "sandbox"


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


class TestShouldSubmit(unittest.IsolatedAsyncioTestCase):
    """Gate logic for sandbox submission."""

    async def test_score_threshold(self):
        from garuda.modules.sandbox.trigger import should_submit

        alert = {"domain": "evil.space", "score": 59}
        result = await should_submit(alert, redis_client=None)
        self.assertFalse(result)

    @patch("garuda.modules.sandbox.trigger._has_downloadable_content", new_callable=AsyncMock, return_value=False)
    @patch("garuda.modules.sandbox.trigger._domain_resolves", new_callable=AsyncMock, return_value=True)
    async def test_content_type_gate(self, _resolve, _download):
        from garuda.modules.sandbox.trigger import should_submit

        alert = {"domain": "evil.space", "score": 65}
        result = await should_submit(alert, redis_client=None)
        self.assertFalse(result)

    @patch("garuda.modules.sandbox.trigger._was_domain_submitted_recently", new_callable=AsyncMock, return_value=False)
    @patch("garuda.modules.sandbox.trigger._has_downloadable_content", new_callable=AsyncMock, return_value=True)
    @patch("garuda.modules.sandbox.trigger._domain_resolves", new_callable=AsyncMock, return_value=True)
    async def test_daily_rate_limit(self, _resolve, _download, _dup):
        from garuda.modules.sandbox.anyrun_client import MAX_SUBMISSIONS_PER_DAY
        from garuda.modules.sandbox.trigger import should_submit

        redis = AsyncMock()
        redis.get = AsyncMock(return_value=str(MAX_SUBMISSIONS_PER_DAY))

        alert = {"domain": "evil.space", "score": 70}
        result = await should_submit(alert, redis_client=redis)
        self.assertFalse(result)

    @patch("garuda.modules.sandbox.trigger._get_daily_submission_count", new_callable=AsyncMock, return_value=0)
    @patch("garuda.modules.sandbox.trigger._has_downloadable_content", new_callable=AsyncMock, return_value=True)
    @patch("garuda.modules.sandbox.trigger._domain_resolves", new_callable=AsyncMock, return_value=True)
    async def test_duplicate_gate(self, _resolve, _download, _daily):
        from garuda.modules.sandbox.trigger import should_submit

        redis = AsyncMock()
        redis.get = AsyncMock(return_value="1")

        alert = {"domain": "evil.space", "score": 70}
        with patch(
            "garuda.modules.sandbox.trigger._was_domain_submitted_recently",
            new_callable=AsyncMock,
            return_value=True,
        ):
            result = await should_submit(alert, redis_client=redis)
        self.assertFalse(result)


class TestAnyRunClient(unittest.IsolatedAsyncioTestCase):
    """ANY.RUN API client unit tests."""

    async def test_task_id_extracted(self):
        from garuda.modules.sandbox.anyrun_client import submit_url

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"taskid": "abc-123-task"}}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("garuda.modules.sandbox.anyrun_client.httpx.AsyncClient", return_value=mock_client):
            task_id = await submit_url("https://evil.space/malware.zip", "test-api-key")

        self.assertEqual(task_id, "abc-123-task")

    async def test_poll_timeout(self):
        from garuda.modules.sandbox.anyrun_client import poll_results

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"status": "running"}}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("garuda.modules.sandbox.anyrun_client.httpx.AsyncClient", return_value=mock_client):
            with patch("garuda.modules.sandbox.anyrun_client.asyncio.sleep", new_callable=AsyncMock):
                with patch("garuda.modules.sandbox.anyrun_client.asyncio.get_event_loop") as mock_loop:
                    clock = [0.0]

                    def fake_time():
                        clock[0] += 200.0
                        return clock[0]

                    mock_loop.return_value.time = fake_time
                    result = await poll_results("task-xyz", "test-key", timeout_sec=180)

        self.assertIsNone(result)

    def test_boss_linux_detection(self):
        from garuda.modules.sandbox.anyrun_client import extract_iocs

        fixture = _load_fixture("anyrun_sample_response.json")
        iocs = extract_iocs(fixture, task_id="task-001")
        self.assertTrue(iocs["is_boss_linux"])
        self.assertIn("payload.desktop", iocs["dropped_filenames"])

    def test_no_raw_binary_storage(self):
        """sandbox_analyses stores URLs only — no binary columns."""
        from garuda.modules.sandbox.anyrun_client import extract_iocs

        fixture = _load_fixture("anyrun_sample_response.json")
        iocs = extract_iocs(fixture, task_id="task-001")

        for value in iocs.values():
            if isinstance(value, str):
                self.assertNotIn("\x00", value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        self.assertLess(len(item.encode("utf-8")), 10_000)

        allowed_keys = {
            "c2_domains", "c2_ips", "mitre_techniques", "dropped_hashes",
            "dropped_filenames", "is_boss_linux", "verdict", "report_url",
        }
        self.assertEqual(set(iocs.keys()), allowed_keys)


if __name__ == "__main__":
    unittest.main()
