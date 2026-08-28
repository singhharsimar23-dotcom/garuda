"""
GARUDA Session 15 Acceptance Tests — Campaign Lifecycle Tracker

Tests cover DNS/HTTP state detection, sinkhole/transfer alerts, cluster burn
detection, lead-time metrics, and sweep idempotency.
"""

import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "lifecycle"


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


class TestNxdomainReturnsDead(unittest.IsolatedAsyncioTestCase):
    async def test_nxdomain_returns_dead(self):
        from garuda.modules.lifecycle.tracker import LifecycleState, check_lifecycle

        with patch(
            "garuda.modules.lifecycle.tracker._resolve_a_records",
            new_callable=AsyncMock,
            return_value=([], True),
        ):
            result = await check_lifecycle("dead-domain.example", "1.2.3.4", 12345)

        self.assertEqual(result["current_state"], LifecycleState.DEAD.value)
        self.assertIsNone(result["current_ip"])


class TestParkingTextDetected(unittest.IsolatedAsyncioTestCase):
    async def test_parking_text_detected(self):
        from garuda.modules.lifecycle.tracker import LifecycleState, check_lifecycle

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>This domain is parked by GoDaddy</body></html>"

        with patch(
            "garuda.modules.lifecycle.tracker._resolve_a_records",
            new_callable=AsyncMock,
            return_value=(["8.8.8.8"], False),
        ), patch(
            "garuda.modules.lifecycle.tracker._fetch_ip_asn",
            new_callable=AsyncMock,
            return_value=15169,
        ), patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await check_lifecycle("parked.example", "8.8.8.8", 15169)

        self.assertEqual(result["current_state"], LifecycleState.PARKED.value)


class TestSinkholeAsnDetected(unittest.IsolatedAsyncioTestCase):
    async def test_sinkhole_asn_detected(self):
        from garuda.modules.lifecycle.tracker import LifecycleState, check_lifecycle, load_sinkhole_asns

        load_sinkhole_asns()
        fixture = _load_fixture("ip_api_sinkhole.json")

        with patch(
            "garuda.modules.lifecycle.tracker._resolve_a_records",
            new_callable=AsyncMock,
            return_value=(["192.0.2.100"], False),
        ), patch(
            "garuda.modules.lifecycle.tracker._fetch_ip_asn",
            new_callable=AsyncMock,
            return_value=393861,
        ):
            result = await check_lifecycle("sinkholed.example", "1.2.3.4", 12345)

        self.assertEqual(result["current_state"], LifecycleState.SINKHOLED.value)
        self.assertEqual(result["current_asn"], 393861)


class TestTransferredDetection(unittest.IsolatedAsyncioTestCase):
    async def test_transferred_detection(self):
        from garuda.modules.lifecycle.tracker import LifecycleState, run_lifecycle_sweep

        alert = {
            "id": "alert-transferred-001",
            "domain": "c2-relocated.example",
            "hosting_ip": "1.2.3.4",
            "hosting_asn": 15169,
            "cluster_id": "cluster-a",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "lifecycle_state": "active",
            "status": "confirmed",
        }

        from garuda.database import _IN_MEMORY_LIFECYCLE_ALERTS
        _IN_MEMORY_LIFECYCLE_ALERTS.clear()
        _IN_MEMORY_LIFECYCLE_ALERTS.append(dict(alert))

        transferred_result = {
            "domain": alert["domain"],
            "current_state": LifecycleState.TRANSFERRED.value,
            "current_ip": "203.0.113.50",
            "current_asn": 4134,
            "ip_changed": True,
            "asn_changed": True,
            "days_alive": 5,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        with patch(
            "garuda.modules.lifecycle.tracker._fetch_sweep_candidates",
            new_callable=AsyncMock,
            return_value=[alert],
        ), patch(
            "garuda.modules.lifecycle.tracker.check_lifecycle",
            new_callable=AsyncMock,
            return_value=transferred_result,
        ), patch(
            "garuda.modules.lifecycle.tracker._dispatch_transferred_alert",
            new_callable=AsyncMock,
        ) as mock_alert:
            result = await run_lifecycle_sweep()

        self.assertEqual(result["transferred"], 1)
        mock_alert.assert_called_once()


class TestClusterBurnDetection(unittest.IsolatedAsyncioTestCase):
    async def test_cluster_burn_detection(self):
        from garuda.modules.lifecycle.tracker import LifecycleState, run_lifecycle_sweep

        now = datetime.now(timezone.utc)
        cluster_id = "apt36-cluster-burn"
        alerts = []
        for i in range(3):
            alerts.append({
                "id": f"burn-alert-{i}",
                "domain": f"burn{i}.example",
                "hosting_ip": f"10.0.0.{i}",
                "hosting_asn": 12345,
                "cluster_id": cluster_id,
                "detected_at": (now - timedelta(hours=12)).isoformat(),
                "lifecycle_state": "active",
                "status": "confirmed",
            })

        dead_result = {
            "current_state": LifecycleState.DEAD.value,
            "current_ip": None,
            "current_asn": None,
            "ip_changed": True,
            "asn_changed": True,
            "days_alive": 2,
            "assessed_at": now.isoformat(),
        }

        with patch(
            "garuda.modules.lifecycle.tracker._fetch_sweep_candidates",
            new_callable=AsyncMock,
            return_value=alerts,
        ), patch(
            "garuda.modules.lifecycle.tracker.check_lifecycle",
            new_callable=AsyncMock,
            return_value=dead_result,
        ), patch(
            "garuda.modules.lifecycle.tracker._dispatch_cluster_burn_alert",
            new_callable=AsyncMock,
        ) as mock_burn:
            result = await run_lifecycle_sweep()

        self.assertEqual(result["dead"], 3)
        mock_burn.assert_called_once()
        args = mock_burn.call_args[0]
        self.assertEqual(args[0], cluster_id)
        self.assertEqual(args[1], 3)


class TestLeadTimePositive(unittest.IsolatedAsyncioTestCase):
    async def test_lead_time_positive(self):
        from garuda.modules.lifecycle.effectiveness import compute_lead_time_metrics

        mock_client = MagicMock()
        mock_client.table.return_value.select.return_value.eq.return_value.execute.return_value = MagicMock(
            data=[
                {
                    "id": "1",
                    "cluster_id": "c1",
                    "detected_at": "2026-01-01T00:00:00+00:00",
                    "public_disclosure_date": "2026-01-15",
                    "lifecycle_state": "active",
                    "status": "confirmed",
                },
                {
                    "id": "2",
                    "cluster_id": "c1",
                    "detected_at": "2026-01-20T00:00:00+00:00",
                    "public_disclosure_date": "2026-01-10",
                    "lifecycle_state": "dead",
                    "status": "confirmed",
                },
            ]
        )

        with patch(
            "garuda.modules.lifecycle.effectiveness.set_cached_json",
            new_callable=AsyncMock,
        ):
            metrics = await compute_lead_time_metrics(mock_client)

        self.assertEqual(metrics["count_positive_lead_time"], 1)
        self.assertEqual(metrics["total_with_disclosure_date"], 2)
        self.assertGreater(metrics["mean_lead_time_days"], 0)


class TestIdempotentSweep(unittest.IsolatedAsyncioTestCase):
    async def test_idempotent(self):
        from garuda.modules.lifecycle.tracker import LifecycleState, run_lifecycle_sweep

        from garuda.database import _IN_MEMORY_LIFECYCLE_ALERTS
        _IN_MEMORY_LIFECYCLE_ALERTS.clear()
        _IN_MEMORY_LIFECYCLE_ALERTS.append({
            "id": "dead-alert-001",
            "domain": "already-dead.example",
            "hosting_ip": "1.2.3.4",
            "hosting_asn": 12345,
            "cluster_id": "solo",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "lifecycle_state": LifecycleState.DEAD.value,
            "status": "confirmed",
        })

        with patch(
            "garuda.modules.lifecycle.tracker._get_supabase_client",
            return_value=None,
        ), patch(
            "garuda.modules.lifecycle.tracker.check_lifecycle",
            new_callable=AsyncMock,
        ) as mock_check, patch(
            "garuda.modules.lifecycle.tracker._dispatch_cluster_burn_alert",
            new_callable=AsyncMock,
        ) as mock_burn:
            result = await run_lifecycle_sweep()

        self.assertEqual(result["swept"], 0)
        mock_check.assert_not_called()
        mock_burn.assert_not_called()


class TestIpApiFixtureValidation(unittest.TestCase):
    def test_ip_api_fixture_validates(self):
        from garuda.modules.lifecycle.tracker import IpApiResponse, parse_asn_from_ip_api

        for name in ("ip_api_valid.json", "ip_api_sinkhole.json", "ip_api_transferred.json"):
            fixture = _load_fixture(name)
            parsed = IpApiResponse.model_validate(fixture)
            self.assertEqual(parsed.status, "success")
            self.assertIsNotNone(parse_asn_from_ip_api(parsed.as_field))


if __name__ == "__main__":
    unittest.main()
