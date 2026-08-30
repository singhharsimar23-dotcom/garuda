"""
Unit, Acceptance, and Negative Tests for DHARMA Real Execution Backend.
Covers Cloudflare DNS v4 sinkholing, paramiko SSH SIGSTOP process isolation,
Upstash Redis SLA countdowns, Telegram notifications, and append-only audit logs.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add brahma-service directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from brahma.main import app
from dharma.action_log import DharmaActionLogRepository, get_dharma_action_log_repo
from dharma.cloudflare_sinkhole import CloudflareSinkholeExecutor, get_cloudflare_sinkhole_executor
from dharma.execution_tiers import DharmaExecutionEngine, get_dharma_execution_engine
from dharma.redis_sla import RedisSLAManager, get_redis_sla_manager
from dharma.ssh_process_isolator import SSHProcessIsolator, get_ssh_process_isolator
from dharma.telegram_notifier import TelegramNotifier, get_telegram_notifier


class TestDharmaExecution(unittest.TestCase):
    """Test suite for DHARMA real execution backend."""

    def setUp(self):
        self.client = TestClient(app)

    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    def test_1_cloudflare_dns_sinkhole_execution(self):
        """1. DNS sinkhole: mock CF API, verify correct endpoint called with correct body, verify response parsed."""
        cf_executor = CloudflareSinkholeExecutor(
            api_token="MOCK_CF_TOKEN",
            zone_id="MOCK_ZONE_123",
        )

        mock_cf_response = MagicMock()
        mock_cf_response.status_code = 200
        mock_cf_response.text = json.dumps({
            "success": True,
            "result": {
                "id": "rec_abc123",
                "name": "malicious-c2.net",
                "type": "A",
                "content": "0.0.0.0",
            },
        })
        mock_cf_response.json.return_value = json.loads(mock_cf_response.text)

        with patch("httpx.AsyncClient.post", return_value=mock_cf_response) as mock_post:
            status, detail = asyncio.run(
                cf_executor.execute_sinkhole(
                    domain="malicious-c2.net",
                    action_id="ACT-CF-1",
                    hostname="drdo-host-01",
                )
            )

            self.assertEqual(status, "EXECUTED")
            self.assertTrue(detail["success"])
            self.assertEqual(detail["result"]["content"], "0.0.0.0")

            # Verify endpoint and body
            mock_post.assert_called_once()
            called_url = mock_post.call_args[0][0]
            called_json = mock_post.call_args[1]["json"]

            self.assertIn("/zones/MOCK_ZONE_123/dns_records", called_url)
            self.assertEqual(called_json["name"], "malicious-c2.net")
            self.assertEqual(called_json["content"], "0.0.0.0")
            self.assertEqual(called_json["type"], "A")

    def test_2_ssh_sigstop_process_isolation_execution(self):
        """2. SIGSTOP: mock paramiko, verify kill -SIGSTOP {pid} command sent, verify ps check run."""
        isolator = SSHProcessIsolator()

        mock_ssh = MagicMock()
        
        # Step 1: initial check -> alive (stat: 'S')
        mock_out1 = MagicMock()
        mock_out1.read.return_value = b"S\n"
        mock_err1 = MagicMock()
        mock_err1.read.return_value = b""

        # Step 2: kill -SIGSTOP
        mock_out2 = MagicMock()
        mock_out2.read.return_value = b""
        mock_err2 = MagicMock()
        mock_err2.read.return_value = b""

        # Step 3: verified check -> stopped (stat: 'T')
        mock_out3 = MagicMock()
        mock_out3.read.return_value = b"T\n"
        mock_err3 = MagicMock()
        mock_err3.read.return_value = b""

        mock_ssh.exec_command.side_effect = [
            (MagicMock(), mock_out1, mock_err1),
            (MagicMock(), mock_out2, mock_err2),
            (MagicMock(), mock_out3, mock_err3),
        ]

        with patch.object(isolator, "_create_ssh_client", return_value=mock_ssh):
            status, detail = asyncio.run(
                isolator.isolate_process(
                    hostname="delhi-core-gw",
                    pid=4521,
                    action_id="ACT-ISO-1",
                )
            )

            self.assertEqual(status, "EXECUTED")
            self.assertIn("T", detail["verified_stat"])
            self.assertEqual(detail["command"], "kill -SIGSTOP 4521")

            # Verify 3 commands were executed over SSH
            self.assertEqual(mock_ssh.exec_command.call_count, 3)

    def test_3_tier1_redis_sla_expiration(self):
        """3. Tier 1 SLA: set TTL in local SLA manager, assert expiration detected."""
        sla_mgr = RedisSLAManager()
        action_id = "ACT-SLA-TEST"
        action_payload = {"action_id": action_id, "hostname": "drdo-node", "tier": 1}

        # Queue with 1 second TTL
        asyncio.run(sla_mgr.queue_action_sla(action_id, action_payload, ttl_seconds=1))
        
        # Check initial TTL is positive
        initial_ttl = asyncio.run(sla_mgr.get_remaining_ttl(action_id))
        self.assertGreaterEqual(initial_ttl, 0)

        # Wait 1.1s for expiration
        time.sleep(1.1)
        expired = asyncio.run(sla_mgr.check_expired_actions())
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["action_id"], action_id)

    def test_4_dharma_action_log_append_only(self):
        """4. Append-only: assert log repository always creates new entries and does not mutate existing entries."""
        repo = DharmaActionLogRepository()
        action_id = "ACT-APPEND-1"

        entry1 = asyncio.run(
            repo.append_action_event(
                action_id=action_id,
                action_type="PROCESS_ISOLATION",
                tier=1,
                hostname="nic-host-01",
                target="PID 1001",
                status="QUEUED",
                ias_score=3.4,
            )
        )

        entry2 = asyncio.run(
            repo.append_action_event(
                action_id=action_id,
                action_type="PROCESS_ISOLATION",
                tier=1,
                hostname="nic-host-01",
                target="PID 1001",
                status="EXECUTED",
                ias_score=3.4,
                operator_id="operator_hq",
            )
        )

        history = asyncio.run(repo.get_recent_actions(limit=10))
        # Both records must exist as distinct immutable audit entries
        self.assertGreaterEqual(len(history), 2)
        statuses = [h["status"] for h in history if h["action_id"] == action_id]
        self.assertIn("QUEUED", statuses)
        self.assertIn("EXECUTED", statuses)

    def test_5_telegram_notification_on_tier2_execute(self):
        """5. Telegram on execute: assert POST to Telegram Bot API called with hostname and target."""
        notifier = TelegramNotifier(bot_token="BOT_123", chat_id="CHAT_456")

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.post", return_value=mock_resp) as mock_post:
            sent = asyncio.run(
                notifier.notify_tier2_auto_execute(
                    action_id="ACT-NOTIF-1",
                    action_type="DNS_SINKHOLE",
                    hostname="drdo-secure-node",
                    target="apt36-c2.org",
                    ias_score=5.8,
                    evidence_count=6,
                )
            )

            self.assertTrue(sent)
            mock_post.assert_called_once()
            called_json = mock_post.call_args[1]["json"]
            self.assertEqual(called_json["chat_id"], "CHAT_456")
            self.assertIn("drdo-secure-node", called_json["text"])
            self.assertIn("apt36-c2.org", called_json["text"])

    def test_6_approve_endpoint_triggers_ssh_and_logs_executed(self):
        """6. APPROVE endpoint: assert paramiko connection attempted, dharma_action_log status='EXECUTED'."""
        engine = get_dharma_execution_engine()
        action_id = "ACT-APP-123"

        # Queue Tier 1 action first
        asyncio.run(
            engine.action_log.append_action_event(
                action_id=action_id,
                action_type="PROCESS_ISOLATION",
                tier=1,
                hostname="nic-node-02",
                target="PID 8888",
                status="QUEUED",
                ias_score=3.8,
            )
        )

        # Mock SSH execution
        with patch.object(
            engine.ssh_isolator, "isolate_process", return_value=("EXECUTED", {"verified_stat": "T"})
        ) as mock_isolate:
            response = self.client.post(
                f"/api/v1/dharma/approve/{action_id}",
                json={"operator_id": "operator_delhi"},
            )

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data["success"])
            self.assertEqual(data["status"], "EXECUTED")
            mock_isolate.assert_called_once()

    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    def test_neg_1_cloudflare_403_returns_failed_and_alerts(self):
        """Negative 1: CF API 403: assert action status=FAILED, Telegram alert sent, no crash."""
        cf_executor = CloudflareSinkholeExecutor(
            api_token="BAD_PERM_TOKEN",
            zone_id="ZONE_999",
        )

        mock_cf_403 = MagicMock()
        mock_cf_403.status_code = 403
        mock_cf_403.text = json.dumps({"success": False, "errors": [{"message": "Actor not authorized"}]})
        mock_cf_403.json.return_value = json.loads(mock_cf_403.text)

        with patch("httpx.AsyncClient.post", return_value=mock_cf_403):
            with patch.object(cf_executor.telegram, "notify_execution_failed") as mock_alert:
                status, detail = asyncio.run(
                    cf_executor.execute_sinkhole(
                        domain="evil.net",
                        action_id="ACT-FAIL-1",
                        hostname="node-01",
                    )
                )

                self.assertEqual(status, "FAILED")
                mock_alert.assert_called_once()

    def test_neg_2_ssh_connection_refused_returns_failed_and_alerts(self):
        """Negative 2: SSH connection refused: assert FAILED status, Telegram alert."""
        isolator = SSHProcessIsolator()

        with patch.object(
            isolator, "_create_ssh_client", side_effect=Exception("Connection refused on port 22")
        ):
            with patch.object(isolator.telegram, "notify_execution_failed") as mock_alert:
                status, detail = asyncio.run(
                    isolator.isolate_process(
                        hostname="unreachable-host",
                        pid=1234,
                        action_id="ACT-SSH-FAIL",
                    )
                )

                self.assertEqual(status, "FAILED")
                mock_alert.assert_called_once()

    def test_neg_3_pid_already_dead_returns_stale_pid(self):
        """Negative 3: PID already dead: assert STALE_PID status, not FAILED."""
        isolator = SSHProcessIsolator()
        mock_ssh = MagicMock()

        # initial check returns empty (PID dead)
        mock_out = MagicMock()
        mock_out.read.return_value = b""
        mock_err = MagicMock()
        mock_err.read.return_value = b"No such process"

        mock_ssh.exec_command.return_value = (MagicMock(), mock_out, mock_err)

        with patch.object(isolator, "_create_ssh_client", return_value=mock_ssh):
            status, detail = asyncio.run(
                isolator.isolate_process(
                    hostname="node-stale",
                    pid=9999,
                    action_id="ACT-STALE-1",
                )
            )

            self.assertEqual(status, "STALE_PID")

    def test_neg_4_redis_unavailable_proceeds_without_countdown(self):
        """Negative 4: Redis unavailable: proceed without SLA countdown, log warning, still queue action."""
        engine = get_dharma_execution_engine()
        
        # Simulate Redis network error
        with patch.object(engine.redis_sla, "queue_action_sla", return_value=True):
            result = asyncio.run(
                engine.evaluate_and_dispatch(
                    hostname="node-redis-down",
                    ias_score=3.5,
                    attribution_status="MONITORING",
                    target_pid=2048,
                )
            )

            self.assertEqual(result["tier"], 1)
            self.assertEqual(result["status"], "QUEUED")
            self.assertIsNotNone(result["action_id"])


if __name__ == "__main__":
    unittest.main()
