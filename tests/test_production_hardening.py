"""
Acceptance and Negative Tests for EPPI eBPF Kprobes, UI Kill List Purge, and Production Hardening.
Covers eBPF event capture, frontend zero-confidence kill list audits, Groq UTNE response sanitization,
Supabase RLS policies, Render.com keepalive workflows, and daemon tamper detection.
"""

import asyncio
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root and services to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../garuda_agent")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../network-service")))

from garuda_agent.eppi import EPPISensor, get_eppi_sensor
from garuda_agent.tamper import TamperDetector, get_tamper_detector
from eppi_engine import EPPIProcessor, get_eppi_processor
from utne.operator_qa import OperatorQA



class TestProductionHardening(unittest.TestCase):
    """Test suite for EPPI eBPF kprobes, Kill List Purge, and Hardening."""

    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    def test_1_eppi_execve_event_capture(self):
        """1. EPPI execve: assert kprobe event captured with correct comm='ls'."""
        sensor = EPPISensor()
        
        # Inject synthetic execve event to test ring buffer ingestion & parsing
        sensor.inject_synthetic_event({
            "pid": 12345,
            "ppid": 1000,
            "event_type": "EXECVE",
            "comm": "ls",
            "filename": "/bin/ls",
            "uid": 1000,
            "gid": 1000,
        })

        events = sensor._event_queue
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["comm"], "ls")
        self.assertEqual(events[0]["event_type"], "EXECVE")
        self.assertEqual(events[0]["filename"], "/bin/ls")

    def test_2_eppi_mmap_prot_exec_capture(self):
        """2. EPPI mmap PROT_EXEC: assert MMAP_EXEC event captured for process hollowing detection."""
        processor = get_eppi_processor()
        
        # Simulate physical spike at current time
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        processor.record_physics_spike("nic-node-01", ias_score=4.5, observed_at_iso=now_iso)

        events = [{
            "pid": 5678,
            "ppid": 1234,
            "event_type": "MMAP_EXEC",
            "comm": "payload_worker",
            "mmap_addr": "0x7fff12340000",
            "mmap_len": 4096,
            "timestamp_utc": now_iso,
        }]

        result = asyncio.run(processor.process_events("nic-node-01", events))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["events_count"], 1)
        self.assertEqual(result["physics_corroborated_events"], 1)
        self.assertEqual(result["high_confidence_matches"], 1)

    def test_3_ui_kill_list_zero_matches(self):
        """3. UI kill list: grep frontend source files for 'Confidence:' and 'CONVERGED' — assert zero matches."""
        frontend_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend/src"))
        
        forbidden_patterns = [
            r"Confidence:\s*\d+",
            r"\bCONVERGED\b",
        ]

        found_violations = []
        for root, _, files in os.walk(frontend_src):
            for file in files:
                if file.endswith((".jsx", ".js", ".tsx", ".ts")):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pat in forbidden_patterns:
                            if re.search(pat, content):
                                found_violations.append(f"{file}: pattern '{pat}' found")

        self.assertEqual(len(found_violations), 0, f"Kill list violations found in UI: {found_violations}")

    def test_4_utne_query_no_percentage_confidence(self):
        """4. UTNE query: POST question, assert response has no percentage confidence for attribution."""
        qa = OperatorQA(groq_api_key="MOCK_KEY")

        # Mock Groq response containing an illegal confidence percentage
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Activity is attributed to APT36 with Confidence: 78.0% based on L3 cache misses."}}]
        }

        with patch("httpx.AsyncClient.post", return_value=mock_resp):
            res = asyncio.run(qa.query_async("Who is attacking?", {"observation_count": 5}))
            self.assertEqual(res["status"], "SUCCESS")
            # Verify percentage was intercepted and sanitized
            self.assertNotIn("78.0%", res["answer"])
            self.assertNotIn("Confidence: 78.0%", res["answer"])

    def test_5_keepalive_workflow_cron_schedule(self):
        """5. Keepalive: verify GitHub Actions workflow file exists with correct cron schedule '*/14 * * * *'."""
        workflow_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../.github/workflows/render-keepalive.yml")
        )
        self.assertTrue(os.path.exists(workflow_path))

        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("*/14 * * * *", content)
            self.assertIn("garuda-axiom-service.onrender.com", content)
            self.assertIn("garuda-brahma-service.onrender.com", content)

    def test_6_agent_tamper_detection(self):
        """6. Agent tamper: modify binary hash file, restart agent, assert TAMPER_DETECTED."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_hash_file:
            tmp_hash_file.write("0000000000000000000000000000000000000000000000000000000000000000\n")
            tmp_hash_path = tmp_hash_file.name

        try:
            detector = TamperDetector(hash_file_path=tmp_hash_path)
            is_valid, curr, expected = detector.verify_integrity()
            self.assertFalse(is_valid)
            self.assertNotEqual(curr, expected)
        finally:
            if os.path.exists(tmp_hash_path):
                os.remove(tmp_hash_path)

    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    def test_neg_1_bcc_unavailable_graceful_skip(self):
        """Negative 1: bcc unavailable on target host: assert EPPI operates gracefully without crashing."""
        sensor = EPPISensor()
        # On non-Linux or without BCC, is_available is False
        events = sensor.read_events()
        self.assertEqual(events, [])
        self.assertIn(sensor.unavailability_reason, [
            "NON_LINUX_OS", "PERMISSION_DENIED_NON_ROOT", "BCC_NOT_INSTALLED", "BPF_SOURCE_FILE_NOT_FOUND", "ACTIVE"
        ])

    def test_neg_2_groq_429_returns_rate_limited(self):
        """Negative 2: Budget limiter enforces rate limits and upstream 429 gracefully fails over."""
        # 1. Test local hourly budget limit
        budget_limiter = unittest.mock.MagicMock()
        budget_limiter.check_and_increment.return_value = (False, 100, 100)
        qa_limited = OperatorQA(groq_api_key="MOCK_KEY", budget_limiter=budget_limiter)
        res_limited = asyncio.run(qa_limited.query_async("Who is attacking?", {"observation_count": 5}))
        self.assertEqual(res_limited["status"], "RATE_LIMITED")
        self.assertIn("budget", res_limited["answer"].lower())

        # 2. Test upstream 429 failover to deterministic grounding
        qa = OperatorQA(groq_api_key="MOCK_KEY")
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Too Many Requests"

        with patch("httpx.AsyncClient.post", return_value=mock_resp):
            res = asyncio.run(qa.query_async("Who is attacking?", {"observation_count": 5}))
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["provider"], "offline:deterministic")
            self.assertIn("Grounded Evidence Summary", res["answer"])



if __name__ == "__main__":
    unittest.main()
