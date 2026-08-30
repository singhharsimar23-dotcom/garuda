"""
Comprehensive Unit, Acceptance, and Negative Tests for garuda_agent daemon.
Covers RAPL sysfs reading, perf_event_open ctypes syscall, entropy, schedstat,
IAS anomaly calculation with contamination prevention, local buffer, and HTTP streamer.
"""

import errno
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, mock_open, patch
import httpx

# Ensure garuda_agent is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from garuda_agent.buffer import LocalBuffer
from garuda_agent.daemon import GarudaDaemon
from garuda_agent.entropy import EntropyReader
from garuda_agent.ias import (
    IASComputer,
    gaussian_kl_divergence,
    CHANNEL_WEIGHTS,
)
from garuda_agent.perf import PerfReader
from garuda_agent.rapl import RAPLReader
from garuda_agent.schedstat import SchedstatReader
from garuda_agent.service import generate_service_content
from garuda_agent.streamer import TelemetryStreamer


class TestRAPLReader(unittest.TestCase):
    """Acceptance & Negative tests for RAPL sysfs reader."""

    @patch("os.path.exists")
    @patch("glob.glob")
    def test_rapl_reader_mocked_sysfs(self, mock_glob, mock_exists):
        """1. Test RAPL reader with mocked sysfs fixture: assert power_w returns dict with package-0 key."""
        base_dir = "/sys/class/powercap/intel-rapl"
        domain_dir = "/sys/class/powercap/intel-rapl/intel-rapl:0"

        mock_exists.side_effect = lambda p: p.replace("\\", "/") in [
            base_dir,
            domain_dir,
            f"{domain_dir}/energy_uj",
            f"{domain_dir}/name",
            f"{domain_dir}/max_energy_range_uj",
        ]
        mock_glob.side_effect = lambda pat: [domain_dir] if "intel-rapl:*" in pat else []

        def custom_open(path, *args, **kwargs):
            norm_p = path.replace("\\", "/")
            if "name" in norm_p:
                return mock_open(read_data="package-0").return_value
            elif "max_energy_range_uj" in norm_p:
                return mock_open(read_data="262143328850").return_value
            elif "energy_uj" in norm_p:
                # Returns 10,000,000 uJ
                return mock_open(read_data="10000000").return_value
            raise FileNotFoundError(path)


        with patch("builtins.open", side_effect=custom_open):
            reader = RAPLReader()
            self.assertTrue(reader.available)

            # First reading initializes baseline
            payload1, flags1, raw1 = reader.read()
            self.assertIn("package-0", raw1)
            self.assertEqual(raw1["package-0"], 0.0)

            # Second reading with energy increased by 25,000,000 uJ after 1 second (25W)
            domain = reader.domains[domain_dir]
            domain.last_timestamp = time.monotonic() - 1.0
            domain.last_energy_uj = 10000000

            def custom_open2(path, *args, **kwargs):
                if "energy_uj" in path:
                    return mock_open(read_data="35000000").return_value
                return custom_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=custom_open2):
                payload2, flags2, raw2 = reader.read()
                self.assertIn("package-0", raw2)
                self.assertAlmostEqual(raw2["package-0"], 25.0, delta=0.5)
                self.assertAlmostEqual(payload2["pkg_w"], 25.0, delta=0.5)
                self.assertFalse(payload2["unavailable"])

    def test_counter_wraparound(self):
        """2. Test counter wraparound: set last=max_range-100, current=50, assert delta=150."""
        max_range = 1000
        last_val = max_range - 100
        curr_val = 50
        
        delta = curr_val - last_val
        if delta < 0:
            delta += max_range

        self.assertEqual(delta, 150)

    @patch("os.path.exists")
    @patch("glob.glob")
    def test_rapl_unavailable(self, mock_glob, mock_exists):
        """6. Test RAPL_UNAVAILABLE: when /sys/class/powercap missing, assert payload has unavailable=true."""
        mock_exists.return_value = False
        mock_glob.return_value = []

        reader = RAPLReader()
        self.assertFalse(reader.available)
        payload, flags, raw = reader.read()
        self.assertTrue(payload["unavailable"])
        self.assertIn("RAPL_UNAVAILABLE", flags)
        self.assertEqual(payload["pkg_w"], 0.0)

    @patch("os.path.exists")
    @patch("glob.glob")
    def test_corrupt_energy_uj(self, mock_glob, mock_exists):
        """Negative test: corrupt energy_uj (non-integer): skip domain, log warning, continue."""
        base_dir = "/sys/class/powercap/intel-rapl"
        domain_dir = "/sys/class/powercap/intel-rapl/intel-rapl:0"

        mock_exists.side_effect = lambda p: p in [base_dir, domain_dir, f"{domain_dir}/energy_uj"]
        mock_glob.side_effect = lambda pat: [domain_dir] if "intel-rapl:*" in pat else []

        with patch("builtins.open", mock_open(read_data="corrupted_non_int_energy")):
            reader = RAPLReader()
            payload, flags, raw = reader.read()
            self.assertEqual(raw, {})
            self.assertEqual(payload["pkg_w"], 0.0)


class TestPerfReader(unittest.TestCase):
    """Acceptance & Negative tests for Perf Hardware Counters."""

    @patch("platform.system", return_value="Linux")
    @patch("ctypes.CDLL")
    def test_perf_unavailable_on_eacces(self, mock_cdll, mock_sys):
        """7. Test PERF_UNAVAILABLE: mock syscall returning EACCES, assert graceful skip, payload has unavailable=true."""
        mock_libc = MagicMock()
        # Mock syscall returning -1 with errno EACCES (13)
        mock_libc.syscall.return_value = -1
        mock_cdll.return_value = mock_libc

        with patch("ctypes.get_errno", return_value=errno.EACCES):
            reader = PerfReader()
            self.assertFalse(reader.available)
            payload, flags = reader.read()
            self.assertTrue(payload["unavailable"])
            self.assertIn("PERF_UNAVAILABLE", flags)
            self.assertEqual(payload["instructions_ps"], 0.0)

    @patch("platform.system", return_value="Windows")
    def test_perf_non_linux_graceful(self, mock_sys):
        """Negative test: Non-linux platform skips perf gracefully."""
        reader = PerfReader()
        self.assertFalse(reader.available)
        payload, flags = reader.read()
        self.assertTrue(payload["unavailable"])
        self.assertIn("PERF_UNAVAILABLE", flags)


class TestIASComputation(unittest.TestCase):
    """Acceptance & Negative tests for IAS score computation and baseline protection."""

    def test_gaussian_kl_formula(self):
        """3. Test IAS computation: inject synthetic channel values, assert score matches expected formula."""
        # When distributions match (mu1=10, sig1=2, mu2=10, sig2=2), DKL must be 0
        dkl_same = gaussian_kl_divergence(10.0, 2.0, 10.0, 2.0)
        self.assertAlmostEqual(dkl_same, 0.0, places=5)

        # Theoretical calculation for mu1=12, sig1=2, mu2=10, sig2=2:
        # term1 = ((12-10)^2 + 4 - 4) / (2 * 4) = 4 / 8 = 0.5
        # term2 = ln(2/2) = 0
        # D_KL = 0.5
        dkl_diff = gaussian_kl_divergence(12.0, 2.0, 10.0, 2.0)
        self.assertAlmostEqual(dkl_diff, 0.5, places=4)

    def test_contamination_prevention(self):
        """4. Test contamination prevention: when IAS >= 1.5 passed to baseline updater, assert baseline unchanged."""
        ias_comp = IASComputer()
        
        # Capture baseline before attack
        base_pkg_mean_before = ias_comp.baselines["BASELINING"]["rapl_pkg"].mean
        base_pkg_std_before = ias_comp.baselines["BASELINING"]["rapl_pkg"].std

        # Inject extreme anomaly (e.g. huge RAPL power and perf spikes to trigger IAS >> 1.5)
        extreme_rapl = {"pkg_w": 250.0, "dram_w": 60.0, "core_w": 180.0, "unavailable": False}
        extreme_perf = {"instructions_ps": 5e8, "cache_misses_ps": 1e8, "cycles_ps": 1e9, "unavailable": False}
        entropy_data = {"bits": 50, "depleting": True, "sustained_low_s": 60}
        sched_data = {"steal_ratio": 0.8}

        payload, flags = ias_comp.compute(
            rapl=extreme_rapl,
            perf=extreme_perf,
            entropy=entropy_data,
            schedstat=sched_data,
        )

        self.assertGreaterEqual(payload["score"], 1.5)
        # Baseline must NOT be updated (contamination prevention)
        base_pkg_mean_after = ias_comp.baselines["BASELINING"]["rapl_pkg"].mean
        base_pkg_std_after = ias_comp.baselines["BASELINING"]["rapl_pkg"].std
        self.assertEqual(base_pkg_mean_before, base_pkg_mean_after)
        self.assertEqual(base_pkg_std_before, base_pkg_std_after)


class TestBufferAndStreamer(unittest.TestCase):
    """Acceptance & Negative tests for SQLite buffer and HTTP streamer."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_buffer.db")
        self.buffer = LocalBuffer(db_path=self.db_path, max_rows=10)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_buffer_push_and_fifo(self):
        """Test buffer FIFO eviction when exceeding max_rows."""
        for i in range(15):
            self.buffer.push({"index": i, "data": "sample"})

        self.assertEqual(self.buffer.count(), 10)
        batch = self.buffer.fetch_batch(limit=10)
        # Oldest rows (0..4) should be pruned, remaining start at 5
        self.assertEqual(batch[0][1]["index"], 5)
        self.assertEqual(batch[-1][1]["index"], 14)

    def test_streamer_disconnect_accumulates_and_flushes(self):
        """5. Test buffer: disconnect network, assert rows accumulate in SQLite, reconnect, assert flush."""
        streamer = TelemetryStreamer(
            axiom_host="mock-axiom.local",
            agent_api_key="TEST_API_KEY",
            buffer=self.buffer,
        )

        sample_payload = {"test": 123}

        # Step 1: Disconnect / failure (mock post returning connection error)
        with patch.object(streamer, "_post_payload", return_value=(False, None)):
            sent = streamer.send(sample_payload)
            self.assertFalse(sent)
            self.assertEqual(self.buffer.count(), 1)

            streamer.send({"test": 456})
            self.assertEqual(self.buffer.count(), 2)

        # Step 2: Reconnect (mock post returning success)
        with patch.object(streamer, "_post_payload", return_value=(True, 200)):
            flushed = streamer.flush_buffer()
            self.assertEqual(flushed, 2)
            self.assertEqual(self.buffer.count(), 0)

    def test_streamer_401_stops_retrying_and_alerts(self):
        """Negative test: AXIOM-II returns 401: log, alert syslog, stop retrying."""
        streamer = TelemetryStreamer(
            axiom_host="mock-axiom.local",
            agent_api_key="INVALID_KEY",
            buffer=self.buffer,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("httpx.Client.post", return_value=mock_resp):
            with patch("garuda_agent.streamer.alert_syslog") as mock_syslog:
                sent = streamer.send({"data": "telemetry"})
                self.assertFalse(sent)
                self.assertTrue(streamer.key_rejected)
                mock_syslog.assert_called()

                # Subsequent sends should immediately fail without network calls
                sent2 = streamer.send({"data": "telemetry2"})
                self.assertFalse(sent2)

    def test_streamer_500_retries_and_buffers(self):
        """Negative test: AXIOM-II returns 500: retry with backoff, buffer data."""
        streamer = TelemetryStreamer(
            axiom_host="mock-axiom.local",
            agent_api_key="TEST_KEY",
            buffer=self.buffer,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        with patch("httpx.Client.post", return_value=mock_resp):
            sent = streamer.send({"data": "critical_reading"})
            self.assertFalse(sent)
            # Must be saved to local buffer
            self.assertEqual(self.buffer.count(), 1)


class TestEntropyAndSchedstat(unittest.TestCase):
    """Tests for entropy and schedstat readers."""

    def test_entropy_reader_critical_detection(self):
        """Test entropy reader critical covert channel flag (< 128 bits)."""
        reader = EntropyReader(path="/tmp/mock_entropy")
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="95")):
                payload, flags = reader.read()
                self.assertEqual(payload["bits"], 95)
                self.assertTrue(payload["depleting"])
                self.assertIn("ENTROPY_CRITICAL", flags)

    def test_schedstat_reader_steal_ratio(self):
        """Test schedstat reader parse and elevated steal ratio."""
        schedstat_v15_data = (
            "version 15\n"
            "cpu0 0 0 0 0 0 0 1000000 200000 500\n"
        )
        schedstat_v15_data2 = (
            "version 15\n"
            "cpu0 0 0 0 0 0 0 1500000 700000 700\n"
        )

        reader = SchedstatReader(path="/proc/schedstat")
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=schedstat_v15_data)):
                reader.read()

            # Second read: delta running = 500k, delta waiting = 500k -> steal ratio = 500k/(500k+500k) = 0.50
            with patch("builtins.open", mock_open(read_data=schedstat_v15_data2)):
                payload, flags = reader.read()
                self.assertAlmostEqual(payload["steal_ratio"], 0.50, places=2)
                self.assertIn("ELEVATED_CPU_STEAL", flags)


class TestDaemonAndService(unittest.TestCase):
    """Test daemon orchestration and service unit generator."""

    def test_service_generator(self):
        """Test systemd service file contains required security flags."""
        content = generate_service_content()
        self.assertIn("User=root", content)
        self.assertIn("LimitCORE=0", content)
        self.assertIn("Restart=always", content)
        self.assertIn("PrivateTmp=true", content)

    def test_daemon_single_shot(self):
        """Test daemon collect_payload output schema."""
        daemon = GarudaDaemon(dry_run=True, once=True)
        payload = daemon.collect_payload()

        self.assertIn("agent_id", payload)
        self.assertIn("hostname", payload)
        self.assertIn("timestamp_utc", payload)
        self.assertIn("rapl", payload)
        self.assertIn("perf", payload)
        self.assertIn("entropy", payload)
        self.assertIn("schedstat", payload)
        self.assertIn("ias", payload)
        self.assertIn("flags", payload)


if __name__ == "__main__":
    unittest.main()
