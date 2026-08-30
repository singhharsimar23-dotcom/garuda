"""
Acceptance Tests for Agent Reader Graceful Degradation & Local Buffer
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, mock_open, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../garuda-agent")))

from garuda_agent.entropy_reader import EntropyReader
from garuda_agent.eppi_loader import EPPILoader
from garuda_agent.local_almanac import LocalAlmanac
from garuda_agent.perf_reader import PerfReader
from garuda_agent.schedstat_reader import SchedstatReader
from garuda_agent.tpm_reader import TPMReader


class TestReaderDegradation(unittest.TestCase):
    """Test suite ensuring all agent channels degrade gracefully without exceptions."""

    def test_entropy_reader_missing_sysfs(self):
        """When /proc/sys/kernel/random/entropy_avail is missing, reader should return None."""
        reader = EntropyReader(sysfs_path="/nonexistent/proc/entropy")
        self.assertFalse(reader.available)
        self.assertIsNone(reader.read_entropy_bits())

    def test_entropy_reader_valid(self):
        """When entropy file exists, read valid integer."""
        with patch("os.path.exists", return_value=True), patch("builtins.open", mock_open(read_data="3842\n")):
            reader = EntropyReader(sysfs_path="/proc/sys/kernel/random/entropy_avail")
            self.assertEqual(reader.read_entropy_bits(), 3842)

    def test_tpm_reader_tool_missing(self):
        """When tpm2_pcrread is not installed, reader disables gracefully."""
        with patch("shutil.which", return_value=None):
            reader = TPMReader()
            self.assertFalse(reader.available)
            self.assertIsNone(reader.read_pcrs())

    def test_tpm_reader_parsing(self):
        """TPMReader parses standard tpm2_pcrread output."""
        sample_output = """
        0 : 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        7 : 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
        10: 0x9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA
        """
        reader = TPMReader()
        pcrs = reader._parse_pcr_output(sample_output)
        self.assertIn("0", pcrs)
        self.assertIn("7", pcrs)
        self.assertIn("10", pcrs)
        self.assertTrue(pcrs["0"].startswith("0x0123456789ABCDEF"))

    def test_schedstat_reader_missing(self):
        """When /proc/schedstat is absent, reader returns None fields gracefully."""
        reader = SchedstatReader(sysfs_path="/nonexistent/schedstat")
        res = reader.read_schedstat()
        self.assertIsNone(res["run_time_ms_per_sec"])

    def test_eppi_kernel_version_gating(self):
        """Kernels older than 5.4 must disable EPPI kprobes."""
        with patch("platform.system", return_value="Linux"), patch("platform.release", return_value="4.19.0-21-amd64"):
            loader = EPPILoader()
            self.assertFalse(loader.enabled)
            self.assertEqual(loader.read_events(), [])

    def test_local_almanac_offline_buffer(self):
        """SQLite offline buffer stores, retrieves, and purges batches correctly."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            almanac = LocalAlmanac(db_path=db_path)
            batch = [{"timestamp": 1700000000.0, "rapl_pkg_uw": 15000000.0}]
            success = almanac.store_offline_batch("test-agent", batch)
            self.assertTrue(success)

            unsent = almanac.get_unsent_batches()
            self.assertEqual(len(unsent), 1)
            self.assertEqual(unsent[0]["agent_id"], "test-agent")

            almanac.mark_batch_sent(unsent[0]["id"])
            self.assertEqual(len(almanac.get_unsent_batches()), 0)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)


if __name__ == "__main__":
    unittest.main()
