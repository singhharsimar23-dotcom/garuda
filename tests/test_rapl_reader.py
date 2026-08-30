"""
Acceptance Tests for RAPL Hardware Power Reader
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, mock_open, patch

# Ensure garuda-agent is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../garuda-agent")))

from garuda_agent.rapl_reader import RAPLReader


class TestRAPLReader(unittest.TestCase):
    """Test suite for RAPLReader."""

    @patch("glob.glob")
    def test_rapl_graceful_no_paths(self, mock_glob):
        """When no RAPL sysfs paths exist, reader should disable gracefully and return None."""
        mock_glob.return_value = []
        reader = RAPLReader()
        self.assertFalse(reader.available)
        self.assertIsNone(reader.read_package_power_uw())
        self.assertIsNone(reader.read_dram_power_uw())
        self.assertIsNone(reader.read_core_power_uw())

    @patch("glob.glob")
    @patch("os.path.exists")
    @patch("time.monotonic")
    def test_rapl_rollover_handled(self, mock_time, mock_exists, mock_glob):
        """Test counter rollover handling when 32-bit counter wraps around."""
        mock_glob.side_effect = lambda pat: ["/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"] if "intel-rapl:*" in pat else []
        mock_exists.return_value = False  # max_energy_range_uj default 2^32
        
        reader = RAPLReader()
        self.assertTrue(reader.available)
        
        # First reading: e1 = 2^32 - 100 at t = 10.0
        max_val = 2**32
        e1 = max_val - 100
        mock_time.return_value = 10.0
        
        with patch("builtins.open", mock_open(read_data=str(e1))):
            p1 = reader._read_channel("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")
            self.assertEqual(p1, 0.0)  # First reading initializes baseline

        # Second reading: e2 = 200 at t = 11.0 (1.0s elapsed)
        # Expected delta = (200 + 2^32) - (2^32 - 100) = 300 uJ / 1.0s = 300.0 uW
        e2 = 200
        mock_time.return_value = 11.0
        with patch("builtins.open", mock_open(read_data=str(e2))):
            p2 = reader._read_channel("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")
            self.assertIsNotNone(p2)
            self.assertAlmostEqual(p2, 300.0, places=2)

    @patch("glob.glob")
    @patch("builtins.open", side_effect=PermissionError("Permission denied"))
    def test_rapl_permission_error(self, mock_file, mock_glob):
        """PermissionError on sysfs should log a warning and return None without crashing."""
        mock_glob.side_effect = lambda pat: ["/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"] if "intel-rapl:*" in pat else []
        reader = RAPLReader()
        power = reader.read_package_power_uw()
        self.assertIsNone(power)


if __name__ == "__main__":
    unittest.main()
