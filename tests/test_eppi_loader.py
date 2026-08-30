"""
Acceptance Tests for EPPI eBPF Loader
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../garuda-agent")))

from garuda_agent.eppi.eppi_loader import EPPILoader


class TestEPPILoader(unittest.TestCase):
    """Test suite for eBPF loader kernel gating and ring buffer handling."""

    def test_kernel_version_check(self):
        """Kernels older than 5.4 must disable EPPI kprobes gracefully."""
        with patch("platform.system", return_value="Linux"), patch("platform.release", return_value="4.19.0-generic"):
            loader = EPPILoader()
            self.assertFalse(loader.enabled)
            self.assertEqual(loader.read_events(), [])

    def test_precompiled_object_missing(self):
        """When pre-compiled .o file is not present, EPPI disables without raising exceptions."""
        with patch("platform.system", return_value="Linux"), patch("platform.release", return_value="5.15.0-generic"):
            # Empty objects dir
            loader = EPPILoader(objects_dir="/nonexistent/eppi/objects")
            self.assertFalse(loader.enabled)

    def test_ring_buffer_overflow(self):
        """Ring buffer overflow events must increment dropped metrics counter without crashing."""
        loader = EPPILoader()
        self.assertEqual(loader.evdf_events_dropped, 0)
        loader.simulate_ring_buffer_overflow(dropped_count=15)
        self.assertEqual(loader.evdf_events_dropped, 15)
        loader.simulate_ring_buffer_overflow(dropped_count=5)
        self.assertEqual(loader.evdf_events_dropped, 20)


if __name__ == "__main__":
    unittest.main()
