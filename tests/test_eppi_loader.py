"""
Acceptance Tests for EPPI eBPF Loader
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../garuda-agent")))

from garuda_agent.eppi import EPPISensor, get_eppi_sensor


class TestEPPILoader(unittest.TestCase):
    """Test suite for eBPF loader kernel gating and ring buffer handling."""

    def test_kernel_version_check(self):
        """Kernels on non-Linux must disable EPPI kprobes gracefully."""
        with patch("platform.system", return_value="Windows"):
            sensor = EPPISensor()
            self.assertFalse(sensor.is_available)
            self.assertEqual(sensor.read_events(), [])

    def test_precompiled_object_missing(self):
        """When source file is not present, EPPI disables without raising exceptions."""
        sensor = EPPISensor(bpf_source_path="/nonexistent/path/eppi_kprobes.c")
        self.assertFalse(sensor.is_available)
        self.assertEqual(sensor.read_events(), [])

    def test_synthetic_event_injection(self):
        """Synthetic event injection allows offline verification."""
        sensor = EPPISensor()
        sensor.inject_synthetic_event({
            "pid": 4501,
            "ppid": 1,
            "event_type": "EXECVE",
            "comm": "systemd",
        })
        self.assertEqual(len(sensor._event_queue), 1)
        self.assertEqual(sensor._event_queue[0]["comm"], "systemd")


if __name__ == "__main__":
    unittest.main()

