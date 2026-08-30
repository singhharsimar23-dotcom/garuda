"""
Acceptance Tests for USB Agent Mode Detector
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../usb-agent")))

from garuda_usb_agent.mode_detector import detect_mode


class TestModeDetector(unittest.TestCase):
    """Test suite for USB runtime mode detection."""

    @patch("garuda_usb_agent.mode_detector.is_endpoint_reachable")
    @patch("garuda_usb_agent.mode_detector.is_host_os_running")
    @patch("garuda_usb_agent.mode_detector.is_running_from_usb")
    def test_alongside_mode(self, mock_usb, mock_host, mock_endpoint):
        """When running with reachable cloud endpoint, mode is ALONGSIDE."""
        mock_usb.return_value = False
        mock_host.return_value = True
        mock_endpoint.return_value = True

        mode = detect_mode(axiom_endpoint="https://axiom.garuda.in")
        self.assertEqual(mode, "ALONGSIDE")

    @patch("garuda_usb_agent.mode_detector.is_endpoint_reachable")
    @patch("garuda_usb_agent.mode_detector.is_host_os_running")
    @patch("garuda_usb_agent.mode_detector.is_running_from_usb")
    def test_airgapped_no_network(self, mock_usb, mock_host, mock_endpoint):
        """When cloud endpoint is unreachable or missing, mode defaults to AIRGAPPED."""
        mock_usb.return_value = True
        mock_host.return_value = True
        mock_endpoint.return_value = False

        mode = detect_mode(axiom_endpoint=None)
        self.assertEqual(mode, "AIRGAPPED")

    @patch("garuda_usb_agent.mode_detector.is_endpoint_reachable")
    @patch("garuda_usb_agent.mode_detector.is_host_os_running")
    @patch("garuda_usb_agent.mode_detector.is_running_from_usb")
    def test_bootable_no_host_os(self, mock_usb, mock_host, mock_endpoint):
        """When host OS is not active and running from USB, mode is BOOTABLE."""
        mock_usb.return_value = True
        mock_host.return_value = False
        mock_endpoint.return_value = False

        mode = detect_mode()
        self.assertEqual(mode, "BOOTABLE")


if __name__ == "__main__":
    unittest.main()
