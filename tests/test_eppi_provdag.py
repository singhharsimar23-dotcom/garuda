"""
Acceptance Tests for EPPI PROVDAG & Physical Power Fusion
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))

from axiom.services.provenance_processor import ProvenanceProcessor


class TestEPPIProvDAG(unittest.TestCase):
    """Test suite for PROVDAG graph construction, RAPL physical power tagging, and attack chain extraction."""

    def setUp(self):
        self.processor = ProvenanceProcessor()

    def test_fork_event_creates_edge(self):
        """FORK and EXEC events create directed edges from parent to child process in the DAG."""
        events = [
            {"event_type": "FORK", "pid": 100, "ppid": 1, "comm": "systemd", "timestamp_ns": 1700000000000000000},
            {"event_type": "FORK", "pid": 1050, "ppid": 100, "comm": "bash", "timestamp_ns": 1700000001000000000},
            {"event_type": "EXEC", "pid": 2048, "ppid": 1050, "comm": "curl", "target": "/usr/bin/curl", "timestamp_ns": 1700000002000000000},
        ]
        self.processor.add_eppi_events(events)

        self.assertTrue(self.processor.dag.has_node("proc_1050"))
        self.assertTrue(self.processor.dag.has_node("proc_2048"))
        self.assertTrue(self.processor.dag.has_edge("proc_100", "proc_1050"))
        self.assertTrue(self.processor.dag.has_edge("proc_1050", "proc_2048"))

    def test_rapl_tagging(self):
        """Processes in PROVDAG are tagged with matching physical RAPL observations at ±500ms window."""
        events = [
            {"event_type": "EXEC", "pid": 3000, "ppid": 1, "comm": "cryptominer", "timestamp_ns": 1700000010 * 10**9},
        ]
        self.processor.add_eppi_events(events)

        # High power observation at T=1700000010.2 (within 500ms)
        rapl_readings = [
            {"timestamp": 1700000010.2, "rapl_pkg_uw": 45000000.0}  # 45,000 mW (exceeds baseline)
        ]

        anomalous_count = self.processor.fuse_rapl_readings(
            rapl_observations=rapl_readings,
            baseline_pkg_mw=15000.0,
            baseline_pkg_std=2000.0,
        )

        self.assertEqual(anomalous_count, 1)
        node_data = self.processor.dag.nodes["proc_3000"]
        self.assertTrue(node_data["is_anomalous"])
        self.assertAlmostEqual(node_data["rapl_pkg_mw"], 45000.0, places=1)

    def test_attack_chain_found(self):
        """Walking DAG ancestors from an anomalous process identifies the initial root entry point."""
        events = [
            # Entry point: spearphished PDF reader (PID 500)
            {"event_type": "EXEC", "pid": 500, "ppid": 1, "comm": "evince", "timestamp_ns": 1700000000 * 10**9},
            # Dropped child script (PID 600)
            {"event_type": "FORK", "pid": 600, "ppid": 500, "comm": "sh", "timestamp_ns": 1700000001 * 10**9},
            # Final anomalous payload execution (PID 700)
            {"event_type": "EXEC", "pid": 700, "ppid": 600, "comm": "crimsonrat", "timestamp_ns": 1700000002 * 10**9},
        ]
        self.processor.add_eppi_events(events)

        # Tag PID 700 as anomalous
        self.processor.fuse_rapl_readings(
            rapl_observations=[{"timestamp": 1700000002.0, "rapl_pkg_uw": 50000000.0}],
            baseline_pkg_mw=15000.0,
            baseline_pkg_std=2000.0,
        )

        chain_res = self.processor.reconstruct_attack_chain()
        self.assertEqual(chain_res["root_entry_pid"], 500)  # Identified evince (PID 500) as root entry point!
        self.assertGreaterEqual(len(chain_res["attack_chain"]), 2)

    def test_empty_provdag_no_crash(self):
        """Empty PROVDAG reconstructs clean empty report without raising exceptions."""
        res = self.processor.reconstruct_attack_chain()
        self.assertEqual(res["nodes_count"], 0)
        self.assertIsNone(res["root_entry_pid"])


if __name__ == "__main__":
    unittest.main()
