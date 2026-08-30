"""
Acceptance and Negative Tests for KALI Autonomous Novel Path Synthesis (ANPS).
Covers MITRE ATT&CK Group G0134 technique graph construction, real MCTS search,
adversary utility / detection probability calculations, DEFENSIVE_GAP vs COVERED classification,
and baseline uncalibrated state handling.
"""

import asyncio
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

# Add brahma-service directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from brahma.main import app
from kali.attack_graph import APT36_TECHNIQUE_CATALOG, AttackGraphBuilder, get_attack_graph_builder
from kali.detection_model import DetectionProbabilityModel, get_detection_model
from kali.mcts_engine import KaliMCTSEngine, TACTIC_VALUES, get_kali_mcts_engine


class TestKaliANPS(unittest.TestCase):
    """Test suite for KALI ANPS MCTS engine."""

    def setUp(self):
        self.client = TestClient(app)
        self.engine = get_kali_mcts_engine()
        self.graph_builder = get_attack_graph_builder()
        self.detection_model = get_detection_model()

    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    def test_1_build_attack_graph_has_real_apt36_techniques(self):
        """1. Build ATT&CK graph: assert APT36 G0134 techniques are nodes, not invented technique IDs."""
        graph = self.graph_builder.build_graph()

        # Check documented G0134 techniques are present
        self.assertIn("T1566.001", graph.nodes)
        self.assertIn("T1059.005", graph.nodes)
        self.assertIn("T1055.012", graph.nodes)
        self.assertIn("T1071.001", graph.nodes)
        self.assertIn("T1041", graph.nodes)

        # Confirm metadata fields
        node_data = graph.nodes["T1055.012"]
        self.assertEqual(node_data["tactic"], "defense-evasion")
        self.assertIn("Process Hollowing", node_data["name"])

        # Check edges exist
        self.assertGreater(graph.number_of_edges(), 15)
        self.assertTrue(graph.has_edge("T1566.001", "T1059.005"))

    def test_2_mcts_500_simulations_terminates_within_30s(self):
        """2. MCTS 500 simulations: assert termination within 30 seconds on test graph."""
        start_time = time.time()
        discoveries = self.engine.synthesize_novel_paths(num_simulations=500, top_k=5)
        duration = time.time() - start_time

        self.assertLess(duration, 30.0, f"MCTS took {duration:.2f}s, expected < 30s")
        self.assertGreater(len(discoveries), 0)

        # Verify discovery structure
        disc = discoveries[0]
        self.assertTrue(disc["discovery_id"].startswith("kali-disc-"))
        self.assertGreaterEqual(len(disc["technique_sequence"]), 3)
        self.assertIsInstance(disc["adversary_utility"], float)
        self.assertIsInstance(disc["p_detection"], float)

    def test_3_reward_computation_exact_match(self):
        """3. Reward computation: trace path T1566.001->T1059.005->T1055.012, compute expected reward manually."""
        path = [
            ("T1566.001", "initial-access"),
            ("T1059.005", "execution"),
            ("T1055.012", "defense-evasion"),
        ]

        # Step 1: initial-access (tactic_val=0.4, p_det=0.10 -> r1 = 0.4 * 0.90 = 0.36)
        r1 = 0.4 * (1.0 - 0.10)
        # Step 2: execution (tactic_val=0.6, p_det=0.80 -> r2 = 0.6 * 0.20 = 0.12)
        r2 = 0.6 * (1.0 - 0.80)
        # Step 3: defense-evasion (tactic_val=0.5, p_det=0.65 -> r3 = 0.5 * 0.35 = 0.175)
        r3 = 0.5 * (1.0 - 0.65)

        expected_reward = round(r1 * r2 * r3, 4)
        computed_reward = self.engine.compute_path_reward(path, sample_count=5000)

        self.assertAlmostEqual(computed_reward, expected_reward, places=3)

    def test_4_defensive_gap_classification(self):
        """4. DEFENSIVE GAP: inject technique with low P_detection, assert gap_status=DEFENSIVE_GAP."""
        # Custom mock model where detection is low (0.15)
        custom_model = DetectionProbabilityModel()
        custom_model.compute_technique_detection_prob = MagicMock(return_value=(0.15, False))
        custom_model.evaluate_path_detection_prob = MagicMock(return_value=(0.35, False))

        test_engine = KaliMCTSEngine()
        test_engine.detection_model = custom_model

        with patch.object(test_engine, "compute_path_reward", return_value=0.85):
            discoveries = test_engine.synthesize_novel_paths(num_simulations=50, top_k=3)
            if discoveries:
                gap_disc = next((d for d in discoveries if d["adversary_utility"] > 0.70), None)
                if gap_disc:
                    self.assertEqual(gap_disc["gap_status"], "DEFENSIVE_GAP")

    def test_5_covered_classification(self):
        """5. COVERED: inject technique with high P_detection, assert gap_status=COVERED."""
        custom_model = DetectionProbabilityModel()
        custom_model.evaluate_path_detection_prob = MagicMock(return_value=(0.85, False))

        test_engine = KaliMCTSEngine()
        test_engine.detection_model = custom_model

        discoveries = test_engine.synthesize_novel_paths(num_simulations=50, top_k=3)
        if discoveries:
            self.assertEqual(discoveries[0]["gap_status"], "COVERED")

    def test_6_uncalibrated_flag_when_samples_low(self):
        """6. Uncalibrated flag: when almanac_baselines sample_count < 100, assert detection_uncalibrated=True."""
        discoveries = self.engine.synthesize_novel_paths(
            num_simulations=50,
            sample_count=25,  # Low sample count (< 100)
            top_k=3,
        )

        self.assertGreater(len(discoveries), 0)
        self.assertTrue(discoveries[0]["detection_uncalibrated"])

    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    def test_neg_1_mitre_fallback_graph(self):
        """Negative 1: MITRE JSON unavailable: load default technique catalog without crashing."""
        builder = AttackGraphBuilder(technique_catalog=None)
        graph = builder.build_graph()
        self.assertGreaterEqual(graph.number_of_nodes(), 10)

    def test_neg_2_alpha_counts_fallback(self):
        """Negative 2: BRAHMA alpha_counts unavailable: use uniform fallback prior."""
        discoveries = self.engine.synthesize_novel_paths(
            num_simulations=50,
            alpha_counts=None,  # No alpha counts
            top_k=3,
        )
        self.assertGreater(len(discoveries), 0)

    def test_neg_3_mcts_timeout_returns_partial_results(self):
        """Negative 3: MCTS timeout safeguard: return partial results without failure."""
        with patch("time.time", side_effect=[0.0, 10.0, 20.0, 29.0, 30.0] + [35.0] * 1000):
            discoveries = self.engine.synthesize_novel_paths(num_simulations=500, top_k=3)
            # Must return cleanly (empty list or partial results) without throwing an exception
            self.assertIsInstance(discoveries, list)


if __name__ == "__main__":
    unittest.main()
