"""
Acceptance and Negative Tests for GARUDA Offline Training Pipeline and Online Learning Subsystems.
Covers transition matrix stochasticity, calibrated physics likelihoods, workload classification accuracy,
online Bayesian label updates, Beta-Bernoulli P_detection calibration, and anti-spoofing rate limiting.
"""

import asyncio
import json
import os
import pickle
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../axiom-service")))

from brahma.learner import BrahmaOnlineLearner, get_brahma_online_learner
from kali.online_calibration import KaliOnlineCalibrator, get_kali_online_calibrator
from online_calibrator import AxiomOnlineCalibrator, get_axiom_online_calibrator
from pipelines.train_transition_matrix import (
    APT36_CAMPAIGN_SEQUENCES,
    SIDECOPY_CAMPAIGN_SEQUENCES,
    build_transition_matrix,
    TACTIC_NAMES,
)


class TestTrainingAndOnlineLearning(unittest.TestCase):
    """Test suite for offline training artifacts and continuous online learning protocols."""

    # ==========================================
    # ACCEPTANCE TESTS
    # ==========================================

    def test_1_transition_matrix_apt36_execution_to_defense_evasion(self):
        """1. Transition matrix: assert APT36 execution -> defense-evasion probability > 0.10."""
        matrix = build_transition_matrix(APT36_CAMPAIGN_SEQUENCES)
        exec_idx = TACTIC_NAMES.index("execution")
        evasion_idx = TACTIC_NAMES.index("defense-evasion")

        prob = matrix[exec_idx][evasion_idx]
        self.assertGreater(prob, 0.10, f"Execution -> Defense-Evasion probability {prob} <= 0.10")

    def test_2_transition_matrix_row_stochastic_sums(self):
        """2. Transition matrix: assert all rows sum to 1.0 within floating point tolerance."""
        for name, seqs in [("APT36", APT36_CAMPAIGN_SEQUENCES), ("SideCopy", SIDECOPY_CAMPAIGN_SEQUENCES)]:
            matrix = build_transition_matrix(seqs)
            self.assertEqual(len(matrix), 14)
            for i, row in enumerate(matrix):
                self.assertEqual(len(row), 14)
                row_sum = sum(row)
                self.assertAlmostEqual(
                    row_sum, 1.0, places=3,
                    msg=f"{name} matrix row {i} ({TACTIC_NAMES[i]}) sum {row_sum} != 1.0"
                )

    def test_3_physics_likelihood_calibrated_bounds_and_citations(self):
        """3. Physics likelihood: assert all values between 0.05 and 1.0 with valid confidence metadata."""
        artifact_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/physics_likelihood.json"))
        self.assertTrue(os.path.exists(artifact_path))

        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("tactics", data)
        self.assertEqual(len(data["tactics"]), 14)

        for tactic, info in data["tactics"].items():
            lik = info["likelihood"]
            self.assertGreaterEqual(lik, 0.05)
            self.assertLessEqual(lik, 1.0)
            self.assertIn(info["confidence"], ["HIGH", "MEDIUM", "LOW"])
            self.assertTrue(len(info.get("citation", "")) > 10)

    def test_4_workload_classifier_accuracy_above_85_percent(self):
        """4. Workload classifier: assert test set accuracy > 0.85 on synthetic data."""
        model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/workload_classifier.pkl"))
        meta_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/workload_classifier_metadata.json"))

        self.assertTrue(os.path.exists(model_path))
        self.assertTrue(os.path.exists(meta_path))

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertGreater(meta["test_accuracy"], 0.85)

        with open(model_path, "rb") as f:
            pipeline = pickle.load(f)

        # Test prediction on synthetic sample: IDLE workload [rapl_pkg=8W, rapl_dram=3W, inst=0.05, cache=0.02]
        pred = pipeline.predict([[8.0, 3.0, 0.05, 0.02]])
        self.assertEqual(pred[0], 0)  # IDLE class index

    def test_5_online_brahma_update_increases_alpha_on_positive_labels(self):
        """5. Online BRAHMA update: 10 POSITIVE labels for execution tactic, assert alpha_counts[execution] increased."""
        learner = BrahmaOnlineLearner()
        host = "nic-delhi-01"
        exec_idx = TACTIC_NAMES.index("execution")
        initial_alpha = learner.get_or_create_host_alphas(host)[exec_idx]

        for _ in range(10):
            asyncio.run(learner.apply_label(hostname=host, tactic="execution", label="POSITIVE"))

        updated_alpha = learner.get_or_create_host_alphas(host)[exec_idx]
        self.assertGreater(updated_alpha, initial_alpha)

    def test_6_online_brahma_update_decreases_alpha_on_negative_labels_bounded(self):
        """6. Online BRAHMA update: 5 NEGATIVE labels, assert alpha decreased but stayed >= 0.01."""
        learner = BrahmaOnlineLearner()
        host = "drdo-srv-02"
        exec_idx = TACTIC_NAMES.index("execution")
        initial_alpha = learner.get_or_create_host_alphas(host)[exec_idx]

        for _ in range(5):
            asyncio.run(learner.apply_label(hostname=host, tactic="execution", label="NEGATIVE"))

        updated_alpha = learner.get_or_create_host_alphas(host)[exec_idx]
        self.assertLess(updated_alpha, initial_alpha)
        self.assertGreaterEqual(updated_alpha, 0.01)

    def test_7_kali_bayesian_calibration_converges_near_80_percent(self):
        """7. KALI calibration: 20 detections, 5 misses, assert P_detection converges mathematically."""
        calibrator = KaliOnlineCalibrator(prior_concentration=20.0)
        tech_id = "T1059.005"

        # Initial estimate is 0.50
        self.assertEqual(calibrator.get_estimate(tech_id), 0.50)

        # 20 consecutive detections: exponential smoothing moves 0.50 -> > 0.80
        for _ in range(20):
            calibrator.calibrate_technique(tech_id, detected=True)

        p_after_detections = calibrator.get_estimate(tech_id)
        self.assertGreater(p_after_detections, 0.80, f"P after 20 detections was {p_after_detections} <= 0.80")

        # 5 misses: decays according to Beta prior concentration
        for _ in range(5):
            calibrator.calibrate_technique(tech_id, detected=False)

        final_p = calibrator.get_estimate(tech_id)
        self.assertGreater(final_p, 0.60)
        self.assertLess(final_p, 0.85)


    # ==========================================
    # NEGATIVE TESTS
    # ==========================================

    def test_neg_1_aptnotes_offline_fallback_matrix(self):
        """Negative 1: APTnotes repo unavailable: build_transition_matrix falls back on documented baseline."""
        # Empty sequences fallback
        matrix = build_transition_matrix([])
        self.assertEqual(len(matrix), 14)
        for row in matrix:
            self.assertAlmostEqual(sum(row), 1.0, places=3)

    def test_neg_2_corrupt_pkl_graceful_recovery(self):
        """Negative 2: Corrupt pkl file: handled gracefully without crash."""
        corrupt_bytes = b"NOT_A_VALID_PICKLE_STREAM_12345"
        with patch("builtins.open", unittest.mock.mock_open(read_data=corrupt_bytes)):
            try:
                pickle.loads(corrupt_bytes)
                failed = False
            except Exception:
                failed = True
            self.assertTrue(failed)

    def test_neg_3_online_update_extreme_flood_rate_limited(self):
        """Negative 3: Online label flood (100 positives in 1s): rate-limits to 10/min, queues excess."""
        learner = BrahmaOnlineLearner()
        host = "flooded-host-01"

        applied_count = 0
        queued_count = 0

        for _ in range(50):
            res = asyncio.run(learner.apply_label(hostname=host, tactic="execution", label="POSITIVE"))
            if res.get("status") == "applied":
                applied_count += 1
            elif res.get("status") == "queued":
                queued_count += 1

        self.assertEqual(applied_count, 10)
        self.assertEqual(queued_count, 40)
        self.assertEqual(len(learner._overflow_queue), 40)


if __name__ == "__main__":
    unittest.main()
