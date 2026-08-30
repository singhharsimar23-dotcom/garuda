"""
Acceptance Tests for KALI-PRIME Batch Red Team & Coverage Evaluator
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kali.anps_batch import ANPSBatchRunner
from kali.coverage_evaluator import evaluate_path_coverage
from kali.dharma_populator import DharmaPopulator


class TestKaliBatch(unittest.TestCase):
    """Test suite for KALI batch candidate path synthesis and DHARMA caching."""

    def setUp(self):
        self.runner = ANPSBatchRunner(max_batch_size=20)
        self.populator = DharmaPopulator()

    def test_paths_under_groq_budget(self):
        """Batch synthesis generates candidate paths within allocated budget."""
        discoveries = self.runner.synthesize_candidate_paths(actor_id="APT36")
        self.assertGreater(len(discoveries), 0)
        self.assertLessEqual(len(discoveries), 20)

    def test_top10_cached_in_redis(self):
        """Top 10 candidate paths are cached in Redis DHARMA plan cache under dharma:plan:APT36:*."""
        discoveries = self.runner.synthesize_candidate_paths(actor_id="APT36")
        count = self.populator.populate_top_paths(discoveries, actor_id="APT36", top_n=10)
        self.assertEqual(count, min(10, len(discoveries)))

        cached = self.populator.get_cached_plans()
        self.assertGreaterEqual(len(cached), 1)
        first_key = list(cached.keys())[0]
        self.assertTrue(first_key.startswith("dharma:plan:APT36:"))

    def test_utility_scores_bounded(self):
        """All adversary utility scores and detection probabilities must be strictly bounded in [0.0, 1.0]."""
        discoveries = self.runner.synthesize_candidate_paths(actor_id="APT36")
        for disc in discoveries:
            self.assertGreaterEqual(disc["adversary_utility_score"], 0.0)
            self.assertLessEqual(disc["adversary_utility_score"], 1.0)
            self.assertGreaterEqual(disc["estimated_detection_probability"], 0.0)
            self.assertLessEqual(disc["estimated_detection_probability"], 1.0)


if __name__ == "__main__":
    unittest.main()
