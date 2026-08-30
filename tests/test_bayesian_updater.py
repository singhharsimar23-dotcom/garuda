"""
Acceptance Tests for BRAHMA Bayesian Kill-Chain Tracker & Updater
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from brahma.services.kill_chain_tracker import KillChainTracker
from brahma.services.bayesian_updater import BayesianUpdater


class TestBayesianUpdater(unittest.TestCase):
    """Test suite for Bayesian Kill-Chain Tracker and mathematical convergence."""

    def test_posterior_sums_to_one(self):
        """Probability distribution over all 14 tactics must always sum to 1.0 (within float tolerance)."""
        tracker = KillChainTracker(agent_id="test-node-01")
        self.assertAlmostEqual(sum(tracker.posterior.values()), 1.0, places=5)

        # Update with dummy probabilities
        tracker.posterior = tracker._normalize({"execution": 0.9, "c2": 0.1})
        self.assertAlmostEqual(sum(tracker.posterior.values()), 1.0, places=5)

    def test_unattributed_below_threshold(self):
        """Strict Rule 8 enforcement: Any tracker with < 15 observations must return UNATTRIBUTED."""
        tracker = KillChainTracker(agent_id="test-node-02", observation_count=14)
        actor, status, conf = tracker.evaluate_attribution()
        self.assertEqual(actor, "UNATTRIBUTED")
        self.assertEqual(status, "INSUFFICIENT_DATA")

        # Even with high MAP probability on a specific tactic, must remain UNATTRIBUTED if count < 15
        tracker.posterior = tracker._normalize({"command-and-control": 0.95})
        actor, status, conf = tracker.evaluate_attribution()
        self.assertEqual(actor, "UNATTRIBUTED")

    def test_no_actor_attribution_without_data(self):
        """A fresh tracker with 0 observations must never emit an actor attribution."""
        tracker = KillChainTracker(agent_id="virgin-node")
        actor, status, conf = tracker.evaluate_attribution()
        self.assertEqual(actor, "UNATTRIBUTED")
        self.assertEqual(status, "INSUFFICIENT_DATA")

    def test_convergence_with_c2_pattern(self):
        """20 consecutive high-IAS anomalies with C2/Execution channels converge to dominant tactic and APT36 attribution."""
        async def _run_test():
            updater = BayesianUpdater()
            agent_id = "target-defense-server"
            
            # Simulate 20 C2/Execution anomaly events
            last_res = None
            for _ in range(20):
                last_res = await updater.process_anomaly_event(
                    agent_id=agent_id,
                    hostname="delhi-core-gw",
                    ias_score=6.2,
                    top_channels=[
                        {"channel": "rapl_pkg", "score": 5.2},
                        {"channel": "entropy", "score": 4.1},
                    ],
                )

            self.assertIsNotNone(last_res)
            self.assertEqual(last_res["observation_count"], 20)
            self.assertIn(last_res["map_tactic"], ["execution", "command-and-control", "defense-evasion"])
            self.assertIn(last_res["actor_id"], ["APT36", "APT36 (possible)"])
            self.assertIn(last_res["convergence_status"], ["CONVERGED", "CONVERGING"])
            self.assertGreaterEqual(last_res["confidence"], 0.50)

        asyncio.run(_run_test())


if __name__ == "__main__":
    unittest.main()
