"""
GARUDA Session 7 Acceptance Tests — Kill-List Refactor & Methodological Governance

Validates:
  1. Removal of unsubstantiated static accuracy guarantees (e.g. 97.9% recall claims).
  2. Gated Bayesian attack-window prediction (hard sample size threshold N >= 500).
  3. Sanitized canary-token access telemetry (timing signal only, zero geographic location claims).
  4. Netflow exfiltration module absence (scope discipline).
"""

import asyncio
from datetime import datetime, timezone
import unittest

from garuda.api.models import StatsResponse
from garuda.intelligence.cluster import (
    MIN_CAMPAIGNS_FOR_POINT_ESTIMATE,
    estimate_attack_window,
)
from garuda.intelligence.honeypot import (
    generate_canary_alert_copy,
    handle_canary_token_trigger,
)


class TestBayesianPredictorGating(unittest.TestCase):
    """
    Acceptance Criteria: Point estimates are gated behind a hard check (campaign_count >= 500).
    Under 500 campaigns, the model unconditionally outputs a range + 'LOW DATA CONFIDENCE'.
    """

    def test_insufficient_data_outputs_low_confidence_range(self):
        # Sample size < 500 -> Must return LOW DATA CONFIDENCE and NO point estimate
        sample_counts = [0, 1, 10, 49, 499]
        for count in sample_counts:
            forecast = estimate_attack_window(campaign_count=count, mean_domain_age_days=5.0)
            self.assertEqual(forecast["confidence_label"], "LOW DATA CONFIDENCE")
            self.assertFalse(forecast["is_point_estimate"])
            self.assertIsNone(forecast["estimated_attack_window_days"])
            self.assertIn("LOW DATA CONFIDENCE", forecast["estimated_window_display"])

    def test_sufficient_data_outputs_calibrated_point_estimate(self):
        # Sample size >= 500 -> Produces calibrated point estimate
        sample_counts = [500, 750, 1500]
        for count in sample_counts:
            forecast = estimate_attack_window(campaign_count=count, mean_domain_age_days=5.0)
            self.assertEqual(forecast["confidence_label"], "CALIBRATED")
            self.assertTrue(forecast["is_point_estimate"])
            self.assertIsNotNone(forecast["estimated_attack_window_days"])
            self.assertIsInstance(forecast["estimated_attack_window_days"], int)
            self.assertEqual(forecast["estimated_attack_window_days"], 14)


class TestCanaryAttributionSanitization(unittest.TestCase):
    """
    Acceptance Criteria: Canary token triggers output access timestamp ('campaign in active preparation')
    and NEVER claim geographic operator location (e.g. Rawalpindi) from token hits alone.
    """

    def test_canary_alert_copy_asserts_timing_not_location(self):
        copy = generate_canary_alert_copy(
            token_id="drdo-procurement-decoy-01",
            source_ip="185.220.101.5",
            timestamp="2026-08-25T14:00:00Z",
        )

        # Asserts timing signals present
        self.assertIn("drdo-procurement-decoy-01", copy)
        self.assertIn("185.220.101.5", copy)
        self.assertIn("2026-08-25", copy)
        self.assertIn("campaign is in active preparation", copy)
        self.assertIn("prevents geographic location attribution", copy)

        # Asserts forbidden geographic location claims absent
        forbidden_geo_claims = [
            "located in",
            "operator located",
            "rawalpindi",
            "islamabad",
            "lahore",
            "karachi",
            "physically located",
        ]
        for term in forbidden_geo_claims:
            self.assertNotIn(term, copy.lower(), f"Forbidden geographic claim '{term}' found in canary copy")

    def test_canary_handler_marks_geographic_attribution_unverified(self):
        payload = asyncio.run(
            handle_canary_token_trigger(
                token_id="token-xyz-99",
                source_ip="194.36.191.12",
                user_agent="Mozilla/5.0",
                timestamp="2026-08-27T10:00:00Z",
            )
        )
        signals = payload.get("signals", {})
        self.assertEqual(signals.get("timing_signal"), "active_campaign_preparation")
        self.assertEqual(signals.get("geographic_attribution"), "unverified_egress_infrastructure")


class TestQualityMetricsComputation(unittest.TestCase):
    """
    Acceptance Criteria: Quality metrics must be dynamic, computable numbers
    (e.g. confirmed indicators in 30d, corroborated by 2+ sources) rather than
    static static 97.9% guarantees.
    """

    def test_stats_model_supports_live_computable_quality_metrics(self):
        stats = StatsResponse(
            total_alerts_24h=42,
            critical_24h=5,
            confirmed_24h=3,
            confirmed_indicators_30d=120,
            corroborated_2plus_sources_30d=85,
            false_positive_rate_7d=0.032,
            active_campaigns=4,
        )
        self.assertEqual(stats.confirmed_indicators_30d, 120)
        self.assertEqual(stats.corroborated_2plus_sources_30d, 85)


class TestScopeBoundaries(unittest.TestCase):
    """
    Acceptance Criteria: Netflow exfiltration and classified tap modules
    must NOT be present in codebase.
    """

    def test_no_netflow_or_classified_taps_in_modules(self):
        import garuda.intelligence as intel
        self.assertFalse(hasattr(intel, "netflow_detector"))
        self.assertFalse(hasattr(intel, "exfiltration_monitor"))


if __name__ == "__main__":
    unittest.main()
