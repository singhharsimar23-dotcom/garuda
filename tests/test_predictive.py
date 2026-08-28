"""
GARUDA Session 12 Acceptance Tests — Predictive Domain Pre-Registration

Tests cover TLD filtering, candidate scoring, DNS NXDOMAIN availability,
analyst-approval validation, and monthly budget gating.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from garuda.api.main import app


class TestCandidateTldFilter(unittest.TestCase):
    """Candidates with .com TLD must be filtered out."""

    def test_candidate_tld_filter(self):
        from garuda.modules.predictive.domain_generator import filter_valid_apt36_tlds

        raw = [
            "modgov-login.com",
            "army-portal.space",
            "nic-secure.net",
            "drdo-sso.online",
            "random-test.xyz",
        ]
        filtered = filter_valid_apt36_tlds(raw)
        self.assertIn("army-portal.space", filtered)
        self.assertIn("drdo-sso.online", filtered)
        self.assertIn("random-test.xyz", filtered)
        self.assertNotIn("modgov-login.com", filtered)
        self.assertNotIn("nic-secure.net", filtered)


class TestCandidateScoring(unittest.TestCase):
    """Score high-confidence .space domains with NIC similarity; penalize random .xyz."""

    def test_candidate_scoring_high(self):
        from garuda.modules.predictive.domain_generator import score_candidate

        with patch(
            "garuda.modules.predictive.domain_generator.compute_similarity",
            return_value=(0.8, "mod.gov.in"),
        ):
            score = score_candidate(
                "modgovindia.space",
                target_keywords=["modgov", "modindia"],
                tension_index=0.75,
                nic_ground_truth=["mod.gov.in"],
            )
        self.assertGreater(score, 0.7)

    def test_candidate_scoring_low(self):
        from garuda.modules.predictive.domain_generator import score_candidate

        with patch(
            "garuda.modules.predictive.domain_generator.compute_similarity",
            return_value=(0.2, ""),
        ):
            score = score_candidate(
                "randomwords-test.xyz",
                target_keywords=["modgov"],
                tension_index=0.3,
                nic_ground_truth=["mod.gov.in"],
            )
        self.assertLess(score, 0.5)


class TestDnsAvailability(unittest.IsolatedAsyncioTestCase):
    """DNS NXDOMAIN check filters available vs taken domains."""

    async def test_dns_nxdomain_available(self):
        from dns.resolver import NXDOMAIN

        from garuda.modules.predictive.domain_generator import filter_available_candidates

        with patch("garuda.modules.predictive.domain_generator.dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = NXDOMAIN()
            result = await filter_available_candidates(["unregistered-candidate.space"])
        self.assertEqual(result, ["unregistered-candidate.space"])

    async def test_dns_resolves_unavailable(self):
        from garuda.modules.predictive.domain_generator import filter_available_candidates

        with patch("garuda.modules.predictive.domain_generator.dns.resolver.resolve") as mock_resolve:
            mock_resolve.return_value = [MagicMock()]
            result = await filter_available_candidates(["taken-domain.space"])
        self.assertEqual(result, [])


class TestPredictiveRegisterEndpoint(unittest.TestCase):
    """Register endpoint enforces analyst approval — never auto-registers."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_headers = {"Authorization": "Bearer test-admin-token"}

    def setUp(self):
        from garuda.database import _IN_MEMORY_PREDICTIVE_DOMAINS
        _IN_MEMORY_PREDICTIVE_DOMAINS.clear()

    @patch("garuda.api.routes.predictive.settings")
    def test_no_auto_register(self, mock_settings):
        mock_settings.TAXII_ADMIN_TOKEN = "test-admin-token"
        mock_settings.PORKBUN_API_KEY = "pk_test"
        mock_settings.PORKBUN_API_SECRET = "sk_test"
        mock_settings.DOMAIN_REGISTRATION_BUDGET_USD_MONTHLY = 50.0
        mock_settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD = 4.99

        response = self.client.post(
            "/api/predictive/register",
            json={
                "domain": "modgov-portal.space",
                "justification": "High-confidence APT36 pre-registration based on ISPR narrative spike.",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 422)
        detail = response.json().get("detail", [])
        fields = {item["loc"][-1] for item in detail if isinstance(item, dict)}
        self.assertIn("analyst_id", fields)

    @patch("garuda.api.routes.predictive.settings")
    def test_justification_length(self, mock_settings):
        mock_settings.TAXII_ADMIN_TOKEN = "test-admin-token"
        mock_settings.PORKBUN_API_KEY = "pk_test"
        mock_settings.PORKBUN_API_SECRET = "sk_test"
        mock_settings.DOMAIN_REGISTRATION_BUDGET_USD_MONTHLY = 50.0
        mock_settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD = 4.99

        response = self.client.post(
            "/api/predictive/register",
            json={
                "domain": "modgov-portal.space",
                "analyst_id": "analyst-001",
                "justification": "too short",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 422)

    @patch("garuda.api.routes.predictive.check_registration_budget", new_callable=AsyncMock)
    @patch("garuda.api.routes.predictive.settings")
    def test_budget_gate(self, mock_settings, mock_budget):
        mock_settings.TAXII_ADMIN_TOKEN = "test-admin-token"
        mock_settings.PORKBUN_API_KEY = "pk_test"
        mock_settings.PORKBUN_API_SECRET = "sk_test"
        mock_settings.DOMAIN_REGISTRATION_BUDGET_USD_MONTHLY = 50.0
        mock_settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD = 4.99

        mock_budget.return_value = (
            False,
            "Monthly registration count at limit: 10/10 domains ($50.00 budget). "
            "Analyst approval required — no auto-registration.",
        )

        response = self.client.post(
            "/api/predictive/register",
            json={
                "domain": "modgov-portal.space",
                "analyst_id": "analyst-001",
                "justification": "High-confidence APT36 pre-registration based on ISPR narrative spike.",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 429)
        self.assertIn("budget", response.json().get("message", "").lower())


if __name__ == "__main__":
    unittest.main()
