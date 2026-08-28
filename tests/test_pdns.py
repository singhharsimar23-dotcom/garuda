"""
GARUDA Session 5 Acceptance Tests — Passive DNS Correlation Engine

Tests validating:
  1. Passive DNS response ingestion across Robtex, VirusTotal, and HackerTarget.
  2. Domain-resolution to defence netblock intersection logic.
  3. Evidentiary raw_response retention in passive_dns_observations.
  4. Non-overclaiming alert copy calibration ("historical infrastructure overlap", not "DRDO is compromised").
  5. Mandatory source provenance invariant for monitored defence IP registries.
"""

import asyncio
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from garuda.api.main import app
from garuda.database import (
    _IN_MEMORY_DEFENCE_IPS,
    _IN_MEMORY_PDNS_OBSERVATIONS,
    find_matching_defence_ip,
    get_monitored_defence_ips,
    get_pdns_observations,
    upsert_monitored_defence_ip,
)
from garuda.intelligence.pdns_correlator import (
    correlate_domain_pdns,
    generate_pdns_alert_copy,
)


class TestPdnsAlertCopyAndCalibration(unittest.TestCase):
    """
    Acceptance Criteria: Alert copy must accurately describe domain-resolution history
    (infrastructure overlap), never claiming internal hosts queried the domain or that
    an organisation is compromised.
    """

    def test_alert_copy_exact_phrasing_and_calibration(self):
        copy = generate_pdns_alert_copy(
            domain="drdo-portal-update.space",
            matched_ip="59.160.10.42",
            org_name="DRDO Hyderabad",
            source="Robtex",
            observed_at="2026-08-20T12:00:00Z",
            confidence=91,
            actor_name="APT36",
        )

        # Expected core phrases matching standardized copy template
        self.assertIn("historical DNS resolution overlap observed between", copy)
        self.assertIn("DRDO Hyderabad netblock", copy)
        self.assertIn("via Robtex", copy)
        self.assertIn("infrastructure overlap, not confirmed internal query", copy)
        self.assertIn("manual verification required", copy)
        self.assertIn("59.160.10.42", copy)
        self.assertIn("2026-08-20", copy)

        # Non-overclaiming assertion: forbidden overclaiming phrases
        forbidden_terms = [
            "is compromised",
            "has been compromised",
            "internal host infected",
            "workstation infected",
            "organisation breached",
            "drdo is breached",
            "internal host queried",
            "workstation queried",
            "DRDO queried",
        ]
        for term in forbidden_terms:
            self.assertNotIn(term.lower(), copy.lower(), f"Forbidden overclaiming term '{term}' found in alert copy")



class TestPdnsCorrelationEngine(unittest.TestCase):
    """
    Acceptance Criteria: A seeded fixture (fake STIX indicator + fake resolution response
    placing an IP inside a fake monitored netblock) produces exactly one
    passive_dns_observations row and one correctly-worded alert without live API calls.
    """

    def setUp(self):
        _IN_MEMORY_DEFENCE_IPS.clear()
        _IN_MEMORY_PDNS_OBSERVATIONS.clear()

        # Seed monitored defence netblock
        asyncio.run(
            upsert_monitored_defence_ip(
                ip="59.160.0.0/16",
                org_name="DRDO Hyderabad Labs",
                source="APNIC Whois Registry inetnum AS18209",
                verified_on="2026-08-27",
                notes="Verified public defence research subnet",
            )
        )

    def test_resolution_intersection_generates_observation_and_alert(self):
        fake_stix_id = "indicator--550e8400-e29b-41d4-a716-446655440000"
        fake_c2_domain = "missile-tracking-review.space"

        # Mocked resolution placing C2 domain historically at 59.160.45.12 (within 59.160.0.0/16)
        mock_resolutions = [
            {
                "rrname": fake_c2_domain,
                "rrtype": "A",
                "rdata": "59.160.45.12",
                "time_first": 1720000000,
                "time_last": "2026-08-15T08:30:00Z",
                "source": "robtex",
            },
            {
                "rrname": fake_c2_domain,
                "rrtype": "A",
                "rdata": "185.220.101.5",  # Foreign VPS — no defence match
                "time_last": "2026-08-25T10:00:00Z",
                "source": "robtex",
            },
        ]

        # Run correlation with custom fixture (no live API calls)
        report = asyncio.run(
            correlate_domain_pdns(
                domain=fake_c2_domain,
                stix_indicator_id=fake_stix_id,
                confidence=92,
                actor_name="APT36",
                send_alert=False,  # Don't hit external Telegram in unit test
                custom_resolutions=mock_resolutions,
            )
        )

        # Assertions on correlation result
        self.assertEqual(report["resolutions_checked"], 2)
        self.assertEqual(report["matches_found"], 1)
        self.assertEqual(len(report["observations"]), 1)

        obs = report["observations"][0]
        self.assertEqual(obs["matched_ip"], "59.160.45.12")
        self.assertEqual(obs["org_name"], "DRDO Hyderabad Labs")
        self.assertEqual(obs["source"], "robtex")

        # Verify alert copy in observation
        self.assertIn("DRDO Hyderabad Labs", obs["alert_copy"])
        self.assertIn("59.160.45.12", obs["alert_copy"])
        self.assertIn("infrastructure overlap, not confirmed internal query", obs["alert_copy"])

        # Verify database record in passive_dns_observations
        db_records = asyncio.run(get_pdns_observations())
        self.assertEqual(len(db_records), 1)
        db_obs = db_records[0]
        self.assertEqual(db_obs["queried_domain"], fake_c2_domain)
        self.assertEqual(db_obs["stix_indicator_id"], fake_stix_id)
        self.assertTrue(db_obs["matches_known_c2"])
        self.assertIn("raw_response", db_obs)
        self.assertEqual(db_obs["raw_response"]["rdata"], "59.160.45.12")

    def test_non_matching_resolutions_produce_zero_observations(self):
        """Resolutions outside monitored defence netblocks produce 0 observations."""
        mock_resolutions = [
            {"rrname": "c2.space", "rdata": "194.36.191.12", "source": "virustotal"},
            {"rrname": "c2.space", "rdata": "8.8.8.8", "source": "hackertarget"},
        ]

        report = asyncio.run(
            correlate_domain_pdns(
                domain="c2.space",
                confidence=85,
                send_alert=False,
                custom_resolutions=mock_resolutions,
            )
        )

        self.assertEqual(report["resolutions_checked"], 2)
        self.assertEqual(report["matches_found"], 0)
        self.assertEqual(len(report["observations"]), 0)

        db_records = asyncio.run(get_pdns_observations())
        self.assertEqual(len(db_records), 0)


class TestDefenceIpProvenanceInvariant(unittest.TestCase):
    """
    Acceptance Criteria: Zero rows in monitored_defence_ips lack a verified source.
    """

    def setUp(self):
        _IN_MEMORY_DEFENCE_IPS.clear()

    def test_empty_source_rejected_by_database_helper(self):
        with self.assertRaises(ValueError):
            asyncio.run(
                upsert_monitored_defence_ip(
                    ip="103.20.100.1",
                    org_name="Mock NIC",
                    source="",  # Empty source must raise ValueError
                )
            )

    def test_valid_source_accepted(self):
        record = asyncio.run(
            upsert_monitored_defence_ip(
                ip="103.20.100.0/24",
                org_name="National Informatics Centre",
                source="IRINN Public Allocation Registry 2026",
            )
        )
        self.assertEqual(record["ip"], "103.20.100.0/24")
        self.assertEqual(record["source"], "IRINN Public Allocation Registry 2026")


class TestPdnsApiEndpoints(unittest.TestCase):
    """API endpoint acceptance tests for /api/v1/pdns/*."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        _IN_MEMORY_DEFENCE_IPS.clear()
        _IN_MEMORY_PDNS_OBSERVATIONS.clear()

    def test_register_defence_ip_endpoint_requires_source(self):
        # Empty source -> 422 Unprocessable Entity
        res_empty = self.client.post(
            "/api/v1/pdns/defence-ips",
            json={"ip": "59.160.0.0/16", "org_name": "DRDO", "source": ""},
        )
        self.assertEqual(res_empty.status_code, 422)

        # Valid source -> 200 OK
        res_valid = self.client.post(
            "/api/v1/pdns/defence-ips",
            json={
                "ip": "59.160.0.0/16",
                "org_name": "DRDO",
                "source": "APNIC AS18209 Documentation",
            },
        )
        self.assertEqual(res_valid.status_code, 200)
        data = res_valid.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["record"]["org_name"], "DRDO")

    def test_list_defence_ips_endpoint(self):
        asyncio.run(
            upsert_monitored_defence_ip(
                ip="14.139.0.0/16",
                org_name="ERNET India / Ministry of Education",
                source="APNIC Registry AS23693",
            )
        )
        res = self.client.get("/api/v1/pdns/defence-ips")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_documented"], 1)
        self.assertEqual(data["defence_ips"][0]["ip"], "14.139.0.0/16")


if __name__ == "__main__":
    unittest.main()
