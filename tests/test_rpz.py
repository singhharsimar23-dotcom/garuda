"""
GARUDA Session 4 Acceptance Tests — Response Policy Zone (RPZ) DNS Defense

Comprehensive test suite validating:
  1. Strict threshold gating (confidence >= 80 for NXDOMAIN).
  2. Sovereign protection safeguards (.gov.in, .nic.in, .mil.in never blocked).
  3. Valid BIND 9 RPZ zone file rendering (SOA, NS, serial YYYYMMDDNN, CNAME ., *.domain CNAME .).
  4. 90-day expiry roll-off & soft-delete audit history.
  5. FastAPI RPZ endpoints (zone distribution over HTTPS, sync cron, JSON listing).
"""

import asyncio
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from garuda.api.main import app
from garuda.config import settings
from garuda.database import (
    _IN_MEMORY_RPZ_ENTRIES,
    expire_stale_rpz_entries,
    get_active_rpz_entries,
    get_all_rpz_entries,
    soft_delete_rpz_entry,
    upsert_rpz_entry,
)
from garuda.response.rpz_generator import (
    compute_zone_serial,
    generate_active_rpz_zone,
    is_domain_protected,
    publish_domain_to_rpz,
    render_rpz_zone_file,
    validate_rpz_eligibility,
)


class TestRpzEligibilityAndSafety(unittest.TestCase):
    """Unit tests for RPZ publication eligibility, threshold gating, and safety."""

    def test_strict_confidence_threshold(self):
        """
        Acceptance Criteria: RPZ publish threshold strictly gated at confidence >= 80.
        Scores below 80 are rejected to protect DNS resolvers from false positives.
        """
        # Low confidence (< 80) -> REJECTED
        eligible, reason = validate_rpz_eligibility("apt36-fake-c2.space", confidence=79, action="nxdomain")
        self.assertFalse(eligible)
        self.assertIn("below the strict RPZ threshold", reason)

        # Confidence = 80 -> ACCEPTED
        eligible, reason = validate_rpz_eligibility("apt36-fake-c2.space", confidence=80, action="nxdomain")
        self.assertTrue(eligible)
        self.assertIsNone(reason)

        # Confidence = 95 -> ACCEPTED
        eligible, reason = validate_rpz_eligibility("apt36-fake-c2.space", confidence=95, action="nxdomain")
        self.assertTrue(eligible)
        self.assertIsNone(reason)

    def test_sovereign_protected_domains_safeguard(self):
        """
        Acceptance Criteria: Domains ending in .gov.in, .nic.in, .mil.in, .res.in
        are NEVER assigned an nxdomain action, even with high confidence.
        """
        protected_domains = [
            "sso.nic.in",
            "mod.gov.in",
            "drdo.gov.in",
            "indianarmy.mil.in",
            "iisc.ac.in",
            "isro.gov.in",
        ]

        for domain in protected_domains:
            self.assertTrue(is_domain_protected(domain), f"{domain} must be protected")
            eligible, reason = validate_rpz_eligibility(domain, confidence=95, action="nxdomain")
            self.assertFalse(eligible, f"{domain} must NOT be eligible for NXDOMAIN")
            self.assertIn("protected sovereign national infrastructure", reason)

    def test_passthru_action_allowed_for_protected_domains(self):
        """
        Allowlist/override passthru actions ARE permitted for legitimate domains
        to explicitly whitelist them in the RPZ hierarchy.
        """
        eligible, reason = validate_rpz_eligibility("drdo.gov.in", confidence=50, action="passthru")
        self.assertTrue(eligible)
        self.assertIsNone(reason)

    def test_invalid_domain_format_rejected(self):
        """Invalid domain strings must be rejected."""
        invalid_domains = ["", "   ", "not_a_domain", "http://evil.com/path", "evil..com"]
        for domain in invalid_domains:
            eligible, reason = validate_rpz_eligibility(domain, confidence=90, action="nxdomain")
            self.assertFalse(eligible)


class TestRpzZoneFileSyntax(unittest.TestCase):
    """Validates RFC-compliant BIND 9 zone file generation."""

    def test_zone_serial_format(self):
        """Zone serial must follow YYYYMMDDNN format (e.g. 2026082701)."""
        dt = datetime(2026, 8, 27, 14, 30, tzinfo=timezone.utc)
        serial = compute_zone_serial(dt, revision=1)
        self.assertEqual(serial, "2026082701")
        self.assertEqual(len(serial), 10)

    def test_bind9_rpz_zone_rendering(self):
        """
        Acceptance Criteria: Generated zone file follows standard BIND 9 RPZ syntax:
          - SOA record with 5 timer fields
          - NS record
          - <domain> CNAME .
          - *.<domain> CNAME .
          - Passthru: <domain> CNAME rpz-passthru.
        """
        entries = [
            {
                "domain": "apt36-c2-portal.space",
                "action": "nxdomain",
                "confidence": 92,
                "source_stix_object_id": "indicator--1111",
            },
            {
                "domain": "transparent-tribe-doc.online",
                "action": "nxdomain",
                "confidence": 88,
                "source_stix_object_id": "indicator--2222",
            },
            {
                "domain": "whitelisted-partner.in",
                "action": "passthru",
                "confidence": 99,
                "source_stix_object_id": "whitelist--3333",
            },
        ]

        zone = render_rpz_zone_file(
            entries=entries,
            origin="rpz.garuda.gov.in",
            ttl=300,
            serial="2026082701",
        )

        # Directives
        self.assertIn("$TTL 300", zone)
        self.assertIn("$ORIGIN rpz.garuda.gov.in.", zone)

        # SOA & NS records
        self.assertIn("@ IN SOA rpz.garuda.gov.in. hostmaster.garuda.gov.in. (", zone)
        self.assertIn("2026082701 ; Serial number", zone)
        self.assertIn("3600       ; Refresh", zone)
        self.assertIn("600        ; Retry", zone)
        self.assertIn("604800     ; Expire", zone)
        self.assertIn("300        ; Minimum", zone)
        self.assertIn("@ IN NS rpz.garuda.gov.in.", zone)

        # NXDOMAIN triggers (CNAME . and wildcard *.domain CNAME .)
        self.assertIn("apt36-c2-portal.space CNAME .", zone)
        self.assertIn("*.apt36-c2-portal.space CNAME .", zone)
        self.assertIn("transparent-tribe-doc.online CNAME .", zone)
        self.assertIn("*.transparent-tribe-doc.online CNAME .", zone)

        # Passthru trigger (CNAME rpz-passthru.)
        self.assertIn("whitelisted-partner.in CNAME rpz-passthru.", zone)
        self.assertIn("*.whitelisted-partner.in CNAME rpz-passthru.", zone)


class TestRpzLifecycleAndSoftDelete(unittest.TestCase):
    """Validates soft-deletion, audit retention, and 90-day automatic roll-off."""

    def setUp(self):
        # Reset in-memory RPZ store for clean test isolation
        _IN_MEMORY_RPZ_ENTRIES.clear()

    def test_upsert_and_active_retrieval(self):
        """Active entries are retrieved; upserts update existing records."""
        asyncio.run(upsert_rpz_entry("c2-active-01.space", confidence=88, action="nxdomain"))
        asyncio.run(upsert_rpz_entry("c2-active-02.space", confidence=85, action="nxdomain"))

        active = asyncio.run(get_active_rpz_entries())
        self.assertEqual(len(active), 2)
        domains = [r["domain"] for r in active]
        self.assertIn("c2-active-01.space", domains)
        self.assertIn("c2-active-02.space", domains)

    def test_soft_deletion_preserves_audit_trail(self):
        """
        Acceptance Criteria: Deleting an entry sets removed_at (soft-delete).
        It is excluded from active zone generation but retained in all-entries history.
        """
        asyncio.run(upsert_rpz_entry("threat-to-delete.space", confidence=90, action="nxdomain"))

        # Soft delete
        deleted = asyncio.run(soft_delete_rpz_entry("threat-to-delete.space"))
        self.assertTrue(deleted)

        # Active entries must NOT contain it
        active = asyncio.run(get_active_rpz_entries())
        self.assertEqual(len(active), 0)

        # History / all entries MUST still retain it with non-null removed_at
        all_entries = asyncio.run(get_all_rpz_entries())
        self.assertEqual(len(all_entries), 1)
        self.assertEqual(all_entries[0]["domain"], "threat-to-delete.space")
        self.assertIsNotNone(all_entries[0]["removed_at"])

        # Rendered zone must NOT contain deleted domain
        zone = render_rpz_zone_file(active)
        self.assertNotIn("threat-to-delete.space", zone)

    def test_90_day_stale_roll_off_policy(self):
        """
        Acceptance Criteria: Entries older than 90 days are automatically expired
        (removed_at set) unless re-corroborated.
        """
        old_time = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
        fresh_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

        # Seed one old entry and one fresh entry
        _IN_MEMORY_RPZ_ENTRIES.append({
            "id": "old-entry-id",
            "domain": "stale-detection-2025.space",
            "action": "nxdomain",
            "confidence": 85,
            "added_at": old_time,
            "removed_at": None,
        })
        _IN_MEMORY_RPZ_ENTRIES.append({
            "id": "fresh-entry-id",
            "domain": "fresh-detection-2026.space",
            "action": "nxdomain",
            "confidence": 92,
            "added_at": fresh_time,
            "removed_at": None,
        })

        # Run 90-day expiry
        expired_count = asyncio.run(expire_stale_rpz_entries(max_age_days=90))
        self.assertEqual(expired_count, 1)

        active = asyncio.run(get_active_rpz_entries())
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["domain"], "fresh-detection-2026.space")


class TestRpzApiEndpoints(unittest.TestCase):
    """Acceptance tests for RPZ HTTP API endpoints and Vercel crons."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        _IN_MEMORY_RPZ_ENTRIES.clear()
        # Seed test indicators
        asyncio.run(upsert_rpz_entry("c2-endpoint-test.space", confidence=95, action="nxdomain"))

    def test_serve_rpz_zone_over_https(self):
        """
        Acceptance Criteria: GET /rpz/zone serves flat BIND zone file with
        Content-Type text/plain; charset=utf-8, Cache-Control, and custom headers.
        """
        resp = self.client.get("/rpz/zone")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp.headers["Content-Type"])
        self.assertIn("c2-endpoint-test.space CNAME .", resp.text)
        self.assertIn("*.c2-endpoint-test.space CNAME .", resp.text)
        self.assertIn("X-RPZ-Serial", resp.headers)
        self.assertIn("X-RPZ-Active-Rules", resp.headers)
        self.assertEqual(resp.headers["X-RPZ-Active-Rules"], "1")

    def test_list_rpz_entries_json(self):
        """GET /api/v1/rpz/entries returns structured JSON."""
        resp = self.client.get("/api/v1/rpz/entries")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["total_returned"], 1)
        self.assertEqual(data["publish_threshold"], 80)
        self.assertEqual(data["entries"][0]["domain"], "c2-endpoint-test.space")

    def test_sync_cron_auth_gating(self):
        """POST /api/rpz/sync requires valid CRON_SECRET."""
        # Unauthenticated -> 401
        res_unauth = self.client.post("/api/rpz/sync")
        self.assertEqual(res_unauth.status_code, 401)

        # Authenticated with CRON_SECRET -> 200
        res_auth = self.client.post(
            "/api/rpz/sync",
            headers={"Authorization": f"Bearer {settings.CRON_SECRET}"},
        )
        self.assertEqual(res_auth.status_code, 200)
        data = res_auth.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["active_rules_count"], 1)
        self.assertIn("zone_serial", data)

    def test_publish_endpoint_enforces_rules(self):
        """POST /api/rpz/publish rejects low confidence and protected domains."""
        # Low confidence -> 422
        res_low = self.client.post(
            "/api/rpz/publish",
            json={"domain": "low-threat.space", "confidence": 65, "action": "nxdomain"},
        )
        self.assertEqual(res_low.status_code, 422)

        # Protected sovereign domain -> 422
        res_prot = self.client.post(
            "/api/rpz/publish",
            json={"domain": "portal.nic.in", "confidence": 99, "action": "nxdomain"},
        )
        self.assertEqual(res_prot.status_code, 422)

        # Valid threat domain -> 200
        res_valid = self.client.post(
            "/api/rpz/publish",
            json={"domain": "apt36-c2-realtime.space", "confidence": 88, "action": "nxdomain"},
        )
        self.assertEqual(res_valid.status_code, 200)
        self.assertEqual(res_valid.json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
