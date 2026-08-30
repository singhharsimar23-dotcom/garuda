"""
Acceptance Tests for MITRE ATT&CK Ingestion
"""

import inspect
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../data-pipeline")))

from mitre_ingester import MitreIngester


class TestMitreIngester(unittest.TestCase):
    """Test suite for dynamic MITRE ATT&CK alias resolution and technique extraction."""

    def setUp(self):
        self.fixture_path = os.path.join(
            os.path.dirname(__file__), "../data-pipeline/fixtures/att&ck_apt36_group.json"
        )
        self.ingester = MitreIngester(fixture_path=self.fixture_path)

    def test_apt36_found_by_alias(self):
        """ATT&CK bundle must resolve APT36 group via 'Transparent Tribe' alias without hardcoded IDs."""
        groups = self.ingester.find_intrusion_sets_by_aliases(["Transparent Tribe"])
        self.assertGreater(len(groups), 0)
        # Verify group represents APT36 / Transparent Tribe
        matched = False
        for g in groups:
            aliases = g.get("aliases", []) + [g.get("name", "")]
            if any("APT36" in a or "Transparent Tribe" in a for a in aliases):
                matched = True
                break
        self.assertTrue(matched, "Did not find APT36 / Transparent Tribe in aliases")

    def test_techniques_extracted(self):
        """Techniques are extracted dynamically from STIX 'uses' relationships."""
        results = self.ingester.extract_apt36_ttps()
        apt36_techs = results["apt36"]["techniques"]
        self.assertGreaterEqual(len(apt36_techs), 10)
        tech_names = [t["name"] for t in apt36_techs]
        self.assertIn("Spearphishing Attachment", tech_names)

    def test_no_hardcoded_stix_ids(self):
        """mitre_ingester.py source code must not contain hardcoded STIX UUIDs."""
        import mitre_ingester
        source = inspect.getsource(mitre_ingester)
        # Search for pattern like intrusion-set--<uuid>
        matches = re.findall(r"intrusion-set--[0-9a-fA-F-]{36}", source)
        self.assertEqual(len(matches), 0, f"Found hardcoded STIX IDs: {matches}")


if __name__ == "__main__":
    unittest.main()
