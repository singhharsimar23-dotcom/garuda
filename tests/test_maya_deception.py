"""
Acceptance Tests for MAYA Deception Subsystem
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../brahma-service")))

from maya.deception_ledger import DeceptionLedger
from maya.ghost_credential import GhostCredentialDeployer
from maya.ghost_document import GhostDocumentDeployer, FORBIDDEN_NAME_PATTERNS


class TestMayaDeception(unittest.TestCase):
    """Test suite for MAYA deterministic deception, content safety, and canary tracking."""

    def setUp(self):
        self.ledger = DeceptionLedger()
        self.cred_deployer = GhostCredentialDeployer(self.ledger)
        self.doc_deployer = GhostDocumentDeployer(self.ledger)

    def test_credential_deterministic(self):
        """Repeated generation of a credential for the same agent/type produces identical content (seed-based)."""
        cred1 = self.cred_deployer.generate_canary_credential("delhi-gw-01", "AWS_KEY")
        cred2 = self.cred_deployer.generate_canary_credential("delhi-gw-01", "AWS_KEY")

        self.assertEqual(cred1["asset_id"], cred2["asset_id"])
        self.assertEqual(cred1["content"], cred2["content"])
        self.assertEqual(cred1["seed"], cred2["seed"])

    def test_document_no_real_names(self):
        """MAYA ghost documents must not contain real government official names."""
        doc = self.doc_deployer.generate_ghost_document("mumbai-server-02", "STRATEGIC_PLAN")
        content = doc["content"]

        for pat in FORBIDDEN_NAME_PATTERNS:
            match = re.search(pat, content, re.IGNORECASE)
            self.assertIsNone(match, f"Found forbidden real name pattern '{pat}' in document output.")

        self.assertIn("DEFENSE OPERATIONAL USE ONLY", content)

    def test_deception_ledger_consistency(self):
        """Ledger maintains asset metadata and deterministic content hashes."""
        doc = self.doc_deployer.generate_ghost_document("drdo-hub", "TACTICAL_RADAR")
        asset = self.ledger.get_asset("APT36_CONTAINMENT", "drdo-hub:TACTICAL_RADAR")

        self.assertIsNotNone(asset)
        self.assertEqual(asset["asset_id"], doc["asset_id"])
        self.assertEqual(asset["asset_type"], "GHOST_DOCUMENT")

    def test_access_logging(self):
        """Canary access triggers increment on access count in ledger."""
        cred = self.cred_deployer.generate_canary_credential("host-99", "SSH_KEY")
        asset_id = cred["asset_id"]

        count1 = self.ledger.record_access(asset_id)
        self.assertEqual(count1, 1)

        count2 = self.ledger.record_access(asset_id)
        self.assertEqual(count2, 2)


if __name__ == "__main__":
    unittest.main()
