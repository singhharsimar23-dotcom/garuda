"""
MAYA Ghost Document Deployer (Tier 1)
Generates fictional, seed-deterministic decoy defense documents with strict content safety rules.
"""

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional

from .deception_ledger import DeceptionLedger

logger = logging.getLogger("brahma.maya.document")

# Forbidden pattern checks (no real ministry officers or real classified programs)
FORBIDDEN_NAME_PATTERNS = [
    r"\b(Modi|Rajnath|Doval|Rawat|Chauhan)\b",
]

# Approved fictional defense project designations
FICTIONAL_PROJECTS = [
    "Project RAKSHA-7 (Tactical Air Defense Grid)",
    "Unit BRAVO-DELTA (Border Sensor Mesh)",
    "Wing 14B (Cyber Intercept Framework)",
    "Exercise INDRA-CHAKRA (Simulated Command Protocol)",
]


class GhostDocumentDeployer:
    """
    Generates plausible decoy documents tailored to adversary collection objectives.
    """

    def __init__(self, ledger: Optional[DeceptionLedger] = None, commander: Optional[Any] = None):
        self.ledger = ledger or DeceptionLedger()
        self.commander = commander

    def _sanitize_content(self, text: str) -> str:
        """Verifies no real named government figures are present in generated decoy."""
        for pat in FORBIDDEN_NAME_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                logger.warning(f"Sanitizer blocked real name match: {pat}")
                text = re.sub(pat, "Officer-In-Charge", text, flags=re.IGNORECASE)
        return text

    def generate_ghost_document(
        self,
        agent_id: str,
        doc_category: str = "STRATEGIC_PLAN",
        compartment: str = "APT36_CONTAINMENT",
    ) -> Dict[str, Any]:
        """
        Generates deterministic decoy document content.
        """
        seed = self.ledger.get_seed(compartment, f"{agent_id}:{doc_category}")
        project_title = FICTIONAL_PROJECTS[seed % len(FICTIONAL_PROJECTS)]
        doc_id = f"DOC-CONFIDENTIAL-{seed:08x}".upper()
        doc_path = f"/home/officer/Documents/{project_title.split(' ')[0]}_{seed:04x}.pdf"

        raw_content = (
            f"=== RESTRICTED // GOVERNMENT DEFENSE DIRECTIVE ===\n"
            f"DOCUMENT REF: {doc_id}\n"
            f"CLASSIFICATION: SECRET // DEFENSE OPERATIONAL USE ONLY\n"
            f"SUBJECT: Operational Overview for {project_title}\n"
            f"AUTHOR: Director, Department of Tactical Simulation (Fictional Unit)\n"
            f"DISTRIBUTION: Wing 14B Command Staff\n\n"
            "1. EXECUTIVE SUMMARY:\n"
            f"This directive outlines secondary response parameters under {project_title}.\n"
            "All simulated perimeter sensors are scheduled for operational testing in Q4.\n\n"
            "2. TECHNICAL SPECIFICATIONS:\n"
            "- Mesh Relay Frequency: 4.82 GHz (Simulated)\n"
            "- Gateway IP: 10.14.88.1 (Simulated Decoy)\n"
            "- Primary Token: GHOST_AUTH_TOKEN_77492\n\n"
            "=== END OF DIRECTIVE ===\n"
        )

        sanitized_content = self._sanitize_content(raw_content)

        # Record in ledger
        self.ledger.record_asset(
            asset_id=doc_id,
            compartment=compartment,
            entity=f"{agent_id}:{doc_category}",
            asset_type="GHOST_DOCUMENT",
            content=sanitized_content,
        )

        return {
            "asset_id": doc_id,
            "agent_id": agent_id,
            "doc_path": doc_path,
            "category": doc_category,
            "project_title": project_title,
            "content": sanitized_content,
            "seed": seed,
        }

    def deploy(self, agent_id: str, doc_category: str = "STRATEGIC_PLAN") -> Dict[str, Any]:
        """Dispatches decoy document creation to agent."""
        ghost_doc = self.generate_ghost_document(agent_id, doc_category)
        if self.commander:
            cmd = {"command": "write_canary", "path": ghost_doc["doc_path"], "content": ghost_doc["content"]}
            self.commander.send_command(agent_id, cmd)

        logger.info(f"Deployed ghost document {ghost_doc['asset_id']} to {agent_id}:{ghost_doc['doc_path']}.")
        return ghost_doc
