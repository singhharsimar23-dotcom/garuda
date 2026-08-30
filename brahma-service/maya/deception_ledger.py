"""
MAYA Deception Ledger
Seed-deterministic generation module ensuring consistent deception state across repeated accesses.
"""

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("brahma.maya.ledger")


class DeceptionLedger:
    """
    Manages deterministic deception seeds and asset tracking.
    Key in Redis: maya:ledger:{adversary_compartment}:{entity}
    """

    def __init__(self, master_salt: str = "GARUDA_DEFENSE_MAYA_2026"):
        self.master_salt = master_salt
        self._memory_ledger: Dict[str, Dict[str, Any]] = {}

    def get_seed(self, compartment: str, entity: str) -> int:
        """
        Derives a deterministic integer seed from compartment and entity name:
        sha256(salt + compartment + entity)[:8] as integer.
        """
        raw = f"{self.master_salt}:{compartment}:{entity}".encode("utf-8")
        hex_digest = hashlib.sha256(raw).hexdigest()[:8]
        return int(hex_digest, 16)

    def record_asset(
        self,
        asset_id: str,
        compartment: str,
        entity: str,
        asset_type: str,
        content: str,
    ) -> Dict[str, Any]:
        """
        Persists deception asset metadata to ledger.
        """
        key = f"maya:ledger:{compartment}:{entity}"
        record = {
            "asset_id": asset_id,
            "compartment": compartment,
            "entity": entity,
            "asset_type": asset_type,
            "seed": self.get_seed(compartment, entity),
            "content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "access_count": 0,
            "first_accessed_at": None,
        }
        self._memory_ledger[key] = record
        return record

    def get_asset(self, compartment: str, entity: str) -> Optional[Dict[str, Any]]:
        """Retrieves asset from ledger."""
        key = f"maya:ledger:{compartment}:{entity}"
        return self._memory_ledger.get(key)

    def record_access(self, asset_id: str) -> int:
        """Increments access count when a canary file or document is opened."""
        for rec in self._memory_ledger.values():
            if rec.get("asset_id") == asset_id:
                rec["access_count"] += 1
                return rec["access_count"]
        return 1
