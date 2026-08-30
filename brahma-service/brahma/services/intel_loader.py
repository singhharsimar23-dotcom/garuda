"""
Threat Intelligence Loader
Loads and indexes APT36 and SideCopy TTP data from database or offline fixtures.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("brahma.services.intel")


class IntelLoader:
    """
    Manages active threat intelligence indices for adversary attribution correlation.
    """

    def __init__(self, fixture_path: Optional[str] = None):
        self.fixture_path = fixture_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "data-pipeline", "fixtures", "att&ck_apt36_group.json"
        )
        self.apt36_techniques: List[str] = []
        self.sidecopy_techniques: List[str] = []
        self._load_local_intel()

    def _load_local_intel(self) -> None:
        if os.path.exists(self.fixture_path):
            try:
                with open(self.fixture_path, "r", encoding="utf-8") as f:
                    bundle = json.load(f)
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "attack-pattern":
                            for ref in obj.get("external_references", []):
                                ext_id = ref.get("external_id")
                                if ext_id:
                                    self.apt36_techniques.append(ext_id)
                logger.info(f"Loaded {len(self.apt36_techniques)} technique references from local intel.")
            except Exception as e:
                logger.debug(f"Could not load local intel fixture: {e}")
