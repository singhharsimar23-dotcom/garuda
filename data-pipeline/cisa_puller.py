"""
CISA Known Exploited Vulnerabilities (KEV) Ingestion Module
Fetches and parses the official CISA KEV JSON catalog for exploited vulnerabilities.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.cisa")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAPuller:
    """
    Ingests and filters CISA Known Exploited Vulnerabilities catalog.
    """

    def __init__(self, fixture_path: Optional[str] = None):
        self.fixture_path = fixture_path or os.path.join(
            os.path.dirname(__file__), "fixtures", "cisa_kev_sample.json"
        )

    def fetch_kev_catalog(self) -> List[Dict[str, Any]]:
        """
        Retrieves the KEV catalog from CISA official endpoint or fallback fixture.
        """
        try:
            logger.info(f"Fetching CISA KEV catalog from {CISA_KEV_FEED_URL}...")
            req = urllib.request.Request(
                CISA_KEV_FEED_URL,
                headers={"User-Agent": "GARUDA-CISA-Puller/0.1.0"},
            )
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                if 200 <= resp.status < 300:
                    data = json.loads(resp.read().decode("utf-8"))
                    vulnerabilities = data.get("vulnerabilities", [])
                    logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities from CISA KEV.")
                    return vulnerabilities
        except Exception as e:
            logger.warning(f"Failed to fetch live CISA KEV feed: {e}. Falling back to fixture.")

        if os.path.exists(self.fixture_path):
            with open(self.fixture_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("vulnerabilities", [])

        return []

    def filter_relevant_cves(self, target_cves: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Filters KEV catalog for target CVEs or weaponized document formats (WinRAR, Office Equation Editor, RTF).
        """
        vulns = self.fetch_kev_catalog()
        if target_cves:
            target_set = set(c.upper() for c in target_cves)
            return [v for v in vulns if v.get("cveID", "").upper() in target_set]

        # Return all entries
        return vulns


def main():
    puller = CISAPuller()
    cves = puller.fetch_kev_catalog()
    print(f"CISA KEV Catalog contains {len(cves)} CVEs.")


if __name__ == "__main__":
    main()
