"""
AlienVault OTX Threat Intelligence Puller
Queries AlienVault OTX REST API for APT36 and SideCopy pulses and indicators with rate limit handling.
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.otx")

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


class OTXPuller:
    """
    Fetches threat intelligence pulses and IOCs from AlienVault OTX.
    """

    def __init__(self, api_key: Optional[str] = None, fixture_path: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OTX_API_KEY")
        self.fixture_path = fixture_path or os.path.join(
            os.path.dirname(__file__), "fixtures", "otx_apt36_pulse.json"
        )

    def _make_request(self, url: str, retries: int = 3) -> Optional[Dict[str, Any]]:
        """
        Executes HTTP GET request against OTX with rate limiting and retry handling.
        """
        headers = {
            "User-Agent": "GARUDA-OTX-Puller/0.1.0",
        }
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        req = urllib.request.Request(url, headers=headers)

        for attempt in range(1, retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    # Check rate limits from headers
                    rem = resp.headers.get("X-RateLimit-Remaining")
                    if rem is not None:
                        logger.debug(f"OTX Rate Limit Remaining: {rem}")

                    if 200 <= resp.status < 300:
                        return json.loads(resp.read().decode("utf-8"))

            except urllib.error.HTTPError as e:
                logger.warning(f"OTX HTTP {e.code} on attempt {attempt}: {e.reason}")
                if e.code == 429:
                    retry_after = e.headers.get("Retry-After")
                    sleep_sec = float(retry_after) if retry_after else 60.0
                    logger.warning(f"OTX rate limit exceeded (429). Sleeping for {sleep_sec}s...")
                    time.sleep(sleep_sec)
                elif e.code in (401, 403):
                    logger.error("OTX authentication failed. Check OTX_API_KEY.")
                    return None
            except Exception as e:
                logger.warning(f"OTX request error on attempt {attempt}: {e}")
                time.sleep(2.0 * attempt)

        return None

    def search_pulses(self, query: str = "APT36", limit: int = 50) -> List[Dict[str, Any]]:
        """
        Searches pulses matching actor query.
        """
        if not self.api_key:
            logger.info("OTX_API_KEY not configured. Using offline pulse fixture.")
            if os.path.exists(self.fixture_path):
                with open(self.fixture_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("results", [])
            return []

        url = f"{OTX_BASE_URL}/search/pulses?q={query}&limit={limit}"
        data = self._make_request(url)
        if data and "results" in data:
            logger.info(f"Retrieved {len(data['results'])} OTX pulses for query '{query}'.")
            return data["results"]

        # Fallback to fixture
        if os.path.exists(self.fixture_path):
            with open(self.fixture_path, "r", encoding="utf-8") as f:
                return json.load(f).get("results", [])

        return []

    def extract_pulse_indicators(self, pulse: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extracts IOC objects from a pulse dictionary.
        """
        raw_indicators = pulse.get("indicators", [])
        clean_indicators = []

        for ind in raw_indicators:
            val = ind.get("indicator")
            ind_type = ind.get("type")
            if val and ind_type:
                clean_indicators.append({
                    "indicator": val,
                    "type": ind_type,
                    "title": ind.get("title", pulse.get("name")),
                    "description": ind.get("description", pulse.get("description")),
                    "pulse_id": pulse.get("id"),
                    "created": ind.get("created", pulse.get("created")),
                })

        return clean_indicators

    def pull_all_actor_intel(self) -> Dict[str, Any]:
        """
        Pulls pulses and indicators for APT36 and SideCopy.
        """
        apt36_pulses = self.search_pulses("APT36", limit=50)
        sidecopy_pulses = self.search_pulses("SideCopy", limit=50)

        all_indicators = []
        for p in apt36_pulses:
            all_indicators.extend(self.extract_pulse_indicators(p))
        for p in sidecopy_pulses:
            all_indicators.extend(self.extract_pulse_indicators(p))

        return {
            "pulses_count": len(apt36_pulses) + len(sidecopy_pulses),
            "indicators_count": len(all_indicators),
            "indicators": all_indicators,
        }


def main():
    puller = OTXPuller()
    intel = puller.pull_all_actor_intel()
    print(f"Pulled {intel['pulses_count']} pulses, {intel['indicators_count']} indicators.")


if __name__ == "__main__":
    main()
