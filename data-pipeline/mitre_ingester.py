"""
MITRE ATT&CK Ingestion Module
Downloads official Enterprise ATT&CK JSON bundle and dynamically resolves APT36 and SideCopy TTPs.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.mitre")

MITRE_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


class MitreIngester:
    """
    Ingests and parses MITRE ATT&CK STIX bundle without hardcoded STIX identifiers.
    """

    def __init__(self, cache_path: str = "/tmp/enterprise-attack.json", fixture_path: Optional[str] = None):
        self.cache_path = cache_path
        self.fixture_path = fixture_path or os.path.join(
            os.path.dirname(__file__), "fixtures", "att&ck_apt36_group.json"
        )
        self.bundle: Optional[Dict[str, Any]] = None

    def fetch_bundle(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Loads the Enterprise ATT&CK bundle from cache, remote URL, or offline fallback fixture.
        """
        if not force_refresh and os.path.exists(self.cache_path):
            try:
                logger.info(f"Loading ATT&CK bundle from local cache: {self.cache_path}")
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.bundle = json.load(f)
                    return self.bundle
            except Exception as e:
                logger.warning(f"Failed to read cached ATT&CK bundle: {e}")

        # Attempt download from GitHub static JSON
        try:
            logger.info(f"Downloading MITRE Enterprise ATT&CK from {MITRE_ENTERPRISE_ATTACK_URL}...")
            req = urllib.request.Request(
                MITRE_ENTERPRISE_ATTACK_URL,
                headers={"User-Agent": "GARUDA-DataPipeline/0.1.0"},
            )
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                if 200 <= resp.status < 300:
                    data = resp.read()
                    self.bundle = json.loads(data.decode("utf-8"))
                    # Save to cache if directory exists or can be created
                    try:
                        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
                        with open(self.cache_path, "wb") as f:
                            f.write(data)
                        logger.info(f"Cached ATT&CK bundle to {self.cache_path}")
                    except Exception as e:
                        logger.debug(f"Could not cache bundle file: {e}")
                    return self.bundle
        except Exception as e:
            logger.warning(f"Could not fetch live ATT&CK bundle: {e}. Falling back to fixture.")

        # Offline fixture fallback
        if os.path.exists(self.fixture_path):
            logger.info(f"Loading fallback ATT&CK fixture from {self.fixture_path}")
            with open(self.fixture_path, "r", encoding="utf-8") as f:
                self.bundle = json.load(f)
                return self.bundle

        raise RuntimeError("Failed to load ATT&CK bundle from remote, cache, and fixture.")

    def find_intrusion_sets_by_aliases(self, target_aliases: List[str]) -> List[Dict[str, Any]]:
        """
        Finds intrusion-set objects matching any of the specified aliases case-insensitively.
        Never relies on hardcoded STIX IDs.
        """
        if not self.bundle:
            self.fetch_bundle()

        objects = self.bundle.get("objects", [])
        matched_groups: List[Dict[str, Any]] = []

        for obj in objects:
            if obj.get("type") == "intrusion-set":
                name = obj.get("name", "")
                aliases = obj.get("aliases", [name])
                if not any(aliases):
                    aliases = [name]

                # Check if any target alias is present in the object's name or aliases
                match = False
                for target in target_aliases:
                    target_lower = target.lower()
                    if target_lower in name.lower() or any(target_lower in a.lower() for a in aliases):
                        match = True
                        break

                if match:
                    matched_groups.append(obj)

        if not matched_groups:
            logger.error(f"No intrusion-set found matching target aliases: {target_aliases}")
        else:
            logger.info(f"Found {len(matched_groups)} intrusion-sets for aliases {target_aliases}")

        return matched_groups

    def extract_group_techniques(self, group_id: str) -> List[Dict[str, Any]]:
        """
        Resolves all attack-pattern techniques linked to the group via 'uses' relationships.
        """
        if not self.bundle:
            self.fetch_bundle()

        objects = self.bundle.get("objects", [])
        # Map objects by id
        obj_map = {obj.get("id"): obj for obj in objects if "id" in obj}

        # Find relationships where source_ref is the group_id and relationship_type is 'uses'
        technique_ids: Set[str] = set()
        for obj in objects:
            if (
                obj.get("type") == "relationship"
                and obj.get("relationship_type") == "uses"
                and obj.get("source_ref") == group_id
            ):
                target_ref = obj.get("target_ref", "")
                if target_ref.startswith("attack-pattern--"):
                    technique_ids.add(target_ref)

        techniques: List[Dict[str, Any]] = []
        for tid in technique_ids:
            tech_obj = obj_map.get(tid)
            if tech_obj:
                tactics = []
                for phase in tech_obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase.get("phase_name"))

                ext_id = None
                for ref in tech_obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id")
                        break

                techniques.append({
                    "stix_id": tech_obj.get("id"),
                    "technique_id": ext_id,
                    "name": tech_obj.get("name"),
                    "tactics": tactics,
                    "description": tech_obj.get("description", ""),
                })

        logger.info(f"Extracted {len(techniques)} techniques for group {group_id}.")
        return techniques

    def extract_apt36_ttps(self) -> Dict[str, Any]:
        """
        Convenience runner extracting all APT36 (Transparent Tribe) & SideCopy techniques.
        """
        apt36_groups = self.find_intrusion_sets_by_aliases(["APT36", "Transparent Tribe", "PROJECTM"])
        sidecopy_groups = self.find_intrusion_sets_by_aliases(["SideCopy"])

        apt36_techniques: List[Dict[str, Any]] = []
        for g in apt36_groups:
            apt36_techniques.extend(self.extract_group_techniques(g["id"]))

        sidecopy_techniques: List[Dict[str, Any]] = []
        for g in sidecopy_groups:
            sidecopy_techniques.extend(self.extract_group_techniques(g["id"]))

        return {
            "apt36": {
                "groups": apt36_groups,
                "techniques": apt36_techniques,
            },
            "sidecopy": {
                "groups": sidecopy_groups,
                "techniques": sidecopy_techniques,
            },
        }


def main():
    ingester = MitreIngester()
    results = ingester.extract_apt36_ttps()
    print(f"APT36 Techniques: {len(results['apt36']['techniques'])}")
    print(f"SideCopy Techniques: {len(results['sidecopy']['techniques'])}")


if __name__ == "__main__":
    main()
