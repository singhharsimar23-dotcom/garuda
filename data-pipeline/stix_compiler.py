"""
STIX 2.1 Threat Intelligence Compiler
Converts ingested ATT&CK TTPs, APTnotes reports, OTX pulses, and MalwareBazaar samples
into standard STIX 2.1 JSON objects and persists them to Supabase stix_objects.
"""

from datetime import datetime, timezone
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.stix")


def _get_utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class STIXCompiler:
    """
    Compiles raw multi-source intelligence into standardized STIX 2.1 JSON bundles.
    """

    def __init__(self, supabase_url: Optional[str] = None, supabase_key: Optional[str] = None):
        self.supabase_url = supabase_url or os.environ.get("SUPABASE_URL")
        self.supabase_key = (
            supabase_key
            or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_SERVICE_KEY")
        )

    def create_threat_actor_object(self, name: str, aliases: List[str], description: str) -> Dict[str, Any]:
        """Creates a STIX 2.1 threat-actor object."""
        now = _get_utc_now_iso()
        actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, name)}"
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": name,
            "aliases": aliases,
            "description": description,
            "threat_actor_types": ["nation-state", "spy"],
            "sophistication": "advanced",
            "resource_level": "government",
            "primary_motivation": "espionage",
        }

    def create_campaign_object(self, name: str, description: str, first_seen: Optional[str] = None) -> Dict[str, Any]:
        """Creates a STIX 2.1 campaign object."""
        now = _get_utc_now_iso()
        camp_id = f"campaign--{uuid.uuid5(uuid.NAMESPACE_DNS, name)}"
        return {
            "type": "campaign",
            "spec_version": "2.1",
            "id": camp_id,
            "created": now,
            "modified": now,
            "name": name,
            "description": description,
            "first_seen": first_seen or now,
        }

    def create_indicator_object(
        self,
        indicator_value: str,
        indicator_type: str,
        title: str,
        description: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Creates a STIX 2.1 indicator object with standard STIX pattern.
        """
        now = _get_utc_now_iso()
        pattern = None

        if indicator_type.lower() in ("ipv4", "ip", "ipv4-addr"):
            pattern = f"[ipv4-addr:value = '{indicator_value}']"
        elif indicator_type.lower() in ("domain", "hostname", "domain-name"):
            pattern = f"[domain-name:value = '{indicator_value}']"
        elif indicator_type.lower() in ("filehash-sha256", "sha256", "hash"):
            pattern = f"[file:hashes.'SHA-256' = '{indicator_value}']"
        elif indicator_type.lower() in ("filehash-md5", "md5"):
            pattern = f"[file:hashes.'MD5' = '{indicator_value}']"
        else:
            pattern = f"[custom-indicator:value = '{indicator_value}']"

        ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{indicator_type}:{indicator_value}')}"
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": title or f"IOC: {indicator_value}",
            "description": description or f"Threat indicator {indicator_value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        }

    def compile_all_sources(
        self,
        mitre_data: Dict[str, Any],
        otx_data: Dict[str, Any],
        malware_data: Dict[str, Any],
        aptnotes_data: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Aggregates multi-source feeds into a single unified list of STIX 2.1 objects.
        """
        stix_objects: List[Dict[str, Any]] = []

        # 1. Threat Actors
        apt36_actor = self.create_threat_actor_object(
            name="APT36",
            aliases=["Transparent Tribe", "PROJECTM", "Mythic Leopard"],
            description="APT36 is a state-sponsored cyber espionage actor targeting Indian defense and government infrastructure.",
        )
        sidecopy_actor = self.create_threat_actor_object(
            name="SideCopy",
            aliases=["SideCopy Group"],
            description="SideCopy is an operational cluster targeting Indian military institutions using weaponized archive templates.",
        )
        stix_objects.extend([apt36_actor, sidecopy_actor])

        # 2. Campaigns from APTnotes
        for note in aptnotes_data:
            report_name = note.get("report_name", "Unknown Campaign")
            camp = self.create_campaign_object(
                name=f"Campaign: {report_name}",
                description=note.get("summary_snippet", ""),
            )
            stix_objects.append(camp)

            # Extract IOCs from note
            iocs = note.get("iocs", {})
            for ip in iocs.get("ipv4", []):
                ind = self.create_indicator_object(ip, "ipv4", f"APTnotes IP ({report_name})", f"Extracted from {report_name}")
                if ind:
                    stix_objects.append(ind)
            for domain in iocs.get("domains", []):
                ind = self.create_indicator_object(domain, "domain", f"APTnotes Domain ({report_name})", f"Extracted from {report_name}")
                if ind:
                    stix_objects.append(ind)
            for h in iocs.get("sha256", []):
                ind = self.create_indicator_object(h, "sha256", f"APTnotes Hash ({report_name})", f"Extracted from {report_name}")
                if ind:
                    stix_objects.append(ind)

        # 3. Indicators from OTX
        for ind_item in otx_data.get("indicators", []):
            stix_ind = self.create_indicator_object(
                indicator_value=ind_item.get("indicator"),
                indicator_type=ind_item.get("type"),
                title=ind_item.get("title"),
                description=ind_item.get("description"),
            )
            if stix_ind:
                stix_objects.append(stix_ind)

        # 4. Indicators from MalwareBazaar
        for sample in malware_data.get("apt36_samples", []) + malware_data.get("sidecopy_samples", []):
            h = sample.get("sha256_hash")
            if h:
                stix_ind = self.create_indicator_object(
                    indicator_value=h,
                    indicator_type="sha256",
                    title=f"MalwareBazaar {sample.get('signature', 'APT36')} Sample",
                    description=f"File: {sample.get('file_name', 'Unknown')}, ClamAV: {sample.get('clamav', 'Unknown')}",
                )
                if stix_ind:
                    stix_objects.append(stix_ind)

        logger.info(f"Compiled {len(stix_objects)} STIX 2.1 objects from all ingestion feeds.")
        return stix_objects

    def persist_to_supabase(self, stix_objects: List[Dict[str, Any]]) -> int:
        """
        Inserts compiled STIX objects into Supabase stix_objects table.
        """
        if not self.supabase_url or not self.supabase_key:
            logger.info("Supabase credentials not set. Skipping remote persistence.")
            return 0

        try:
            from supabase import create_client
            client = create_client(self.supabase_url, self.supabase_key)

            records = []
            for obj in stix_objects:
                records.append({
                    "id": obj["id"],
                    "type": obj["type"],
                    "spec_version": obj.get("spec_version", "2.1"),
                    "created": obj["created"],
                    "modified": obj["modified"],
                    "data": obj,
                })

            # Upsert batch in chunks of 50
            chunk_size = 50
            total_saved = 0
            for i in range(0, len(records), chunk_size):
                chunk = records[i:i + chunk_size]
                res = client.table("stix_objects").upsert(chunk).execute()
                total_saved += len(chunk)

            logger.info(f"Successfully persisted {total_saved} STIX objects to Supabase.")
            return total_saved
        except Exception as e:
            logger.warning(f"Failed to persist STIX objects to Supabase: {e}")
            return 0


def main():
    compiler = STIXCompiler()
    # Test compilation
    objects = compiler.compile_all_sources(
        mitre_data={},
        otx_data={"indicators": [{"indicator": "194.163.142.71", "type": "IPv4", "title": "Test C2", "description": ""}]},
        malware_data={"apt36_samples": []},
        aptnotes_data=[],
    )
    print(f"Compiled {len(objects)} STIX objects.")


if __name__ == "__main__":
    main()
