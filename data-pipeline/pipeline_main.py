"""
GARUDA Threat Intelligence Pipeline Orchestrator
Entry point for GitHub Actions workflow executing weekly threat intel ingestion.
"""

import json
import logging
import os
import sys

from .aptnotes_parser import APTnotesParser
from .brahma_uploader import BrahmaUploader
from .cisa_puller import CISAPuller
from .malwarebazaar_puller import MalwareBazaarPuller
from .mitre_ingester import MitreIngester
from .otx_puller import OTXPuller
from .stix_compiler import STIXCompiler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.orchestrator")


def run_pipeline() -> bool:
    """
    Executes the complete multi-source threat intelligence ingestion pipeline.
    """
    logger.info("=== Starting GARUDA Threat Intelligence Pipeline ===")

    # 1. MITRE ATT&CK Ingestion
    logger.info("[1/6] Ingesting MITRE ATT&CK enterprise bundle...")
    mitre = MitreIngester()
    mitre_data = mitre.extract_apt36_ttps()
    logger.info(
        f"Extracted {len(mitre_data['apt36']['techniques'])} APT36 techniques, "
        f"{len(mitre_data['sidecopy']['techniques'])} SideCopy techniques."
    )

    # 2. APTnotes Ingestion
    logger.info("[2/6] Parsing APTnotes threat intelligence reports...")
    aptnotes = APTnotesParser()
    aptnotes_data = aptnotes.parse_all_reports()

    # 3. AlienVault OTX Ingestion
    logger.info("[3/6] Pulling pulses and indicators from AlienVault OTX...")
    otx = OTXPuller()
    otx_data = otx.pull_all_actor_intel()

    # 4. CISA KEV Ingestion
    logger.info("[4/6] Ingesting CISA Known Exploited Vulnerabilities catalog...")
    cisa = CISAPuller()
    cisa_vulns = cisa.fetch_kev_catalog()

    # 5. MalwareBazaar Ingestion
    logger.info("[5/6] Pulling sample hashes from abuse.ch MalwareBazaar...")
    malware = MalwareBazaarPuller()
    malware_data = malware.pull_all_actor_samples()

    # 6. STIX 2.1 Compilation & Supabase Persistence
    logger.info("[6/6] Compiling STIX 2.1 objects and updating Supabase / BRAHMA...")
    compiler = STIXCompiler()
    stix_objects = compiler.compile_all_sources(
        mitre_data=mitre_data,
        otx_data=otx_data,
        malware_data=malware_data,
        aptnotes_data=aptnotes_data,
    )
    compiler.persist_to_supabase(stix_objects)

    # Upload TTP frequencies and intel priors to BRAHMA
    uploader = BrahmaUploader()
    uploader.upload_intel({
        "mitre_ttps": mitre_data,
        "otx_indicators_count": otx_data.get("indicators_count", 0),
        "malware_samples_count": malware_data.get("total_samples", 0),
        "cisa_cves_count": len(cisa_vulns),
    })

    logger.info("=== Threat Intelligence Pipeline Finished Successfully ===")
    return True


if __name__ == "__main__":
    success = run_pipeline()
    sys.exit(0 if success else 1)
