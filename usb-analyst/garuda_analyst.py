"""
GARUDA Air-Gapped Analyst Workstation CLI
Extracts offline physical alerts and telemetry from USB LUKS partition and generates PDF + STIX 2.1 packages.
"""

import argparse
from datetime import datetime, timezone, timedelta
import json
import logging
import os
import sys

from report_generator import generate_pdf_report
from stix_exporter import export_alerts_to_stix_bundle

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [ANALYST] %(message)s")
logger = logging.getLogger("garuda.analyst.cli")


def run_analyst_pipeline(usb_data_dir: str, output_dir: str = ".") -> bool:
    """
    Executes air-gapped triage pipeline over USB mount.
    """
    logger.info(f"Reading air-gapped telemetry from {usb_data_dir}...")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Load alerts from event_queue
    alert_dir = os.path.join(usb_data_dir, "event_queue")
    alerts = []
    hostname = "isolated-endpoint"

    if os.path.exists(alert_dir):
        for fname in sorted(os.listdir(alert_dir)):
            if fname.startswith("alert_") and fname.endswith(".json"):
                fpath = os.path.join(alert_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        a_data = json.load(f)
                        alerts.append(a_data)
                        if "hostname" in a_data:
                            hostname = a_data["hostname"]
                except Exception as e:
                    logger.warning(f"Could not parse {fname}: {e}")

    logger.info(f"Loaded {len(alerts)} offline alerts for host '{hostname}'.")

    now_tag = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(output_dir, f"{hostname}_garuda_report_{now_tag}.pdf")
    stix_path = os.path.join(output_dir, f"{hostname}_stix_{now_tag}.json")

    # 2. Generate PDF Report
    pdf_success = generate_pdf_report(
        output_path=pdf_path,
        hostname=hostname,
        alerts=alerts,
    )

    # 3. Export STIX 2.1 Bundle
    stix_bundle = export_alerts_to_stix_bundle(alerts, hostname=hostname)
    with open(stix_path, "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=2)

    logger.info(f"STIX 2.1 bundle written to {stix_path}")
    logger.info("=== Air-Gapped Triage Pipeline Completed Successfully ===")
    return pdf_success


def main():
    parser = argparse.ArgumentParser(description="GARUDA Air-Gapped Analyst Workstation Tool")
    parser.add_argument("--usb", required=True, help="Path to mounted USB data partition (/media/garuda/data)")
    parser.add_argument("--output", default=".", help="Output directory for reports and STIX bundles")
    args = parser.parse_args()

    success = run_analyst_pipeline(usb_data_dir=args.usb, output_dir=args.output)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
