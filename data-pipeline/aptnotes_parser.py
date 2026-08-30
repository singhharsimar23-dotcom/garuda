"""
APTnotes Threat Report Parser
Clones the APTnotes repository, filters for APT36 / SideCopy reports, and extracts text & IOCs using pdfminer.six.
"""

import glob
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("garuda.data_pipeline.aptnotes")

APTNOTES_REPO_URL = "https://github.com/aptnotes/data"
DEFAULT_CLONE_DIR = "/tmp/aptnotes"

# Target threat actor keyword filters
ACTOR_KEYWORDS = ["apt36", "transparent", "sidecopy", "c-major", "mythic leopard"]

# Regular expressions for IOC extraction
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|in|org|net|gov|edu|mil|info|biz|xyz|site|online)\b", re.IGNORECASE)
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class APTnotesParser:
    """
    Parses and extracts threat intelligence from APTnotes PDF repository.
    """

    def __init__(self, clone_dir: str = DEFAULT_CLONE_DIR):
        self.clone_dir = clone_dir

    def clone_or_update(self) -> bool:
        """
        Shallow clones the APTnotes data repository if not present.
        """
        if os.path.exists(self.clone_dir) and os.path.isdir(self.clone_dir):
            logger.info(f"APTnotes repository already cloned at {self.clone_dir}")
            return True

        try:
            logger.info(f"Cloning APTnotes from {APTNOTES_REPO_URL} into {self.clone_dir}...")
            res = subprocess.run(
                ["git", "clone", "--depth=1", APTNOTES_REPO_URL, self.clone_dir],
                capture_output=True,
                text=True,
                timeout=120.0,
            )
            if res.returncode == 0:
                logger.info("Successfully cloned APTnotes repository.")
                return True
            else:
                logger.warning(f"git clone failed (code {res.returncode}): {res.stderr}")
                return False
        except Exception as e:
            logger.warning(f"Failed to clone APTnotes repository: {e}")
            return False

    def find_relevant_reports(self) -> List[str]:
        """
        Finds PDF reports matching APT36, Transparent Tribe, SideCopy, or C-Major.
        """
        if not os.path.exists(self.clone_dir):
            return []

        pdf_files = glob.glob(os.path.join(self.clone_dir, "**", "*.pdf"), recursive=True)
        matched_reports = []

        for pdf_path in pdf_files:
            file_name = os.path.basename(pdf_path).lower()
            if any(kw in file_name for kw in ACTOR_KEYWORDS):
                matched_reports.append(pdf_path)

        logger.info(f"Found {len(matched_reports)} relevant reports matching actor keywords.")
        return matched_reports

    def extract_text_from_pdf(self, pdf_path: str) -> Optional[str]:
        """
        Extracts plain text from PDF using pdfminer.six.
        """
        try:
            from pdfminer.high_level import extract_text
            text = extract_text(pdf_path)
            return text
        except ImportError:
            logger.warning("pdfminer.six is not installed. Install with: pip install pdfminer.six")
            return None
        except Exception as e:
            logger.warning(f"Error extracting text from {pdf_path}: {e}")
            return None

    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extracts IPv4 addresses, SHA256 hashes, domains, and CVEs using regular expressions.
        """
        raw_ips = set(RE_IPV4.findall(text))
        # Filter private / localhost IPs
        clean_ips = [ip for ip in raw_ips if not (
            ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("0.")
        )]

        hashes = list(set(RE_SHA256.findall(text)))
        domains = list(set(RE_DOMAIN.findall(text)))
        cves = list(set(RE_CVE.findall(text)))

        return {
            "ipv4": clean_ips,
            "sha256": hashes,
            "domains": domains,
            "cves": cves,
        }

    def parse_all_reports(self) -> List[Dict[str, Any]]:
        """
        Parses all filtered reports and extracts aggregated indicators.
        """
        self.clone_or_update()
        reports = self.find_relevant_reports()
        results = []

        for pdf_path in reports:
            file_name = os.path.basename(pdf_path)
            text = self.extract_text_from_pdf(pdf_path)
            if text:
                iocs = self.extract_iocs_from_text(text)
                results.append({
                    "report_name": file_name,
                    "path": pdf_path,
                    "iocs": iocs,
                    "summary_snippet": text[:500].replace("\n", " ").strip(),
                })

        logger.info(f"Processed {len(results)} reports with extracted IOCs.")
        return results


def main():
    parser = APTnotesParser()
    results = parser.parse_all_reports()
    print(f"Parsed {len(results)} APTnotes reports.")


if __name__ == "__main__":
    main()
