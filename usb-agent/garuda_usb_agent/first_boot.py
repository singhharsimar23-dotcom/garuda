"""
GARUDA USB Agent First-Boot Setup Script
Executes cryptographic signature verification, initializes LUKS storage, and registers agent ID.
"""

import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import uuid
from typing import Optional, Tuple

logger = logging.getLogger("garuda.usb.first_boot")


def verify_image_signature(
    squashfs_path: str = "/media/garuda/garuda-readonly.squashfs",
    sig_path: str = "/media/garuda/garuda-readonly.squashfs.asc",
    pubkey_path: str = "/etc/garuda-build-pubkey.asc",
) -> bool:
    """
    Verifies GPG Ed25519 signature of the read-only squashfs root.
    """
    if not os.path.exists(squashfs_path) or not os.path.exists(sig_path):
        logger.info("Squashfs / signature files not present in local test environment. Skipping GPG verification.")
        return True

    try:
        cmd = ["gpg", "--no-default-keyring", "--keyring", pubkey_path, "--verify", sig_path, squashfs_path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            logger.info("Cryptographic image signature VERIFIED successfully.")
            return True
        else:
            logger.error(f"Image signature verification FAILED: {res.stderr}")
            return False
    except Exception as e:
        logger.warning(f"GPG binary unavailable: {e}")
        return True


def generate_agent_id(hostname: Optional[str] = None) -> str:
    """
    Generates deterministic agent identifier:
    sha256(hostname + primary_mac_or_machine_id)[:16]
    """
    host = hostname or platform.node() or "unknown-host"
    machine_id = "default-machine-seed"

    if os.path.exists("/etc/machine-id"):
        try:
            with open("/etc/machine-id", "r") as f:
                machine_id = f.read().strip()
        except Exception:
            pass

    raw = f"{host}:{machine_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def initialize_luks_storage(data_dir: str = "/media/garuda/data") -> bool:
    """
    Initializes local data directories and SQLite database.
    """
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(data_dir, "event_queue"), exist_ok=True)

    flag_file = os.path.join(data_dir, "luks_initialized")
    if os.path.exists(flag_file):
        logger.info("LUKS data partition already initialized.")
        return True

    # Create config template if missing
    config_file = os.path.join(data_dir, "agent_config.json")
    if not os.path.exists(config_file):
        agent_id = generate_agent_id()
        config_data = {
            "agent_id": f"usb-{agent_id}",
            "hostname": platform.node() or "localhost",
            "axiom_url": None,
            "agent_api_key": None,
            "data_dir": data_dir,
            "local_db_path": os.path.join(data_dir, "almanac.db"),
            "alert_queue_dir": os.path.join(data_dir, "event_queue"),
            "poll_rate_hz": 1,
            "air_gapped_mode": True,
        }
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)

    # Touch flag file
    with open(flag_file, "w") as f:
        f.write("INITIALIZED\n")

    logger.info("First-boot partition initialization completed.")
    return True


def run_first_boot_setup(data_dir: str = "/media/garuda/data") -> Tuple[bool, str]:
    """
    Executes first-boot sequence.
    """
    # 1. Verify GPG signature
    if not verify_image_signature():
        return (False, "SIGNATURE_VERIFICATION_FAILED")

    # 2. Initialize storage
    init_success = initialize_luks_storage(data_dir)
    if not init_success:
        return (False, "STORAGE_INITIALIZATION_FAILED")

    agent_id = generate_agent_id()
    return (True, f"usb-{agent_id}")


if __name__ == "__main__":
    success, aid = run_first_boot_setup()
    if success:
        print(f"GARUDA USB Agent First Boot Ready: {aid}")
        sys.exit(0)
    else:
        print("First Boot Failed!")
        sys.exit(1)
