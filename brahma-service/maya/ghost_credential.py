"""
MAYA Ghost Credential Deployer (Tier 0)
Deploys deterministic decoy credential files on hosts exhibiting lateral movement patterns.
"""

import hashlib
import logging
import uuid
from typing import Any, Dict, List, Optional

from .deception_ledger import DeceptionLedger

logger = logging.getLogger("brahma.maya.credential")


class GhostCredentialDeployer:
    """
    Deploys decoy credentials into standard credential stores.
    """

    def __init__(self, ledger: Optional[DeceptionLedger] = None, commander: Optional[Any] = None):
        self.ledger = ledger or DeceptionLedger()
        self.commander = commander

    def generate_canary_credential(
        self,
        agent_id: str,
        cred_type: str = "AWS_KEY",
        compartment: str = "APT36_CONTAINMENT",
    ) -> Dict[str, Any]:
        """
        Generates deterministic ghost credential content based on seed.
        """
        seed = self.ledger.get_seed(compartment, f"{agent_id}:{cred_type}")
        seed_hex = f"{seed:08x}".upper()
        asset_id = f"canary-cred-{seed_hex[:6]}"

        if cred_type == "AWS_KEY":
            path = f"/root/.aws/credentials_{seed_hex[:4]}"
            content = (
                "[default]\n"
                f"aws_access_key_id = AKIA{seed_hex}DEFENSE\n"
                f"aws_secret_access_key = {hashlib.sha256(str(seed).encode()).hexdigest()[:40]}\n"
                "region = ap-south-1\n"
            )
        elif cred_type == "SSH_KEY":
            path = f"/home/deploy/.ssh/id_rsa_{seed_hex[:4]}"
            content = (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn\n"
                f"{hashlib.sha256(str(seed).encode()).hexdigest()[:64]}\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
        else:
            path = f"/opt/garuda/config/db_{seed_hex[:4]}.conf"
            content = f"DB_USER=gov_admin_{seed_hex[:4]}\nDB_PASSWORD=Secure_{seed_hex}\n"

        # Record in ledger
        self.ledger.record_asset(
            asset_id=asset_id,
            compartment=compartment,
            entity=f"{agent_id}:{cred_type}",
            asset_type="CANARY_CREDENTIAL",
            content=content,
        )

        return {
            "asset_id": asset_id,
            "agent_id": agent_id,
            "path": path,
            "cred_type": cred_type,
            "content": content,
            "seed": seed,
        }

    def deploy(self, agent_id: str, cred_type: str = "AWS_KEY") -> Dict[str, Any]:
        """Dispatches credential deployment command to agent."""
        canary = self.generate_canary_credential(agent_id, cred_type)
        if self.commander:
            cmd = {"command": "write_canary", "path": canary["path"], "content": canary["content"]}
            self.commander.send_command(agent_id, cmd)

        logger.info(f"Deployed ghost credential {canary['asset_id']} to {agent_id}:{canary['path']}.")
        return canary
