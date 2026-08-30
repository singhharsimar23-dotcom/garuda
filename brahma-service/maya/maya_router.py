"""
MAYA Deception Router
Exposes endpoints for deploying ghost credentials and documents, and monitoring canary access.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .deception_ledger import DeceptionLedger
from .ghost_credential import GhostCredentialDeployer
from .ghost_document import GhostDocumentDeployer

router = APIRouter(prefix="/api/v1/maya", tags=["MAYA Deception Subsystem"])

ledger = DeceptionLedger()
cred_deployer = GhostCredentialDeployer(ledger)
doc_deployer = GhostDocumentDeployer(ledger)


class DeployCanaryRequest(BaseModel):
    agent_id: str
    cred_type: str = "AWS_KEY"
    compartment: str = "APT36_CONTAINMENT"


class DeployDocRequest(BaseModel):
    agent_id: str
    doc_category: str = "STRATEGIC_PLAN"
    compartment: str = "APT36_CONTAINMENT"


class CanaryAccessRequest(BaseModel):
    asset_id: str


@router.post("/deploy-canary")
def deploy_canary(req: DeployCanaryRequest):
    """Deploys a ghost credential canary on target agent."""
    return cred_deployer.deploy(req.agent_id, req.cred_type)


@router.post("/deploy-doc")
def deploy_ghost_doc(req: DeployDocRequest):
    """Deploys a ghost document on target agent."""
    return doc_deployer.deploy(req.agent_id, req.doc_category)


@router.post("/access-signal")
def record_canary_access(req: CanaryAccessRequest):
    """Callback when a canary file or document is opened."""
    count = ledger.record_access(req.asset_id)
    return {
        "status": "CANARY_TRIGGERED",
        "asset_id": req.asset_id,
        "access_count": count,
        "severity": "CRITICAL",
    }
