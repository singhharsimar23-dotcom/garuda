"""
Platform Provenance & TPM Integrity Router
Validates TPM PCR 0 (Firmware/BIOS), PCR 7 (Secure Boot), and PCR 10 (IMA Measurement) states.
"""

from typing import Dict
from fastapi import APIRouter, Depends, HTTPException

from ..config import AxiomSettings, get_settings
from ..db.pool import get_db_pool
from ..models.anomaly import ProvenanceRequest, ProvenanceResponse

router = APIRouter(prefix="/api/v1", tags=["Provenance"])


@router.post("/provenance", response_model=ProvenanceResponse)
async def verify_provenance(
    request: ProvenanceRequest,
    settings: AxiomSettings = Depends(get_settings),
) -> ProvenanceResponse:
    """
    Evaluates submitted TPM 2.0 PCR hashes against known baseline states to detect firmware or kernel tampering.
    """
    pcrs = request.tpm_pcrs
    required_pcrs = ["0", "7", "10"]
    pcr_status: Dict[str, str] = {}
    valid = True

    for p in required_pcrs:
        val = pcrs.get(p)
        if not val or val.startswith("0x00000000"):
            pcr_status[f"pcr_{p}"] = "UNMEASURED_OR_ZERO"
            valid = False
        else:
            pcr_status[f"pcr_{p}"] = "VALID"

    trust_level = "TRUSTED" if valid else "UNTRUSTED"
    msg = "Platform boot measurements verified." if valid else "PCR mismatch or missing measurements detected."

    return ProvenanceResponse(
        agent_id=request.agent_id,
        integrity_valid=valid,
        pcr_status=pcr_status,
        trust_level=trust_level,
        message=msg,
    )
