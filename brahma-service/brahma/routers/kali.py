"""
KALI ANPS Router
Provides endpoints for executing Monte Carlo Tree Search path synthesis and querying active discoveries.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from kali.mcts_engine import get_kali_mcts_engine

logger = logging.getLogger("brahma.routers.kali")
router = APIRouter(prefix="/api/v1/kali", tags=["KALI Autonomous Path Synthesis"])

_cached_discoveries: List[Dict[str, Any]] = []


class SynthesizeRequest(BaseModel):
    num_simulations: Optional[int] = Field(default=500, description="MCTS iterations")
    alpha_counts: Optional[List[float]] = None
    sample_count: Optional[int] = Field(default=5000, description="Baseline sample count")
    top_k: int = Field(default=10, ge=1, le=50)


@router.post("/synthesize", status_code=status.HTTP_200_OK)
async def trigger_anps_synthesis(payload: SynthesizeRequest = SynthesizeRequest()):
    """
    Trigger real MCTS search across the ATT&CK graph to uncover novel evasive paths.
    """
    global _cached_discoveries
    engine = get_kali_mcts_engine()

    try:
        discoveries = engine.synthesize_novel_paths(
            num_simulations=payload.num_simulations,
            alpha_counts=payload.alpha_counts,
            sample_count=payload.sample_count,
            top_k=payload.top_k,
        )
        _cached_discoveries = discoveries
        return {
            "status": "success",
            "count": len(discoveries),
            "simulations": payload.num_simulations,
            "discoveries": discoveries,
        }
    except Exception as e:
        logger.error(f"KALI MCTS synthesis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ANPS Synthesis Error: {str(e)}",
        )


@router.get("/discoveries", status_code=status.HTTP_200_OK)
async def get_kali_discoveries(limit: int = Query(default=10, ge=1, le=50)):
    """
    Retrieve active KALI novel attack path discoveries.
    """
    global _cached_discoveries
    if not _cached_discoveries:
        # Run default generation if cache is empty
        engine = get_kali_mcts_engine()
        _cached_discoveries = engine.synthesize_novel_paths(num_simulations=100, top_k=limit)

    return {
        "status": "success",
        "count": len(_cached_discoveries[:limit]),
        "discoveries": _cached_discoveries[:limit],
    }


@router.get("/discoveries/{discovery_id}", status_code=status.HTTP_200_OK)
async def get_discovery_by_id(discovery_id: str):
    """
    Retrieve detailed metric breakdown for a specific KALI discovery ID.
    """
    global _cached_discoveries
    match = next((d for d in _cached_discoveries if d["discovery_id"] == discovery_id), None)
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Discovery ID '{discovery_id}' not found.",
        )
    return match


class CalibrateRequest(BaseModel):
    technique_id: str
    detected: bool
    ias_achieved: Optional[float] = 0.0


@router.post("/calibrate", status_code=status.HTTP_200_OK)
async def calibrate_kali_technique(payload: CalibrateRequest):
    """
    Online Bayesian calibration of P_detection for a technique based on live detection feedback.
    """
    try:
        from kali.online_calibration import get_kali_online_calibrator
    except ImportError:
        from ...kali.online_calibration import get_kali_online_calibrator

    calibrator = get_kali_online_calibrator()
    new_p = calibrator.calibrate_technique(
        technique_id=payload.technique_id,
        detected=payload.detected,
        ias_achieved=payload.ias_achieved or 0.0,
    )
    return {
        "status": "success",
        "technique_id": payload.technique_id,
        "new_p_detection": new_p,
    }

