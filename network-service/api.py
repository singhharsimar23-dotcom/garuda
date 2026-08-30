"""
UTNE Service API (Koyeb Deployment)
FastAPI application serving real-time SITREPs, Operator Q&A, and CERT-In STIX Attribution Packages.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from utne.attribution_packager import AttributionPackager
from utne.groq_synthesizer import UTNESynthesizer
from utne.operator_qa import OperatorQA
from utne.rate_limiter import BudgetLimiter
from utne.sitrep_builder import SitrepBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("network.api")

app = FastAPI(
    title="GARUDA UTNE Narrative Service",
    description="Unified Threat Narrative Engine on Koyeb for Indian Cyber Defense Infrastructure",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = BudgetLimiter()
synthesizer = UTNESynthesizer(budget_limiter=limiter)
qa_engine = OperatorQA(budget_limiter=limiter)
builder = SitrepBuilder()


class QueryRequest(BaseModel):
    question: str = Field(..., max_length=500)
    recent_sitreps: List[Dict[str, Any]] = Field(default_factory=list)
    active_anomalies: List[Dict[str, Any]] = Field(default_factory=list)


class STIXPackageRequest(BaseModel):
    actor_name: str
    confidence_pct: float
    observed_ttps: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    ias_evidence: Dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "utne-narrative-service", "budget": limiter.get_status()}


@app.get("/api/v1/utne/sitrep")
def get_sitrep():
    """Generates live operational situation report."""
    evidence = builder.build_evidence_bundle()
    return synthesizer.generate_sitrep(evidence)


@app.post("/api/v1/utne/query")
def query_sitrep(req: QueryRequest):
    """Answers operator natural language questions."""
    return qa_engine.query(
        question=req.question,
        recent_sitreps=req.recent_sitreps,
        active_anomalies=req.active_anomalies,
    )


@app.post("/api/v1/utne/stix-package")
def create_stix_package(req: STIXPackageRequest):
    """Compiles CERT-In STIX 2.1 attribution package."""
    return AttributionPackager.create_certin_package(
        actor_name=req.actor_name,
        confidence_pct=req.confidence_pct,
        observed_ttps=req.observed_ttps,
        affected_assets=req.affected_assets,
        ias_anomaly_evidence=req.ias_evidence,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8002, reload=False)
