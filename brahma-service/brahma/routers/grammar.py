"""
Grammar Expansion Router
Allows explicit triggers for behavioral grammar expansion and adversary prediction rules.
"""

from fastapi import APIRouter, Depends
from ..config import BrahmaSettings, get_settings
from ..models.brahma import GrammarExpansionRequest, GrammarExpansionResponse
from ..services.groq_expander import expand_behavioral_grammar

router = APIRouter(prefix="/api/v1/brahma/grammar", tags=["Grammar Expansion"])


@router.post("/expand", response_model=GrammarExpansionResponse)
async def trigger_grammar_expansion(
    request: GrammarExpansionRequest,
    settings: BrahmaSettings = Depends(get_settings),
) -> GrammarExpansionResponse:
    """
    Synthesizes expanded grammar rules for off-pattern adversary execution.
    """
    res = await expand_behavioral_grammar(
        agent_id=request.agent_id,
        current_tactic=request.current_tactic,
        observed_channels=request.observed_channels,
        entropy_bits=request.entropy_bits,
        settings=settings,
    )

    return GrammarExpansionResponse(
        agent_id=request.agent_id,
        expansion_triggered=res.get("expansion_triggered", False),
        new_rules=res.get("new_rules", []),
        suggested_techniques=res.get("suggested_techniques", []),
        explanation=res.get("explanation", ""),
    )
