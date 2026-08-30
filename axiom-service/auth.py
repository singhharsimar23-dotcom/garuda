"""
Agent Authentication Module
Validates Bearer token headers against the Supabase agent_registry table.
"""

import logging
from typing import Optional
from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import get_settings

logger = logging.getLogger("axiom.auth")
security = HTTPBearer(auto_error=False)


async def get_supabase_client():
    """Create or return initialized Supabase async/sync client."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return None
    try:
        from supabase import create_client
        return create_client(settings.supabase_url, settings.supabase_service_key)
    except Exception as e:
        logger.warning(f"Could not connect to Supabase: {e}")
        return None


async def validate_agent_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
) -> str:
    """
    Validate incoming Agent Bearer API token.
    Checks against Supabase agent_registry table or fallback environment AGENT_API_KEY.
    """
    if not credentials or not credentials.credentials:
        logger.warning("Authentication failed: Missing Authorization Bearer header.")
        raise HTTPException(
            status_code=401,
            detail="AGENT_KEY_REJECTED: Missing or malformed authorization token",
        )

    token = credentials.credentials.strip()
    settings = get_settings()

    # 1. Direct match with configured AGENT_API_KEY (fast path / bootstrap)
    if settings.agent_api_key and token == settings.agent_api_key:
        return token

    # 2. Check Supabase agent_registry table
    supabase = await get_supabase_client()
    if supabase:
        try:
            res = supabase.table("agent_registry").select("id, is_active").eq("api_key", token).execute()
            if res.data and len(res.data) > 0:
                agent_record = res.data[0]
                if agent_record.get("is_active", True):
                    return token
                else:
                    logger.warning(f"Agent key {token[:8]}... is inactive/revoked in registry.")
                    raise HTTPException(
                        status_code=401,
                        detail="AGENT_KEY_REJECTED: Agent key is revoked or deactivated",
                    )
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Database query on agent_registry failed: {e}")

    logger.warning(f"AGENT_KEY_REJECTED: Token {token[:8]}... not authorized.")
    raise HTTPException(
        status_code=401,
        detail="AGENT_KEY_REJECTED: Invalid agent credentials",
    )
