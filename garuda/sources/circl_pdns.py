import logging
from typing import Any, Dict, List
from garuda.sources.robtex import query_unified_pdns

logger = logging.getLogger("garuda.sources.circl_pdns")


async def query_pdns(domain: str) -> List[Dict[str, Any]]:
    """
    Query unified Passive DNS (Robtex Free API + VirusTotal + HackerTarget).
    Replaces restricted partner-only CIRCL access with zero-auth public and active APIs.
    """
    return await query_unified_pdns(domain)
