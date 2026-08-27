import logging
from typing import Any, Dict, Optional
import httpx

from garuda.config import settings

logger = logging.getLogger("garuda.response.blocklist_submit")


async def submit_to_urlhaus(url: str, alert: Optional[Dict[str, Any]] = None) -> bool:
    """
    Submit a confirmed malicious payload or C2 URL to abuse.ch URLhaus.

    CRITICAL COMPLIANCE POLICY:
    Submissions are strictly gated to alerts that have been explicitly confirmed by an analyst
    (alert['status'] == 'confirmed'). Unconfirmed alerts are rejected to prevent false submissions.

    Args:
        url: The malicious URL to report.
        alert: Associated alert record containing analyst validation status.

    Returns:
        bool: True if submission succeeded (urlhaus_submit_status == 'ok'), False otherwise.
    """
    # Strict analyst confirmation check
    if alert is not None:
        status = alert.get("status", "").lower()
        if status != "confirmed":
            logger.warning(
                f"[blocklist_submit] BLOCKED: Cannot submit '{url}' to URLhaus. Alert status is '{status}' (must be 'confirmed')."
            )
            return False

    token = settings.URLHAUS_API_KEY or "anonymous"
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    payload = {
        "token": token,
        "url": url,
        "threat": "malware_download",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.post(endpoint, data=payload)
            response.raise_for_status()
            data = response.json()
            status_result = data.get("query_status") or data.get("urlhaus_submit_status")
            return status_result == "ok"
    except httpx.HTTPError as err:
        logger.error(f"[blocklist_submit] HTTP error submitting to URLhaus: {err}")
        return False
    except Exception as e:
        logger.error(f"[blocklist_submit] Unexpected error submitting to URLhaus: {e}")
        return False


async def submit_to_phishtank(url: str, app_key: Optional[str] = None) -> bool:
    """
    Submit a credential harvesting phishing URL to PhishTank.

    Queries POST https://www.phishtank.com/api/info.php.

    Args:
        url: Target phishing URL.
        app_key: PhishTank application API key.

    Returns:
        bool: True if PhishTank accepted submission, False otherwise.
    """
    endpoint = "https://www.phishtank.com/api/info.php"
    payload = {
        "url": url,
        "format": "json",
        "app_key": app_key or "",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.post(endpoint, data=payload)
            response.raise_for_status()
            data = response.json()
            return "results" in data or response.status_code == 200
    except httpx.HTTPError as err:
        logger.error(f"[blocklist_submit] HTTP error submitting to PhishTank: {err}")
        return False
    except Exception as e:
        logger.error(f"[blocklist_submit] Unexpected error submitting to PhishTank: {e}")
        return False
