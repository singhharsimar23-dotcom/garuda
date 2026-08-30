"""
Canary Token Trigger Handler
Immediate high-fidelity trigger that bypasses attribution gating and orchestrates instant DHARMA Tier 2 containment.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import httpx
from fastapi import APIRouter, Header, Request, status

from campaign import get_campaign_manager
try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings
try:
    from sentinel_models import CanaryTriggerPayload
except ImportError:
    from models import CanaryTriggerPayload



logger = logging.getLogger("sentinel.canary")
router = APIRouter(prefix="/webhook", tags=["Canary"])


class CanaryManager:
    """
    Orchestrates high-priority actions on canary token activation.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()

    async def handle_canary_trip(
        self,
        token_id: str,
        requester_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Executes immediate canary response: bypasses attribution gating, dispatches DHARMA Tier 2, and boosts BRAHMA priors.
        """
        now = datetime.now(timezone.utc)
        target_host = (details or {}).get("hostname", "canary-trap-node")

        # 1. Update Campaign State to CONFIRMED (Bypassing all Gating Rules)
        camp_mgr = get_campaign_manager()
        state = camp_mgr.get_or_create_host_state(target_host)
        state.attribution_status = "CONFIRMED — APT36 (Transparent Tribe)"
        state.peak_ias = max(state.peak_ias, 9.5)
        state.fusion_score = 9.8

        logger.critical(f"🚨 CANARY TOKEN '{token_id}' TRIGGERED! Attacker IP: {requester_ip}. Bypassing attribution gating.")

        # 2. Record Canary Event in physics_observations
        if supabase_client:
            try:
                supabase_client.table("physics_observations").insert({
                    "hostname": target_host,
                    "observed_at": now.isoformat(),
                    "ias_score": 9.5,
                    "workload_class": "CANARY_TRIP",
                    "flags": ["CANARY_TRIGGERED", "HIGH_CONFIDENCE_BREACH"],
                }).execute()
            except Exception as e:
                logger.debug(f"Failed logging canary trip to Supabase: {e}")

        # 3. Trigger DHARMA Tier 2 Immediately (Auto-execute DNS sinkhole & isolation)
        dharma_ok = await self._dispatch_dharma_tier2(target_host, requester_ip)

        # 4. Send Telegram Alert
        await self._send_telegram_alert(
            f"🚨 *[CANARY TOKEN TRIGGERED]*\nDecoy document opened from IP `{requester_ip or 'UNKNOWN'}`!\n"
            f"Token ID: `{token_id}`\nAttribution Status: *CONFIRMED*\nDHARMA Tier 2 Containment: *DISPATCHED*"
        )

        # 5. POST to BRAHMA: 100x Alpha Update
        brahma_ok = await self._boost_brahma_priors(target_host, tactic="initial-access", multiplier=100.0)

        return {
            "status": "success",
            "token_id": token_id,
            "attribution_status": "CONFIRMED",
            "dharma_tier2_triggered": dharma_ok,
            "brahma_boosted": brahma_ok,
        }

    async def _dispatch_dharma_tier2(self, hostname: str, requester_ip: Optional[str]) -> bool:
        """Trigger DHARMA Tier 2 auto-execution endpoint."""
        if not self.settings.dharma_service_url:
            return True

        url = f"{self.settings.dharma_service_url.rstrip('/')}/api/v1/dharma/evaluate"
        headers = {"Content-Type": "application/json"}
        payload = {
            "hostname": hostname,
            "ias_score": 9.5,
            "attribution_status": "ATTRIBUTED — APT36 (Transparent Tribe)",
            "attacker_ip": requester_ip or "0.0.0.0",
            "force_tier2": True,
        }

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code in (200, 201)
        except Exception as e:
            logger.warning(f"Failed triggering DHARMA on canary trip: {e}")
            return False

    async def _boost_brahma_priors(self, hostname: str, tactic: str, multiplier: float) -> bool:
        """Post 100x alpha update to BRAHMA."""
        if not self.settings.brahma_service_url:
            return True

        url = f"{self.settings.brahma_service_url.rstrip('/')}/internal/observe"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        payload = {
            "hostname": hostname,
            "ias_score": 9.5,
            "workload_class": "CANARY",
            "channel_sigmas": {"rapl_pkg": 10.0, "perf_cache_miss": 10.0},
            "weight_multiplier": multiplier,
            "source": "CANARY_TOKEN_ACTIVATION",
        }

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code in (200, 201)
        except Exception as e:
            logger.debug(f"Failed boosting BRAHMA on canary trip: {e}")
            return False

    async def _send_telegram_alert(self, msg: str) -> None:
        """Send urgent canary alert to Telegram."""
        if not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.info(f"[TELEGRAM CANARY]: {msg}")
            return
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(url, json={
                    "chat_id": self.settings.telegram_chat_id,
                    "text": msg,
                    "parse_mode": "Markdown",
                })
        except Exception as e:
            logger.debug(f"Telegram canary alert failed: {e}")


_canary_manager = CanaryManager()


def get_canary_manager() -> CanaryManager:
    return _canary_manager


@router.post(
    "/canary/{token_id}",
    status_code=status.HTTP_200_OK,
)
async def canary_webhook_endpoint(
    token_id: str,
    request: Request,
):
    """
    Webhook target called when an external decoy canary token is opened.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent")

    body_data = {}
    try:
        body_data = await request.json()
    except Exception:
        pass

    mgr = get_canary_manager()
    result = await mgr.handle_canary_trip(
        token_id=token_id,
        requester_ip=body_data.get("requester_ip") or client_ip,
        user_agent=user_agent,
        details=body_data,
    )
    return result
