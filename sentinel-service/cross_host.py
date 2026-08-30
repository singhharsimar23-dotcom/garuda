"""
Cross-Host Kill Chain & Lateral Movement Correlator
Chains multi-host adversarial progressions across network endpoints and confirms lateral movement.
"""

from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional, Tuple
import httpx

try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings
try:
    from sentinel_models import MultiHostLink
except ImportError:
    from models import MultiHostLink



logger = logging.getLogger("sentinel.cross_host")

VALID_TRANSITIONS = {
    "initial-access": {"execution", "discovery"},
    "execution": {"defense-evasion", "privilege-escalation", "credential-access", "discovery"},
    "credential-access": {"lateral-movement", "discovery"},
    "discovery": {"lateral-movement", "collection"},
    "lateral-movement": {"execution", "collection", "command-and-control"},
    "collection": {"exfiltration", "command-and-control"},
    "command-and-control": {"exfiltration", "impact"},
}


class CrossHostCorrelator:
    """
    Correlates cross-host attack sequences and confirms distributed lateral movement.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._active_links: List[MultiHostLink] = []

    async def correlate_cross_host_activity(
        self,
        host_observations: Dict[str, Dict[str, Any]],
        host_eppi_connects: Optional[Dict[str, List[str]]] = None,
        supabase_client=None,
    ) -> List[MultiHostLink]:
        """
        Evaluate pairs of hosts with anomalies within 30-minute window.
        """
        now = datetime.now(timezone.utc)
        confirmed_links = []
        host_list = list(host_observations.keys())

        for i in range(len(host_list)):
            for j in range(i + 1, len(host_list)):
                host_a = host_list[i]
                host_b = host_list[j]

                obs_a = host_observations[host_a]
                obs_b = host_observations[host_b]

                tactic_a = obs_a.get("top_tactic", "execution").lower()
                tactic_b = obs_b.get("top_tactic", "lateral-movement").lower()

                time_a = obs_a.get("timestamp") or now
                time_b = obs_b.get("timestamp") or now

                # Check 30-minute window
                time_diff = abs((time_a - time_b).total_seconds())
                if time_diff > 1800.0:
                    continue

                # Check valid kill chain transition (either A -> B or B -> A)
                is_valid_seq = (
                    tactic_b in VALID_TRANSITIONS.get(tactic_a, set())
                    or tactic_a in VALID_TRANSITIONS.get(tactic_b, set())
                    or tactic_a == tactic_b
                )

                if is_valid_seq:
                    fusion_a = float(obs_a.get("fusion_score", 3.0))
                    fusion_b = float(obs_b.get("fusion_score", 3.0))
                    joint_score = round(max(fusion_a, fusion_b) * 1.5, 4)

                    # Check Lateral Movement Confirmation Criteria:
                    # 1. Cross-host pair linked
                    # 2. Time delta < 4h
                    # 3. EPPI CONNECT from A to B
                    # 4. Same actor attribution
                    eppi_connected = False
                    if host_eppi_connects:
                        connected_ips = host_eppi_connects.get(host_a, [])
                        b_ip = obs_b.get("ip_address")
                        if b_ip and b_ip in connected_ips:
                            eppi_connected = True

                    actor_a = obs_a.get("attribution_actor", "APT36")
                    actor_b = obs_b.get("attribution_actor", "APT36")

                    is_confirmed = (time_diff <= 14400.0) and eppi_connected and (actor_a == actor_b)

                    link = MultiHostLink(
                        host_a=host_a,
                        host_b=host_b,
                        tactic_a=tactic_a,
                        tactic_b=tactic_b,
                        joint_fusion_score=joint_score,
                        lateral_movement_confirmed=is_confirmed,
                        campaign_ids=[
                            str(obs_a.get("campaign_id", "")),
                            str(obs_b.get("campaign_id", "")),
                        ],
                    )
                    confirmed_links.append(link)

                    # Trigger simultaneous DHARMA containment if joint score >= 5.0 (CRITICAL)
                    if joint_score >= 5.0:
                        await self._dispatch_dharma_emergency(host_a, host_b, joint_score)

                    # Persist to Supabase
                    if supabase_client:
                        try:
                            supabase_client.table("multi_host_campaigns").insert({
                                "host_a": host_a,
                                "host_b": host_b,
                                "tactic_a": tactic_a,
                                "tactic_b": tactic_b,
                                "joint_fusion_score": joint_score,
                                "lateral_movement_confirmed": is_confirmed,
                            }).execute()
                        except Exception as e:
                            logger.debug(f"Failed inserting multi_host_campaigns to Supabase: {e}")

        self._active_links = confirmed_links
        return confirmed_links

    async def _dispatch_dharma_emergency(self, host_a: str, host_b: str, joint_score: float) -> None:
        """Trigger DHARMA emergency isolation on coordinated lateral movement."""
        if not self.settings.dharma_service_url:
            return

        endpoint = f"{self.settings.dharma_service_url.rstrip('/')}/api/v1/dharma/evaluate"
        headers = {"Content-Type": "application/json"}

        for host in [host_a, host_b]:
            payload = {
                "hostname": host,
                "ias_score": joint_score,
                "attribution_status": "ATTRIBUTED — APT36 (Transparent Tribe)",
                "lateral_movement_suspected": True,
            }
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    await client.post(endpoint, headers=headers, json=payload)
                    logger.info(f"Dispatched DHARMA emergency isolation for {host} (Joint Score: {joint_score:.2f}).")
            except Exception as e:
                logger.warning(f"Failed dispatching DHARMA emergency trigger for {host}: {e}")


_cross_host_correlator = CrossHostCorrelator()


def get_cross_host_correlator() -> CrossHostCorrelator:
    return _cross_host_correlator
