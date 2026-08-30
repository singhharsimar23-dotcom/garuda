"""
Continuous Evidence Stream Observer & Processor
Maintains persistent asyncio subscription/polling over telemetry tables, feeding the internal processing queue.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from campaign import get_campaign_manager
try:
    from sentinel_config import get_settings
except ImportError:
    from config import get_settings
try:
    from sentinel_fusion import get_fusion_engine
except ImportError:
    from fusion import get_fusion_engine


from hypothesis import get_hypothesis_synthesizer
try:
    from sentinel_models import CampaignState, EvidenceNode, ObservationEvent
except ImportError:
    from models import CampaignState, EvidenceNode, ObservationEvent
from sidecopy import get_sidecopy_model


logger = logging.getLogger("sentinel.observation")


class ObservationLoop:
    """
    Subscribes to telemetry events, enqueues them, and coordinates agent processing loops.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.queue: asyncio.Queue[ObservationEvent] = asyncio.Queue()
        self.is_running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._recent_eppi_by_host: Dict[str, List[Dict[str, Any]]] = {}

    def enqueue_event(self, table: str, record: Dict[str, Any], action: str = "INSERT") -> None:
        """Push observation event into internal queue."""
        evt = ObservationEvent(table=table, action=action, record=record)
        self.queue.put_nowait(evt)

    async def start(self, supabase_client=None) -> None:
        """Start the persistent observation processing loop."""
        self.is_running = True
        logger.info("Starting SENTINEL continuous observation processing loop...")
        self._loop_task = asyncio.create_task(self._process_queue_loop(supabase_client))

    async def stop(self) -> None:
        """Stop processing loop."""
        self.is_running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        logger.info("SENTINEL observation processing loop stopped.")

    async def _process_queue_loop(self, supabase_client=None) -> None:
        """Main queue consumer running at 10Hz (conflict mode) or 1Hz (standard)."""
        while self.is_running:
            delay = 0.1 if self.settings.conflict_mode else 1.0
            try:
                # Process all items currently available in queue
                while not self.queue.empty():
                    event = await self.queue.get()
                    await self._handle_event(event, supabase_client)
                    self.queue.task_done()
            except Exception as e:
                logger.error(f"Error in observation processing loop: {e}", exc_info=True)

            await asyncio.sleep(delay)

    async def _handle_event(self, event: ObservationEvent, supabase_client=None) -> None:
        """Dispatches event to appropriate subsystem handlers."""
        table = event.table
        record = event.record

        if table == "physics_observations":
            await self._handle_physics_observation(record, supabase_client)
        elif table == "eppi_provdag_graphs":
            self._handle_eppi_event(record)
        elif table == "dharma_action_log":
            await self._handle_dharma_action(record, supabase_client)

    async def _handle_physics_observation(self, record: Dict[str, Any], supabase_client=None) -> None:
        """Process a physical microarchitecture anomaly from AXIOM-II."""
        hostname = record.get("hostname", "unknown")
        ias_score = float(record.get("ias_score", 0.0))
        rec_id = str(record.get("id") or uuid.uuid4())
        obs_time = datetime.now(timezone.utc)

        # 1. Retrieve Recent EPPI Events
        recent_eppi = self._recent_eppi_by_host.get(hostname, [])

        # 2. Compute Multi-Stream Fusion Score
        fusion_engine = get_fusion_engine()
        fusion_score = fusion_engine.compute_fusion_score(
            ias_score=ias_score,
            recent_eppi_events=recent_eppi,
            stix_matches=0,
            tension_index=0.45,
        )

        # 3. Update Parallel SideCopy Model
        sidecopy_model = get_sidecopy_model()
        sidecopy_posterior = sidecopy_model.update_observation(
            hostname=hostname,
            ias_score=ias_score,
            top_channels=list(record.get("channel_sigmas", {}).keys()),
        )

        # 4. Construct Evidence Node
        evidence_node = EvidenceNode(
            id=rec_id,
            source_table="physics_observations",
            event_type="PHYSICS_ANOMALY",
            details={
                "ias_score": ias_score,
                "fusion_score": fusion_score,
                "workload_class": record.get("workload_class", "GENERAL"),
                "channel_sigmas": record.get("channel_sigmas", {}),
            },
            timestamp=obs_time,
            weight=1.0,
        )

        # 5. Update Campaign State
        camp_mgr = get_campaign_manager()
        state = await camp_mgr.update_host_campaign(
            hostname=hostname,
            ias_score=ias_score,
            fusion_score=fusion_score,
            evidence_node=evidence_node,
            sidecopy_posterior=sidecopy_posterior,
            supabase_client=supabase_client,
        )

        # 6. Synthesize Operational Hypothesis
        if fusion_score >= self.settings.fusion_log_threshold and state.campaign_id:
            hypo_synth = get_hypothesis_synthesizer()
            summary = [e.dict() for e in state.evidence_chain[-3:]]
            hypothesis_text = await hypo_synth.generate_hypothesis(
                campaign_id=state.campaign_id,
                hostname=hostname,
                top_tactic="execution",
                fusion_score=fusion_score,
                evidence_chain_summary=summary,
                observed_technique_ids=["T1059.005", "T1055.012"],
                brahma_attribution_status=state.attribution_status,
            )
            state.hypothesis = hypothesis_text

    def _handle_eppi_event(self, record: Dict[str, Any]) -> None:
        """Accumulate EPPI events per host."""
        hostname = record.get("hostname", "unknown")
        if hostname not in self._recent_eppi_by_host:
            self._recent_eppi_by_host[hostname] = []

        self._recent_eppi_by_host[hostname].append(record)
        if len(self._recent_eppi_by_host[hostname]) > 50:
            self._recent_eppi_by_host[hostname].pop(0)

    async def _handle_dharma_action(self, record: Dict[str, Any], supabase_client=None) -> None:
        """Handle DHARMA containment execution feedback."""
        hostname = record.get("hostname", "unknown")
        action_name = record.get("action_name", "UNKNOWN_ACTION")
        camp_mgr = get_campaign_manager()
        state = camp_mgr.get_or_create_host_state(hostname)
        if action_name not in state.dharma_actions:
            state.dharma_actions.append(action_name)


_observation_loop = ObservationLoop()


def get_observation_loop() -> ObservationLoop:
    return _observation_loop
