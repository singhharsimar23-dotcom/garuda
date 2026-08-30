"""
EPPI Ingestion & Process Provenance DAG Engine
Processes kernel eBPF kprobe events, builds parent-child provenance graphs,
correlates physical execution spikes (100ms window), and dispatches DHARMA containment.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import httpx

from config import get_settings

logger = logging.getLogger("axiom.eppi_engine")

# Known APT36 / Transparent Tribe payload comm identifiers
APT36_PAYLOAD_SIGNATURES = [
    "elizarat", "crimsonrat", "caprarat", "obliquerat",
    "actionrat", "mythicleopard", "transparenttribe",
    "c-major", "vbs_worker", "payload_worker", "trojan"
]


class EPPIProcessor:
    """
    Ingests eBPF events, builds Process Provenance DAGs, and performs physical correlation.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._prov_graphs: Dict[str, Dict[int, List[int]]] = defaultdict(lambda: defaultdict(list))
        self._recent_physics_spikes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def record_physics_spike(self, hostname: str, ias_score: float, observed_at_iso: str) -> None:
        """Record high IAS event for 100ms / 500ms EPPI correlation."""
        try:
            dt = datetime.fromisoformat(observed_at_iso.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)

        self._recent_physics_spikes[hostname].append({
            "ias_score": ias_score,
            "timestamp": dt,
        })
        # Retain only last 50 spikes
        if len(self._recent_physics_spikes[hostname]) > 50:
            self._recent_physics_spikes[hostname].pop(0)

    def _is_physics_corroborated(self, hostname: str, event_time: datetime, window_ms: int = 100) -> bool:
        """Check if any physical anomaly spike occurred within window_ms of the eBPF event."""
        spikes = self._recent_physics_spikes.get(hostname, [])
        for spk in spikes:
            diff_ms = abs((event_time - spk["timestamp"]).total_seconds() * 1000.0)
            if diff_ms <= window_ms and spk["ias_score"] >= 3.0:
                return True
        return False

    async def process_events(
        self,
        hostname: str,
        events: List[Dict[str, Any]],
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Process batch of EPPI eBPF events from a monitored host.
        """
        processed_rows = []
        high_confidence_matches = 0
        physics_corroborated_events = 0
        trigger_brahma_tasks = []

        for evt in events:
            pid = int(evt.get("pid", 0))
            ppid = int(evt.get("ppid", 0))
            comm = str(evt.get("comm", "")).lower()
            evt_type = evt.get("event_type", "UNKNOWN")
            ts_str = evt.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()

            try:
                event_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                event_dt = datetime.now(timezone.utc)

            # Build Provenance DAG edge (ppid -> pid)
            if ppid > 0 and pid > 0:
                if pid not in self._prov_graphs[hostname][ppid]:
                    self._prov_graphs[hostname][ppid].append(pid)

            # Check APT36 Payload Signature Match
            is_apt36_match = any(sig in comm or (evt.get("filename") and sig in str(evt.get("filename")).lower())
                                for sig in APT36_PAYLOAD_SIGNATURES)
            if is_apt36_match:
                high_confidence_matches += 1

            # Check 100ms Physics Corroboration
            is_phys_corroborated = self._is_physics_corroborated(hostname, event_dt, window_ms=100)
            if is_phys_corroborated:
                physics_corroborated_events += 1

            # Check 500ms MMAP_EXEC Trigger for T1055.012 Process Hollowing
            if evt_type == "MMAP_EXEC" and self._is_physics_corroborated(hostname, event_dt, window_ms=500):
                trigger_brahma_tasks.append((hostname, pid))

            row = {
                "hostname": hostname,
                "pid": pid,
                "ppid": ppid,
                "event_type": evt_type,
                "comm": evt.get("comm", ""),
                "details": {
                    "filename": evt.get("filename"),
                    "remote_addr": evt.get("remote_addr"),
                    "remote_port": evt.get("remote_port"),
                    "mmap_addr": evt.get("mmap_addr"),
                    "mmap_len": evt.get("mmap_len"),
                    "apt36_signature_match": is_apt36_match,
                    "physics_corroborated": is_phys_corroborated,
                },
                "timestamp_utc": ts_str,
            }
            processed_rows.append(row)

        # Dispatch BRAHMA triggers for T1055 process injection if corroborated
        for host, target_pid in trigger_brahma_tasks:
            await self._forward_brahma_eppi_trigger(host, target_pid)

        # Persist to Supabase if configured
        if supabase_client and processed_rows:
            try:
                supabase_client.table("eppi_provdag_graphs").insert(processed_rows).execute()
            except Exception as e:
                logger.warning(f"Failed inserting eppi_provdag_graphs to Supabase: {e}")

        logger.info(
            f"[EPPI PROCESS] Host '{hostname}': {len(events)} events processed "
            f"(APT36 Matches: {high_confidence_matches}, Physics Corroborated: {physics_corroborated_events})"
        )

        return {
            "status": "success",
            "hostname": hostname,
            "events_count": len(events),
            "high_confidence_matches": high_confidence_matches,
            "physics_corroborated_events": physics_corroborated_events,
            "dag_nodes": len(self._prov_graphs[hostname]),
        }

    async def _forward_brahma_eppi_trigger(self, hostname: str, pid: int) -> None:
        """Asynchronously notify BRAHMA of EPPI corroborated T1055 execution."""
        if not self.settings.brahma_service_url:
            return

        url = f"{self.settings.brahma_service_url.rstrip('/')}/internal/observe"
        headers = {
            "X-Inter-Service-Secret": self.settings.inter_service_secret,
            "Content-Type": "application/json",
        }
        payload = {
            "hostname": hostname,
            "ias_score": 4.5,
            "channel_sigmas": {"perf_cache_miss": 4.5, "rapl_pkg": 3.8},
            "workload_class": "EXECUTION",
            "eppi_technique_id": "T1055.012",
            "source": "EPPI_EBPF_PROVDAG",
        }

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(url, headers=headers, json=payload)
                logger.info(f"Triggered BRAHMA observation for EPPI T1055.012 on PID {pid} ({hostname}).")
        except Exception as e:
            logger.warning(f"Failed triggering BRAHMA from EPPI: {e}")


_eppi_processor = EPPIProcessor()


def get_eppi_processor() -> EPPIProcessor:
    return _eppi_processor
