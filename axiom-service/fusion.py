"""
Fleet-Wide Multi-Sensor Fusion Engine
Correlates physical side-channel observations across distributed hosts in 5-minute rolling windows
to detect coordinated lateral movement campaigns across clusters.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from models import FleetFusionAlert

logger = logging.getLogger("axiom.fusion")

FUSION_WINDOW_MINUTES = 5
MIN_HOST_COUNT_FOR_LATERAL_ALERT = 3
MEDIUM_IAS_THRESHOLD = 3.0


class FleetFusionEngine:
    """
    Analyzes fleet-wide physics telemetry for synchronized microarchitectural anomalies.
    """

    def __init__(self):
        self._in_memory_observations: List[Dict[str, Any]] = []

    def record_observation(self, observation: Dict[str, Any]) -> None:
        """Track observation locally for in-memory fusion evaluation."""
        self._in_memory_observations.append(observation)
        # Keep last 15 minutes of observations in memory
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
        self._in_memory_observations = [
            obs for obs in self._in_memory_observations
            if obs.get("observed_at_dt", datetime.now(timezone.utc)) >= cutoff
        ]

    def evaluate_fleet_fusion(
        self,
        supabase_client=None,
        window_minutes: int = FUSION_WINDOW_MINUTES,
    ) -> List[FleetFusionAlert]:
        """
        Query physics observations over the rolling window, group by workload_class,
        and generate LATERAL_MOVEMENT alerts if >= 3 hosts exhibit IAS >= MEDIUM.
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=window_minutes)
        window_start_iso = window_start.isoformat()

        recent_records: List[Dict[str, Any]] = []

        # 1. Fetch from Supabase if available
        if supabase_client:
            try:
                res = (
                    supabase_client.table("physics_observations")
                    .select("hostname, workload_class, ias_score, observed_at")
                    .gte("observed_at", window_start_iso)
                    .gte("ias_score", MEDIUM_IAS_THRESHOLD)
                    .execute()
                )
                if res.data:
                    recent_records = res.data
            except Exception as e:
                logger.warning(f"Failed to query physics_observations from Supabase: {e}")

        # 2. Fall back / merge with local in-memory records
        if not recent_records and self._in_memory_observations:
            recent_records = [
                obs for obs in self._in_memory_observations
                if obs.get("observed_at_dt", now) >= window_start
                and float(obs.get("ias_score", 0.0)) >= MEDIUM_IAS_THRESHOLD
            ]

        # Group anomalous hosts by workload class
        grouped_by_workload: Dict[str, set] = defaultdict(set)
        host_scores: Dict[str, float] = {}

        for rec in recent_records:
            host = rec.get("hostname")
            wclass = rec.get("workload_class") or "UNSPECIFIED"
            score = float(rec.get("ias_score", 0.0))
            if host:
                grouped_by_workload[wclass].add(host)
                host_scores[host] = max(host_scores.get(host, 0.0), score)

        alerts_generated: List[FleetFusionAlert] = []

        for wclass, hosts in grouped_by_workload.items():
            if len(hosts) >= MIN_HOST_COUNT_FOR_LATERAL_ALERT:
                host_list = sorted(list(hosts))
                alert_id = f"ALERT-FLEET-{uuid.uuid4().hex[:8].upper()}"
                
                # Evidence description without artificial percentage
                evidence = (
                    f"Fleet-wide correlated physics anomaly: {len(host_list)} hosts "
                    f"({', '.join(host_list)}) concurrently exhibited elevated Integrated Anomaly Scores "
                    f"(IAS >= {MEDIUM_IAS_THRESHOLD}) in workload group '{wclass}' within a {window_minutes}-minute window."
                )

                alert = FleetFusionAlert(
                    alert_id=alert_id,
                    alert_type="LATERAL_MOVEMENT",
                    confidence_source="FLEET_CORRELATION",
                    affected_hosts=host_list,
                    workload_class=wclass,
                    window_start=window_start,
                    window_end=now,
                    evidence_description=evidence,
                )
                alerts_generated.append(alert)

                logger.critical(
                    f"[FLEET FUSION ALERT] LATERAL_MOVEMENT detected across {len(host_list)} hosts: {host_list}"
                )

                # Write to anomaly_alerts in Supabase
                if supabase_client:
                    try:
                        db_payload = {
                            "alert_id": alert_id,
                            "hostname": host_list[0],  # Primary or cluster lead
                            "type": "LATERAL_MOVEMENT",
                            "alert_type": "LATERAL_MOVEMENT",
                            "ias_score": round(max(host_scores.values()), 4),
                            "confidence_source": "FLEET_CORRELATION",
                            "details": {
                                "affected_hosts": host_list,
                                "workload_class": wclass,
                                "window_start": window_start.isoformat(),
                                "window_end": now.isoformat(),
                                "evidence": evidence,
                            },
                            "detected_at": now.isoformat(),
                        }
                        supabase_client.table("anomaly_alerts").insert(db_payload).execute()
                    except Exception as e:
                        logger.warning(f"Failed to record fleet alert to anomaly_alerts table: {e}")

        return alerts_generated


_fusion_engine = FleetFusionEngine()


def get_fusion_engine() -> FleetFusionEngine:
    return _fusion_engine
