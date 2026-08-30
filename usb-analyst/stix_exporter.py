"""
Air-Gapped STIX 2.1 Exporter
Converts local physical anomaly findings and EPPI causal chains into standard STIX 2.1 JSON bundles.
"""

from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Any, Dict, List

logger = logging.getLogger("garuda.analyst.stix")


def export_alerts_to_stix_bundle(
    alerts: List[Dict[str, Any]],
    hostname: str = "classified-endpoint",
) -> Dict[str, Any]:
    """
    Creates a compliant STIX 2.1 Bundle containing observed-data and indicator objects.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    stix_objects = []

    # 1. Identity Object (GARUDA Defense Agent)
    identity_id = "identity--5e24a49c-garuda-defense"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "GARUDA Physical Intrusion Defense System",
        "identity_class": "system",
    })

    # 2. Add Indicator / Observed Data per Alert
    for a in alerts:
        alert_id = a.get("alert_id", str(uuid.uuid4())[:8])
        ias_score = a.get("ias_score", 0.0)
        level = a.get("level", "MEDIUM")

        obs_id = f"observed-data--{uuid.uuid4()}"
        stix_objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created_by_ref": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "first_observed": now_iso,
            "last_observed": now_iso,
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "x-garuda-physics-anomaly",
                    "hostname": hostname,
                    "ias_score": ias_score,
                    "level": level,
                    "top_channels": a.get("top_channels", []),
                }
            },
        })

        # Indicator
        ind_id = f"indicator--{uuid.uuid4()}"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created_by_ref": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"GARUDA Physical Divergence on {hostname}",
            "description": f"Microarchitectural divergence detected with IAS score {ias_score:.2f} σ ({level}).",
            "indicator_types": ["anomalous-activity"],
            "pattern": f"[x-garuda-physics-anomaly:ias_score >= {ias_score:.2f}]",
            "pattern_type": "stix",
            "valid_from": now_iso,
        })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects,
    }

    return bundle
