from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from garuda.database import get_supabase_client
from garuda.response.alerts import dispatch_alert

logger = logging.getLogger("garuda.intelligence.cluster")

REGISTRAR_MAP = {
    "namecheap": 1,
    "pdr ltd": 2,
    "publicdomainregistry": 2,
    "enom": 3,
    "epik": 4,
    "godaddy": 5,
    "other": 99,
}

SECTOR_MAP = {
    "mod": 1,
    "ministry of defence (mod)": 1,
    "nic": 2,
    "national informatics centre (nic)": 2,
    "drdo": 3,
    "defence r&d (drdo)": 3,
    "army": 4,
    "navy": 5,
    "iaf": 6,
    "air force": 6,
    "other": 99,
}

HISTORICAL_AVG_ATTACK_WINDOW_DAYS = 19.3


def _encode_registrar(registrar: Optional[str]) -> int:
    if not registrar:
        return REGISTRAR_MAP["other"]
    reg_clean = registrar.lower().strip()
    for k, v in REGISTRAR_MAP.items():
        if k in reg_clean:
            return v
    return REGISTRAR_MAP["other"]


def _encode_subnet24(ip: Optional[str]) -> int:
    if not ip or "." not in ip:
        return 0
    parts = ip.strip().split(".")
    if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
        # "185.220.101" -> 185220101
        return int(f"{int(parts[0]):03d}{int(parts[1]):03d}{int(parts[2]):03d}")
    return 0


def _encode_sector(sector: Optional[str]) -> int:
    if not sector:
        return SECTOR_MAP["other"]
    sec_clean = sector.lower().strip()
    for k, v in SECTOR_MAP.items():
        if k in sec_clean:
            return v
    return SECTOR_MAP["other"]


def _encode_time_bucket(timestamp_val: Any) -> int:
    if not timestamp_val:
        return int(datetime.now(timezone.utc).timestamp() // (72 * 3600))
    if isinstance(timestamp_val, str):
        try:
            dt = datetime.fromisoformat(timestamp_val.replace("Z", "+00:00"))
            return int(dt.timestamp() // (72 * 3600))
        except Exception:
            pass
    elif isinstance(timestamp_val, (datetime,)):
        return int(timestamp_val.timestamp() // (72 * 3600))
    return int(datetime.now(timezone.utc).timestamp() // (72 * 3600))


def encode_features(alerts: List[Dict[str, Any]]) -> np.ndarray:
    """
    Transform raw threat alert attributes into normalized numeric feature vectors for DBSCAN.

    Vector Schema:
        [encode_registrar, encode_asn, encode_subnet24, encode_sector, time_bucket_72h]

    Args:
        alerts: List of alert dictionaries from database.

    Returns:
        np.ndarray: 2D numpy array of shape (N, 5).
    """
    matrix: List[List[float]] = []
    for a in alerts:
        signals = a.get("signals", {})
        registrar = a.get("registrar") or signals.get("registrar")
        asn = int(a.get("hosting_asn") or signals.get("hosting_asn") or 0)
        ip = a.get("hosting_ip") or signals.get("hosting_ip")
        sector = a.get("sector") or signals.get("sector")
        dt_val = a.get("detected_at") or a.get("created_at")

        vector = [
            float(_encode_registrar(registrar)),
            float(asn),
            float(_encode_subnet24(ip)),
            float(_encode_sector(sector)),
            float(_encode_time_bucket(dt_val)),
        ]
        matrix.append(vector)

    return np.array(matrix, dtype=np.float64)


async def detect_campaigns(window_hours: int = 72) -> List[Dict[str, Any]]:
    """
    Discover correlated multi-domain APT36 attack campaigns using spatial-temporal DBSCAN clustering.

    Workflow:
        1. Fetch alerts created within the last window_hours with status != 'false_positive'.
        2. Encode alerts into 5-dimensional feature vectors.
        3. Fit StandardScaler and DBSCAN(eps=1.5, min_samples=2).
        4. Group clustered alerts and calculate attack window forecast:
           estimated_attack_window = avg_days_registration_to_attack (19.3) - mean(domain_age_days).
        5. Persist campaign to 'campaigns' table and update cluster_id on member alerts.
        6. Dispatch CRITICAL automated alert for every newly detected campaign cluster.

    Args:
        window_hours: Lookback window in hours (default: 72).

    Returns:
        List[Dict[str, Any]]: List of discovered campaign clusters.
    """
    client = get_supabase_client()
    alerts: List[Dict[str, Any]] = []

    if client:
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
            res = (
                client.table("alerts")
                .select("*")
                .gte("created_at", cutoff)
                .neq("status", "false_positive")
                .execute()
            )
            alerts = res.data or []
        except Exception as e:
            logger.error(f"[cluster] Error fetching alerts from Supabase: {e}")

    if len(alerts) < 2:
        logger.info(f"[cluster] Insufficient alert volume ({len(alerts)}) for DBSCAN clustering.")
        return []

    # Encode feature vectors
    x_raw = encode_features(alerts)

    # Standardize features and run DBSCAN
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_raw)
    db = DBSCAN(eps=1.5, min_samples=2).fit(x_scaled)
    labels = db.labels_

    campaigns: List[Dict[str, Any]] = []
    unique_labels = set(labels)

    for label in unique_labels:
        if label == -1:
            # Noise points
            continue

        member_indices = [i for i, lbl in enumerate(labels) if lbl == label]
        cluster_alerts = [alerts[i] for i in member_indices]
        cluster_id = f"CAMP-APT36-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{label:02d}"

        # Aggregate sectors and metadata
        sectors_set = set()
        registrars_set = set()
        asns_set = set()
        age_list: List[float] = []

        for item in cluster_alerts:
            sec = item.get("sector")
            if sec:
                sectors_set.add(sec)
            reg = item.get("registrar")
            if reg:
                registrars_set.add(reg)
            asn_val = item.get("hosting_asn")
            if asn_val:
                asns_set.add(int(asn_val))

            age = item.get("signals", {}).get("domain_age_days")
            if age is not None and isinstance(age, (int, float)):
                age_list.append(float(age))

        mean_age = float(np.mean(age_list)) if age_list else 5.0
        estimated_attack_window = max(1, int(round(HISTORICAL_AVG_ATTACK_WINDOW_DAYS - mean_age)))

        campaign_entry = {
            "cluster_id": cluster_id,
            "domain_count": len(cluster_alerts),
            "registrar": next(iter(registrars_set), "Mixed"),
            "hosting_asn": next(iter(asns_set), 0),
            "sectors": list(sectors_set),
            "estimated_attack_window_days": estimated_attack_window,
            "confidence": "high" if len(cluster_alerts) >= 3 else "medium",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Write campaign to Supabase & update member alerts
        if client:
            try:
                client.table("campaigns").upsert(campaign_entry, on_conflict="cluster_id").execute()
                for member in cluster_alerts:
                    member_id = member.get("id")
                    if member_id:
                        client.table("alerts").update({"cluster_id": cluster_id}).eq("id", member_id).execute()
            except Exception as e:
                logger.error(f"[cluster] Failed writing campaign {cluster_id} to Supabase: {e}")

        # Dispatch critical alert for new campaign
        await dispatch_alert({
            "domain": f"Campaign {cluster_id} ({len(cluster_alerts)} correlated domains)",
            "score": 95,
            "sector": ", ".join(sectors_set) if sectors_set else "National Security",
            "signals": campaign_entry,
        })

        campaigns.append(campaign_entry)

    logger.info(f"[cluster] Campaign detection completed: Discovered {len(campaigns)} active clusters.")
    return campaigns
