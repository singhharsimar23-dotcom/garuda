from datetime import datetime, timedelta, timezone
import json
import logging
import threading
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from supabase import Client, create_client

from garuda.config import settings

logger = logging.getLogger("garuda.database")

# ==============================================================================
# Supabase Client Initialization
# ==============================================================================

_supabase_client: Optional[Client] = None
_db_lock = threading.Lock()


def get_supabase_client() -> Optional[Client]:
    """Retrieve or initialize the Supabase client singleton."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if settings.SUPABASE_URL and (settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY):
        url = settings.SUPABASE_URL.strip()
        key = (settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY or "").strip()
        if "your-project" in url or "your-supabase" in key or not url.startswith("http"):
            return None
        try:
            _supabase_client = create_client(url, key)
            return _supabase_client
        except Exception:
            return None

    return None


# ==============================================================================
# Pydantic Table Schema Models
# ==============================================================================


class AlertBase(BaseModel):
    domain: str
    score: int = Field(ge=0, le=100)
    signals: Dict[str, Any] = Field(default_factory=dict)
    registered_at: Optional[datetime] = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    registrar: Optional[str] = None
    hosting_ip: Optional[str] = None
    hosting_asn: Optional[int] = None
    sector: Optional[str] = None
    cluster_id: Optional[str] = None
    status: str = Field(default="pending")
    analyst_id: Optional[str] = None
    analyst_note: Optional[str] = None
    yara_rule: Optional[str] = None
    screenshot_url: Optional[str] = None
    stix_id: Optional[str] = None
    llm_narrative: Optional[str] = None


class AlertCreate(AlertBase):
    pass


class AlertInDB(AlertBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class CampaignBase(BaseModel):
    cluster_id: str
    domain_count: int = Field(default=1, ge=1)
    registrar: Optional[str] = None
    hosting_asn: Optional[int] = None
    sectors: List[str] = Field(default_factory=list)
    estimated_attack_window_days: Optional[int] = None
    confidence: str = Field(default="medium")


class CampaignCreate(CampaignBase):
    pass


class CampaignInDB(CampaignBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class WhitelistBase(BaseModel):
    domain: str
    reason: Optional[str] = None
    analyst_id: Optional[str] = None


class WhitelistCreate(WhitelistBase):
    pass


class WhitelistInDB(WhitelistBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class AuditLogBase(BaseModel):
    alert_id: Optional[UUID] = None
    action: str
    analyst_id: Optional[str] = None
    justification: str


class AuditLogCreate(AuditLogBase):
    pass


class AuditLogInDB(AuditLogBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class TensionLogBase(BaseModel):
    tension_index: float = Field(ge=0.0, le=1.0)
    conflict_mode: bool = False
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TensionLogCreate(TensionLogBase):
    pass


class TensionLogInDB(TensionLogBase):
    id: UUID = Field(default_factory=uuid4)
    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# TAXII 2.1 & STIX 2.1 Pydantic Models
# ==============================================================================


class TaxiiCollectionBase(BaseModel):
    slug: str
    title: str
    description: Optional[str] = None
    can_read: bool = True
    can_write: bool = False
    media_types: List[str] = Field(default_factory=lambda: ["application/stix+json;version=2.1"])


class TaxiiCollectionInDB(TaxiiCollectionBase):
    id: UUID = Field(default_factory=uuid4)
    model_config = ConfigDict(from_attributes=True)


class StixObjectBase(BaseModel):
    id: str
    type: str
    spec_version: str = "2.1"
    created: datetime
    modified: datetime
    collection_id: UUID
    confidence: Optional[int] = None
    india_context: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any]
    revoked: bool = False


class StixObjectInDB(StixObjectBase):
    model_config = ConfigDict(from_attributes=True)


class TaxiiSubscriberBase(BaseModel):
    name: str
    api_key: str
    allowed_collections: List[str] = Field(default_factory=lambda: ["*"])
    active: bool = True


class TaxiiSubscriberInDB(TaxiiSubscriberBase):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


class TaxiiAccessLogBase(BaseModel):
    subscriber_id: Optional[UUID] = None
    collection_id: Optional[UUID] = None
    endpoint: str
    objects_returned: int = 0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class TaxiiAccessLogInDB(TaxiiAccessLogBase):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# In-Memory Fallback Stores for Standalone & Test Environments
# ==============================================================================

_DEFAULT_COLLECTIONS: List[Dict[str, Any]] = [
    {
        "id": "11111111-1111-1111-1111-111111111111",
        "slug": "high-confidence",
        "title": "High Confidence IOCs",
        "description": "Analyst-verified and high-confidence (>70) threat indicators targeting Indian national cyberspace.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "22222222-2222-2222-2222-222222222222",
        "slug": "all-iocs",
        "title": "All Detected Threat IOCs",
        "description": "Complete feed of all automated & analyst-reviewed indicators detected by GARUDA sensor arrays.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "33333333-3333-3333-3333-333333333333",
        "slug": "nic-sector",
        "title": "NIC & Government IT Sector",
        "description": "Threat intelligence targeting National Informatics Centre, Gov.in, and state portal infrastructure.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "44444444-4444-4444-4444-444444444444",
        "slug": "drdo-defence",
        "title": "DRDO & Defence Research Sector",
        "description": "Targeted espionage and infrastructure spoofing indicators against Indian Defence R&D establishments.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "55555555-5555-5555-5555-555555555555",
        "slug": "military-hq",
        "title": "Military HQ & Armed Forces Sector",
        "description": "Threat indicators targeting Tri-Services headquarters, command networks, and defence personnel.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "66666666-6666-6666-6666-666666666666",
        "slug": "generic-government",
        "title": "Generic Public Administration Sector",
        "description": "Threat intelligence covering municipal, PSU, state secretariat, and civil service digital assets.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "77777777-7777-7777-7777-777777777777",
        "slug": "apt36-cluster",
        "title": "APT36 / Transparent Tribe Cluster",
        "description": "Clustered campaign intelligence tracking APT36 infrastructure patterns and state-sponsored espionage.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
]

_IN_MEMORY_COLLECTIONS: Dict[str, Dict[str, Any]] = {c["id"]: dict(c) for c in _DEFAULT_COLLECTIONS}
_IN_MEMORY_STIX_OBJECTS: List[Dict[str, Any]] = []
_IN_MEMORY_SUBSCRIBERS: Dict[str, Dict[str, Any]] = {
    # Default development / test API key
    "garuda-demo-key-1234567890abcdef": {
        "id": "99999999-9999-9999-9999-999999999999",
        "name": "AFCERT / Govt Subscriber Demo",
        "api_key": "garuda-demo-key-1234567890abcdef",
        "allowed_collections": ["*"],
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
}
_IN_MEMORY_ACCESS_LOGS: List[Dict[str, Any]] = []
_IN_MEMORY_RPZ_ENTRIES: List[Dict[str, Any]] = []
_IN_MEMORY_DEFENCE_IPS: List[Dict[str, Any]] = []
_IN_MEMORY_PDNS_OBSERVATIONS: List[Dict[str, Any]] = []
_IN_MEMORY_OPERATOR_CLUSTERS: List[Dict[str, Any]] = []
_IN_MEMORY_CAMPAIGN_FINGERPRINTS: List[Dict[str, Any]] = []
_IN_MEMORY_CLUSTER_REVIEW_QUEUE: List[Dict[str, Any]] = []


# ==============================================================================
# TAXII 2.1 & STIX 2.1 Database Access Operations
# ==============================================================================


async def get_taxii_collections() -> List[Dict[str, Any]]:
    """Retrieve all available TAXII 2.1 collections."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("taxii_collections").select("*").execute()
            if res.data:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_taxii_collections failed, falling back to memory: {e}")

    with _db_lock:
        return list(_IN_MEMORY_COLLECTIONS.values())


async def get_taxii_collection_by_id_or_slug(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single TAXII collection by UUID or slug."""
    client = get_supabase_client()
    if client:
        try:
            # Try UUID first
            try:
                UUID(identifier)
                res = client.table("taxii_collections").select("*").eq("id", identifier).execute()
            except ValueError:
                res = client.table("taxii_collections").select("*").eq("slug", identifier).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase get_taxii_collection failed, falling back: {e}")

    with _db_lock:
        for c in _IN_MEMORY_COLLECTIONS.values():
            if str(c.get("id")) == identifier or str(c.get("slug")) == identifier:
                return dict(c)
    return None


async def insert_stix_objects(objects: List[Dict[str, Any]]) -> int:
    """
    Insert a list of validated STIX objects into stix_objects table.
    Ensures objects have collection_id, id, type, raw, confidence, modified, created.
    """
    if not objects:
        return 0

    with _db_lock:
        for obj in objects:
            obj_id = obj.get("id")
            obj_coll = str(obj.get("collection_id", ""))
            # Composite key: (id, collection_id) — same STIX object can live in multiple collections
            existing_idx = next(
                (i for i, o in enumerate(_IN_MEMORY_STIX_OBJECTS)
                 if o.get("id") == obj_id and str(o.get("collection_id", "")) == obj_coll),
                None,
            )
            if existing_idx is not None:
                _IN_MEMORY_STIX_OBJECTS[existing_idx] = dict(obj)
            else:
                _IN_MEMORY_STIX_OBJECTS.append(dict(obj))

    client = get_supabase_client()
    if client:
        try:
            client.table("stix_objects").upsert(objects, on_conflict="id").execute()
        except Exception as e:
            logger.warning(f"[database] Supabase insert_stix_objects error: {e}")

    return len(objects)


def _parse_ts(val: Any) -> Optional[datetime]:
    if not val:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


async def query_stix_objects(
    collection_id: str,
    added_after: Optional[datetime] = None,
    limit: Optional[int] = None,
    next_offset: int = 0,
    match_type: Optional[str] = None,
    match_id: Optional[str] = None,
    match_version: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], bool, Optional[str]]:
    """
    Query STIX objects for a collection with filtering, ordering, and pagination.

    Returns:
        Tuple[List[Dict[str, Any]], bool, Optional[str]]:
            - list of raw STIX object dictionaries
            - more (boolean)
            - next pagination token / offset (string or None)
    """
    client = get_supabase_client()
    if client:
        try:
            query = client.table("stix_objects").select("raw, modified, id, type, spec_version").eq("collection_id", collection_id)
            if match_type:
                types = [t.strip() for t in match_type.split(",") if t.strip()]
                if len(types) == 1:
                    query = query.eq("type", types[0])
                else:
                    query = query.in_("type", types)
            if match_id:
                ids = [i.strip() for i in match_id.split(",") if i.strip()]
                if len(ids) == 1:
                    query = query.eq("id", ids[0])
                else:
                    query = query.in_("id", ids)
            if added_after:
                query = query.gt("modified", added_after.isoformat())

            query = query.order("modified", desc=False)

            fetch_limit = (limit if limit and limit > 0 else 100) + 1
            query = query.range(next_offset, next_offset + fetch_limit - 1)
            res = query.execute()

            items = res.data or []
            if items:
                has_more = len(items) > (fetch_limit - 1)
                results = items[: fetch_limit - 1] if has_more else items
                next_token = str(next_offset + len(results)) if has_more else None
                raw_objects = [item["raw"] for item in results if "raw" in item]
                return raw_objects, has_more, next_token
        except Exception as e:
            logger.warning(f"[database] Supabase query_stix_objects error, using in-memory: {e}")

    with _db_lock:
        filtered: List[Dict[str, Any]] = []
        for obj in _IN_MEMORY_STIX_OBJECTS:
            if str(obj.get("collection_id")) != str(collection_id):
                continue
            if match_type:
                types = [t.strip() for t in match_type.split(",") if t.strip()]
                if obj.get("type") not in types:
                    continue
            if match_id:
                ids = [i.strip() for i in match_id.split(",") if i.strip()]
                if obj.get("id") not in ids:
                    continue
            if added_after:
                mod_dt = _parse_ts(obj.get("modified"))
                if not mod_dt or mod_dt <= added_after:
                    continue
            filtered.append(obj)

        # Sort ascending by modified for TAXII 2.1 timeline consistency
        filtered.sort(key=lambda x: _parse_ts(x.get("modified")) or datetime.min.replace(tzinfo=timezone.utc))

        page_size = limit if limit and limit > 0 else 100
        start = max(0, next_offset)
        end = start + page_size
        sliced = filtered[start:end]
        has_more = end < len(filtered)
        next_token = str(end) if has_more else None

        raw_objects = [item["raw"] for item in sliced if "raw" in item]
        return raw_objects, has_more, next_token


async def query_stix_manifest(
    collection_id: str,
    added_after: Optional[datetime] = None,
    limit: Optional[int] = None,
    next_offset: int = 0,
    match_type: Optional[str] = None,
    match_id: Optional[str] = None,
    match_version: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], bool, Optional[str]]:
    """
    Query lightweight TAXII 2.1 Manifest records for sync operations.
    """
    client = get_supabase_client()
    if client:
        try:
            query = client.table("stix_objects").select("id, modified, spec_version, raw").eq("collection_id", collection_id)
            if match_type:
                types = [t.strip() for t in match_type.split(",") if t.strip()]
                if len(types) == 1:
                    query = query.eq("type", types[0])
                else:
                    query = query.in_("type", types)
            if match_id:
                ids = [i.strip() for i in match_id.split(",") if i.strip()]
                if len(ids) == 1:
                    query = query.eq("id", ids[0])
                else:
                    query = query.in_("id", ids)
            if added_after:
                query = query.gt("modified", added_after.isoformat())

            query = query.order("modified", desc=False)

            fetch_limit = (limit if limit and limit > 0 else 100) + 1
            query = query.range(next_offset, next_offset + fetch_limit - 1)
            res = query.execute()

            items = res.data or []
            if items:
                has_more = len(items) > (fetch_limit - 1)
                results = items[: fetch_limit - 1] if has_more else items
                next_token = str(next_offset + len(results)) if has_more else None

                manifest_items = []
                for item in results:
                    raw = item.get("raw", {})
                    ver = raw.get("modified") or raw.get("created") or str(item.get("modified"))
                    manifest_items.append({
                        "id": item["id"],
                        "date_added": str(item.get("modified")),
                        "version": str(ver),
                        "media_types": ["application/stix+json;version=2.1"],
                    })
                return manifest_items, has_more, next_token
        except Exception as e:
            logger.warning(f"[database] Supabase query_stix_manifest error, using in-memory: {e}")

    with _db_lock:
        filtered: List[Dict[str, Any]] = []
        for obj in _IN_MEMORY_STIX_OBJECTS:
            if str(obj.get("collection_id")) != str(collection_id):
                continue
            if match_type:
                types = [t.strip() for t in match_type.split(",") if t.strip()]
                if obj.get("type") not in types:
                    continue
            if match_id:
                ids = [i.strip() for i in match_id.split(",") if i.strip()]
                if obj.get("id") not in ids:
                    continue
            if added_after:
                mod_dt = _parse_ts(obj.get("modified"))
                if not mod_dt or mod_dt <= added_after:
                    continue
            filtered.append(obj)

        filtered.sort(key=lambda x: _parse_ts(x.get("modified")) or datetime.min.replace(tzinfo=timezone.utc))

        page_size = limit if limit and limit > 0 else 100
        start = max(0, next_offset)
        end = start + page_size
        sliced = filtered[start:end]
        has_more = end < len(filtered)
        next_token = str(end) if has_more else None

        manifest_items = []
        for item in sliced:
            raw = item.get("raw", {})
            ver = raw.get("modified") or raw.get("created") or str(item.get("modified"))
            manifest_items.append({
                "id": item["id"],
                "date_added": str(item.get("modified")),
                "version": str(ver),
                "media_types": ["application/stix+json;version=2.1"],
            })
        return manifest_items, has_more, next_token


async def authenticate_taxii_key(api_key: str, collection_slug: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Validate a TAXII subscriber API key and verify authorization for a target collection.

    Returns:
        Subscriber dict if valid and authorized, None otherwise.
    """
    if not api_key:
        return None

    api_key_clean = api_key.strip()
    # Strip optional "Bearer " prefix
    if api_key_clean.lower().startswith("bearer "):
        api_key_clean = api_key_clean[7:].strip()

    client = get_supabase_client()
    sub_data = None
    if client:
        try:
            res = client.table("taxii_subscribers").select("*").eq("api_key", api_key_clean).eq("active", True).execute()
            if res.data:
                sub_data = res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase authenticate_taxii_key error: {e}")

    if not sub_data:
        with _db_lock:
            sub_data = _IN_MEMORY_SUBSCRIBERS.get(api_key_clean)

    if not sub_data:
        return None

    if not sub_data.get("active", True):
        return None

    # Check collection slug access authorization
    if collection_slug:
        allowed = sub_data.get("allowed_collections", ["*"])
        if "*" not in allowed and collection_slug not in allowed:
            return None

    return sub_data


async def register_taxii_subscriber(name: str, api_key: str, allowed_collections: Optional[List[str]] = None) -> Dict[str, Any]:
    """Register or update a TAXII subscriber with API key."""
    sub = {
        "id": str(uuid4()),
        "name": name,
        "api_key": api_key,
        "allowed_collections": allowed_collections or ["*"],
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    client = get_supabase_client()
    if client:
        try:
            client.table("taxii_subscribers").upsert(sub, on_conflict="api_key").execute()
        except Exception as e:
            logger.warning(f"[database] Supabase register_taxii_subscriber error: {e}")

    with _db_lock:
        _IN_MEMORY_SUBSCRIBERS[api_key] = dict(sub)
    return sub


async def get_taxii_subscribers() -> List[Dict[str, Any]]:
    """Retrieve all TAXII feed subscribers."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("taxii_subscribers").select("*").execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_taxii_subscribers error: {e}")

    with _db_lock:
        return list(_IN_MEMORY_SUBSCRIBERS.values())


async def revoke_taxii_subscriber(sub_id_or_key: str) -> bool:
    """Revoke/deactivate a TAXII subscriber."""
    client = get_supabase_client()
    if client:
        try:
            client.table("taxii_subscribers").update({"active": False}).or_(f"id.eq.{sub_id_or_key},api_key.eq.{sub_id_or_key}").execute()
        except Exception as e:
            logger.warning(f"[database] Supabase revoke_taxii_subscriber error: {e}")

    with _db_lock:
        for k, v in list(_IN_MEMORY_SUBSCRIBERS.items()):
            if v.get("id") == sub_id_or_key or k == sub_id_or_key:
                v["active"] = False
                return True
    return True


async def get_taxii_access_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve recent TAXII feed access logs."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("taxii_access_log").select("*, taxii_subscribers(name)").order("timestamp", desc=True).limit(limit).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_taxii_access_logs error: {e}")

    with _db_lock:
        return list(reversed(_IN_MEMORY_ACCESS_LOGS[-limit:]))



async def log_taxii_access(
    endpoint: str,
    subscriber_id: Optional[str] = None,
    collection_id: Optional[str] = None,
    objects_returned: int = 0,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Log TAXII feed consumption to audit trail."""
    record = {
        "id": str(uuid4()),
        "subscriber_id": subscriber_id,
        "collection_id": collection_id,
        "endpoint": endpoint,
        "objects_returned": objects_returned,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": ip_address,
        "user_agent": user_agent,
    }
    client = get_supabase_client()
    if client:
        try:
            client.table("taxii_access_log").insert(record).execute()
            return
        except Exception as e:
            logger.warning(f"[database] Supabase log_taxii_access error: {e}")

    with _db_lock:
        _IN_MEMORY_ACCESS_LOGS.append(record)


async def init_database_tables() -> None:
    """Execute startup initialization and ensure default collections exist."""
    client = get_supabase_client()
    if client is not None:
        try:
            # Seed collections if empty
            res = client.table("taxii_collections").select("id").limit(1).execute()
            if not res.data:
                client.table("taxii_collections").upsert(_DEFAULT_COLLECTIONS, on_conflict="slug").execute()
        except Exception as e:
            logger.warning(f"[database] init_database_tables Supabase seed warning: {e}")


# ==============================================================================
# RPZ (Response Policy Zone) Database Operations (Session 4)
# ==============================================================================

async def upsert_rpz_entry(
    domain: str,
    confidence: int,
    source_stix_object_id: Optional[str] = None,
    action: str = "nxdomain",
) -> Dict[str, Any]:
    """
    Publish or update a DNS RPZ trigger entry.
    Confidence must be >= 80 (enforced at application layer).
    """
    clean_domain = domain.strip().lower().rstrip(".")
    now_iso = datetime.now(timezone.utc).isoformat()

    entry = {
        "id": str(uuid4()),
        "domain": clean_domain,
        "action": action.lower(),
        "source_stix_object_id": source_stix_object_id,
        "confidence": confidence,
        "added_at": now_iso,
        "removed_at": None,
    }

    client = get_supabase_client()
    if client:
        try:
            res = client.table("rpz_entries").upsert(
                {
                    "domain": clean_domain,
                    "action": action.lower(),
                    "source_stix_object_id": source_stix_object_id,
                    "confidence": confidence,
                    "added_at": now_iso,
                    "removed_at": None,
                },
                on_conflict="domain",
            ).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase upsert_rpz_entry error: {e}")

    with _db_lock:
        existing_idx = next((i for i, r in enumerate(_IN_MEMORY_RPZ_ENTRIES) if r["domain"] == clean_domain), None)
        if existing_idx is not None:
            # Preserve original id, update fields, clear removed_at
            entry["id"] = _IN_MEMORY_RPZ_ENTRIES[existing_idx]["id"]
            _IN_MEMORY_RPZ_ENTRIES[existing_idx] = dict(entry)
        else:
            _IN_MEMORY_RPZ_ENTRIES.append(dict(entry))

    return entry


async def get_active_rpz_entries() -> List[Dict[str, Any]]:
    """Retrieve all currently active (non-soft-deleted) RPZ entries."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("rpz_entries").select("*").is_("removed_at", "null").order("added_at", desc=True).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_active_rpz_entries error: {e}")

    with _db_lock:
        return [dict(r) for r in _IN_MEMORY_RPZ_ENTRIES if r.get("removed_at") is None]


async def get_all_rpz_entries(limit: int = 1000) -> List[Dict[str, Any]]:
    """Retrieve all RPZ entries including soft-deleted ones for forensic audit trail."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("rpz_entries").select("*").order("added_at", desc=True).limit(limit).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_all_rpz_entries error: {e}")

    with _db_lock:
        return [dict(r) for r in _IN_MEMORY_RPZ_ENTRIES[:limit]]


async def soft_delete_rpz_entry(domain: str) -> bool:
    """Soft-delete an RPZ entry by setting removed_at to current timestamp."""
    clean_domain = domain.strip().lower().rstrip(".")
    now_iso = datetime.now(timezone.utc).isoformat()

    client = get_supabase_client()
    if client:
        try:
            res = client.table("rpz_entries").update({"removed_at": now_iso}).eq("domain", clean_domain).execute()
            if res.data:
                return True
        except Exception as e:
            logger.warning(f"[database] Supabase soft_delete_rpz_entry error: {e}")

    with _db_lock:
        found = False
        for r in _IN_MEMORY_RPZ_ENTRIES:
            if r["domain"] == clean_domain:
                r["removed_at"] = now_iso
                found = True
        return found


async def expire_stale_rpz_entries(max_age_days: int = 90) -> int:
    """
    Auto-review and expire RPZ entries older than max_age_days without re-corroboration.
    Sets removed_at = now() for soft-deletion.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    now_iso = datetime.now(timezone.utc).isoformat()
    expired_count = 0

    client = get_supabase_client()
    if client:
        try:
            res = (
                client.table("rpz_entries")
                .update({"removed_at": now_iso})
                .is_("removed_at", "null")
                .lt("added_at", cutoff.isoformat())
                .execute()
            )
            if res.data:
                expired_count = len(res.data)
                return expired_count
        except Exception as e:
            logger.warning(f"[database] Supabase expire_stale_rpz_entries error: {e}")

    with _db_lock:
        for r in _IN_MEMORY_RPZ_ENTRIES:
            if r.get("removed_at") is None:
                added_ts = _parse_ts(r.get("added_at"))
                if added_ts and added_ts < cutoff:
                    r["removed_at"] = now_iso
                    expired_count += 1

    return expired_count


# ==============================================================================
# Passive DNS & Defence IP Correlation Operations (Session 5)
# ==============================================================================

import ipaddress


async def upsert_monitored_defence_ip(
    ip: str,
    org_name: str,
    source: str,
    verified_on: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Register or update a monitored Indian defence or government IP / CIDR range.
    CRITICAL: 'source' field is MANDATORY and must point to a verifiable registry record.
    """
    clean_ip = ip.strip()
    clean_source = (source or "").strip()
    if not clean_source:
        raise ValueError("Source provenance is mandatory for all monitored defence IPs. Never guess or fabricate ranges.")

    verified_date = verified_on or datetime.now(timezone.utc).date().isoformat()
    record = {
        "id": str(uuid4()),
        "ip": clean_ip,
        "org_name": org_name.strip(),
        "source": clean_source,
        "verified_on": verified_date,
        "notes": notes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    client = get_supabase_client()
    if client:
        try:
            res = client.table("monitored_defence_ips").upsert(
                {
                    "ip": clean_ip,
                    "org_name": org_name.strip(),
                    "source": clean_source,
                    "verified_on": verified_date,
                    "notes": notes,
                },
                on_conflict="ip",
            ).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase upsert_monitored_defence_ip error: {e}")

    with _db_lock:
        existing_idx = next((i for i, r in enumerate(_IN_MEMORY_DEFENCE_IPS) if r["ip"] == clean_ip), None)
        if existing_idx is not None:
            record["id"] = _IN_MEMORY_DEFENCE_IPS[existing_idx]["id"]
            _IN_MEMORY_DEFENCE_IPS[existing_idx] = dict(record)
        else:
            _IN_MEMORY_DEFENCE_IPS.append(dict(record))

    return record


async def get_monitored_defence_ips() -> List[Dict[str, Any]]:
    """Retrieve all documented monitored defence IPs and ranges."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("monitored_defence_ips").select("*").execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_monitored_defence_ips error: {e}")

    with _db_lock:
        return [dict(r) for r in _IN_MEMORY_DEFENCE_IPS]


async def find_matching_defence_ip(target_ip: str) -> Optional[Dict[str, Any]]:
    """
    Check if target_ip matches any documented defence IP address or CIDR netblock.
    """
    clean_target = target_ip.strip()
    try:
        target_obj = ipaddress.ip_address(clean_target)
    except ValueError:
        return None

    ranges = await get_monitored_defence_ips()
    for row in ranges:
        ip_str = row.get("ip", "").strip()
        if not ip_str:
            continue
        try:
            if "/" in ip_str:
                net = ipaddress.ip_network(ip_str, strict=False)
                if target_obj in net:
                    return row
            else:
                if target_obj == ipaddress.ip_address(ip_str):
                    return row
        except ValueError:
            continue

    return None


async def insert_pdns_observation(
    defence_ip_id: Optional[str],
    queried_domain: str,
    resolved_via: str,
    matches_known_c2: bool,
    raw_response: Dict[str, Any],
    stix_indicator_id: Optional[str] = None,
    observed_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Record a Passive DNS historical domain-resolution observation.
    Retains full raw_response for verifiable evidentiary trail.
    """
    obs_time = observed_at or datetime.now(timezone.utc).isoformat()
    record = {
        "id": str(uuid4()),
        "defence_ip_id": defence_ip_id,
        "queried_domain": queried_domain.strip().lower(),
        "resolved_via": resolved_via.strip().lower(),
        "matches_known_c2": matches_known_c2,
        "stix_indicator_id": stix_indicator_id,
        "observed_at": obs_time,
        "raw_response": raw_response,
    }

    client = get_supabase_client()
    if client:
        try:
            res = client.table("passive_dns_observations").insert(record).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase insert_pdns_observation error: {e}")

    with _db_lock:
        _IN_MEMORY_PDNS_OBSERVATIONS.append(dict(record))

    return record


async def get_pdns_observations(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve recorded passive DNS correlation findings."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("passive_dns_observations").select("*").order("observed_at", desc=True).limit(limit).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_pdns_observations error: {e}")

    with _db_lock:
        return [dict(r) for r in _IN_MEMORY_PDNS_OBSERVATIONS[:limit]]


# ==============================================================================
# Operator Clusters & Campaign Fingerprints Operations (Session 6)
# ==============================================================================

async def create_operator_cluster(
    label: str,
    first_observed: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new operator cluster working group.
    Note: 'label' is an internal working name (e.g. 'cluster-a-nic-mod'), not a public attribution claim.
    """
    clean_label = label.strip()
    obs_date = first_observed or datetime.now(timezone.utc).date().isoformat()
    record = {
        "id": str(uuid4()),
        "label": clean_label,
        "first_observed": obs_date,
        "notes": notes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    client = get_supabase_client()
    if client:
        try:
            res = client.table("operator_clusters").insert({
                "label": clean_label,
                "first_observed": obs_date,
                "notes": notes,
            }).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase create_operator_cluster error: {e}")

    with _db_lock:
        _IN_MEMORY_OPERATOR_CLUSTERS.append(dict(record))

    return record


async def get_operator_clusters() -> List[Dict[str, Any]]:
    """Retrieve all documented operator clusters."""
    client = get_supabase_client()
    if client:
        try:
            res = client.table("operator_clusters").select("*").order("first_observed", desc=True).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_operator_clusters error: {e}")

    with _db_lock:
        return [dict(r) for r in _IN_MEMORY_OPERATOR_CLUSTERS]


async def insert_campaign_fingerprint(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Record technical fingerprint of threat campaign infrastructure.
    Starts unclustered (cluster_id=None) until verified.
    """
    record = {
        "id": str(uuid4()),
        "cluster_id": data.get("cluster_id"),
        "domain": data["domain"].strip().lower(),
        "registrar": data.get("registrar"),
        "registrar_account_pattern": data.get("registrar_account_pattern"),
        "nameserver_sequence": data.get("nameserver_sequence") or [],
        "hosting_asn": data.get("hosting_asn"),
        "cert_issued_at": data.get("cert_issued_at"),
        "geopolitical_event_ref": data.get("geopolitical_event_ref"),
        "lure_theme": data.get("lure_theme"),
        "target_sector": data.get("target_sector"),
        "cves_used": data.get("cves_used") or [],
        "stix_indicator_id": data.get("stix_indicator_id"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    client = get_supabase_client()
    if client:
        try:
            res = client.table("campaign_infrastructure_fingerprints").upsert(
                record, on_conflict="domain"
            ).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase insert_campaign_fingerprint error: {e}")

    with _db_lock:
        existing_idx = next((i for i, f in enumerate(_IN_MEMORY_CAMPAIGN_FINGERPRINTS) if f["domain"] == record["domain"]), None)
        if existing_idx is not None:
            record["id"] = _IN_MEMORY_CAMPAIGN_FINGERPRINTS[existing_idx]["id"]
            _IN_MEMORY_CAMPAIGN_FINGERPRINTS[existing_idx] = dict(record)
        else:
            _IN_MEMORY_CAMPAIGN_FINGERPRINTS.append(dict(record))

    return record


async def get_campaign_fingerprints(cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve campaign infrastructure fingerprints, optionally filtered by cluster."""
    client = get_supabase_client()
    if client:
        try:
            q = client.table("campaign_infrastructure_fingerprints").select("*")
            if cluster_id is not None:
                q = q.eq("cluster_id", cluster_id)
            res = q.order("created_at", desc=True).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_campaign_fingerprints error: {e}")

    with _db_lock:
        if cluster_id is not None:
            return [dict(f) for f in _IN_MEMORY_CAMPAIGN_FINGERPRINTS if f.get("cluster_id") == cluster_id]
        return [dict(f) for f in _IN_MEMORY_CAMPAIGN_FINGERPRINTS]


async def update_fingerprint_cluster(fingerprint_id: str, cluster_id: Optional[str]) -> bool:
    """Assign or unassign a cluster to a campaign infrastructure fingerprint."""
    client = get_supabase_client()
    if client:
        try:
            res = (
                client.table("campaign_infrastructure_fingerprints")
                .update({"cluster_id": cluster_id})
                .eq("id", fingerprint_id)
                .execute()
            )
            if res.data:
                return True
        except Exception as e:
            logger.warning(f"[database] Supabase update_fingerprint_cluster error: {e}")

    with _db_lock:
        for f in _IN_MEMORY_CAMPAIGN_FINGERPRINTS:
            if str(f.get("id")) == str(fingerprint_id):
                f["cluster_id"] = cluster_id
                return True
        return False


async def insert_cluster_review_item(
    fingerprint_id: str,
    suggested_cluster_id: str,
    similarity_score: float,
    matched_signals: Dict[str, Any],
) -> Dict[str, Any]:
    """Insert a candidate match into the human-reviewable queue."""
    record = {
        "id": str(uuid4()),
        "fingerprint_id": fingerprint_id,
        "suggested_cluster_id": suggested_cluster_id,
        "similarity_score": round(float(similarity_score), 4),
        "matched_signals": matched_signals,
        "status": "pending",
        "analyst_id": None,
        "reviewed_at": None,
        "justification": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    client = get_supabase_client()
    if client:
        try:
            res = client.table("cluster_review_queue").upsert(
                record, on_conflict="fingerprint_id,suggested_cluster_id"
            ).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase insert_cluster_review_item error: {e}")

    with _db_lock:
        existing_idx = next(
            (i for i, q in enumerate(_IN_MEMORY_CLUSTER_REVIEW_QUEUE)
             if str(q["fingerprint_id"]) == str(fingerprint_id) and str(q["suggested_cluster_id"]) == str(suggested_cluster_id)),
            None,
        )
        if existing_idx is not None:
            record["id"] = _IN_MEMORY_CLUSTER_REVIEW_QUEUE[existing_idx]["id"]
            _IN_MEMORY_CLUSTER_REVIEW_QUEUE[existing_idx] = dict(record)
        else:
            _IN_MEMORY_CLUSTER_REVIEW_QUEUE.append(dict(record))

    return record


async def get_cluster_review_queue(status: Optional[str] = "pending") -> List[Dict[str, Any]]:
    """Retrieve review queue items, optionally filtered by status ('pending', 'approved', 'rejected')."""
    client = get_supabase_client()
    if client:
        try:
            q = client.table("cluster_review_queue").select("*")
            if status:
                q = q.eq("status", status)
            res = q.order("similarity_score", desc=True).execute()
            if res.data is not None:
                return res.data
        except Exception as e:
            logger.warning(f"[database] Supabase get_cluster_review_queue error: {e}")

    with _db_lock:
        if status:
            return [dict(q) for q in _IN_MEMORY_CLUSTER_REVIEW_QUEUE if q.get("status") == status]
        return [dict(q) for q in _IN_MEMORY_CLUSTER_REVIEW_QUEUE]


async def update_cluster_review_decision(
    review_id: str,
    decision: str,
    analyst_id: str,
    justification: str,
) -> Optional[Dict[str, Any]]:
    """
    Process an analyst decision on a candidate attribution review.
    If 'approved', updates the fingerprint's cluster_id.
    """
    clean_decision = decision.strip().lower()
    if clean_decision not in ("approved", "rejected"):
        raise ValueError("Decision must be 'approved' or 'rejected'.")

    now_iso = datetime.now(timezone.utc).isoformat()
    review_item = None

    with _db_lock:
        for q in _IN_MEMORY_CLUSTER_REVIEW_QUEUE:
            if str(q.get("id")) == str(review_id):
                q["status"] = clean_decision
                q["analyst_id"] = analyst_id
                q["reviewed_at"] = now_iso
                q["justification"] = justification
                review_item = dict(q)
                break

    client = get_supabase_client()
    if client:
        try:
            res = (
                client.table("cluster_review_queue")
                .update({
                    "status": clean_decision,
                    "analyst_id": analyst_id,
                    "reviewed_at": now_iso,
                    "justification": justification,
                })
                .eq("id", review_id)
                .execute()
            )
            if res.data:
                review_item = res.data[0]
        except Exception as e:
            logger.warning(f"[database] Supabase update_cluster_review_decision error: {e}")

    if review_item and clean_decision == "approved":
        # Assign cluster_id to fingerprint upon approval
        fp_id = review_item.get("fingerprint_id")
        cluster_id = review_item.get("suggested_cluster_id")
        if fp_id and cluster_id:
            await update_fingerprint_cluster(fp_id, cluster_id)

    return review_item
