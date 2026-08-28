"""
GARUDA Threat Intelligence - TAXII 2.1 Spec-Conformant Read Server & STIX 2.1 Feeds
Backed by Supabase Postgres with in-memory fallback.
"""

import base64
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status

from garuda.database import (
    authenticate_taxii_key,
    get_taxii_collection_by_id_or_slug,
    get_taxii_collections,
    log_taxii_access,
    query_stix_manifest,
    query_stix_objects,
)

logger = logging.getLogger("garuda.api.routes.taxii")

TAXII21_MEDIA_TYPE = "application/taxii+json;version=2.1"
API_ROOT_DEFAULT = "api_v1"

router = APIRouter(tags=["TAXII 2.1 Sovereign Threat Feeds"])


# ==============================================================================
# Helper Functions & TAXII Spec Formatters
# ==============================================================================


def taxii_json_response(content: Any, status_code: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
    """Return a FastAPI Response with the mandatory TAXII 2.1 Content-Type header."""
    resp_headers = {
        "Content-Type": TAXII21_MEDIA_TYPE,
    }
    if headers:
        resp_headers.update(headers)
    return Response(
        content=json.dumps(content),
        status_code=status_code,
        media_type=TAXII21_MEDIA_TYPE,
        headers=resp_headers,
    )


def taxii_error_response(
    title: str,
    description: str,
    status_code: int = 400,
    error_id: Optional[str] = None,
    error_code: Optional[str] = None,
) -> Response:
    """Return a TAXII 2.1 spec-compliant Error object response."""
    error_payload: Dict[str, Any] = {
        "title": title,
        "description": description,
        "error_id": error_id or f"TAXII-ERR-{status_code}",
        "http_status": str(status_code),
    }
    if error_code:
        error_payload["error_code"] = error_code

    return Response(
        content=json.dumps(error_payload),
        status_code=status_code,
        media_type=TAXII21_MEDIA_TYPE,
        headers={"Content-Type": TAXII21_MEDIA_TYPE},
    )


def _extract_api_key(request: Request) -> Optional[str]:
    """
    Extract API key from HTTP request supporting:
    - Authorization: Bearer <key>
    - Authorization: Basic <base64(user:pass)>
    - X-API-Key header
    - ?api_key= query parameter
    """
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth_header:
        auth_header = auth_header.strip()
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        if auth_header.lower().startswith("basic "):
            try:
                b64_val = auth_header[6:].strip()
                decoded = base64.b64decode(b64_val).decode("utf-8")
                # format user:password
                if ":" in decoded:
                    user, pwd = decoded.split(":", 1)
                    # If either user or password is a key
                    return user.strip() if user.strip() and user.strip() != "api_key" else pwd.strip()
                return decoded.strip()
            except Exception:
                pass

    x_api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    if x_api_key:
        return x_api_key.strip()

    query_key = request.query_params.get("api_key")
    if query_key:
        return query_key.strip()

    return None


def _get_base_url(request: Request) -> str:
    """Determine base server URL from request headers or scope."""
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    forwarded_host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"{forwarded_proto}://{forwarded_host}"


def _parse_iso_datetime(val: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime string into UTC aware datetime."""
    if not val:
        return None
    try:
        clean = val.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ==============================================================================
# Endpoint 1: Server Discovery (/taxii2/)
# ==============================================================================


@router.get("/taxii2", include_in_schema=False)
@router.get("/taxii2/")
@router.get("/api/taxii2", include_in_schema=False)
@router.get("/api/taxii2/")
async def taxii_server_discovery(request: Request):
    """
    TAXII 2.1 Server Discovery (Section 4.1).
    Returns server identity, title, description, and list of API roots.
    """
    base_url = _get_base_url(request)
    api_root_url = f"{base_url}/taxii2/{API_ROOT_DEFAULT}/"

    response_data = {
        "title": "GARUDA Sovereign CTI TAXII 2.1 Server",
        "description": "National Threat Intelligence Sharing Gateway for Indian Critical Infrastructure & Defence Sectors",
        "contact": "cti@garuda.gov.in",
        "default": api_root_url,
        "api_roots": [api_root_url],
    }
    return taxii_json_response(response_data)


# ==============================================================================
# Endpoint 2: API Root Information (/<api-root>/)
# ==============================================================================


@router.get("/taxii2/{api_root}", include_in_schema=False)
@router.get("/taxii2/{api_root}/")
@router.get("/api/taxii2/{api_root}", include_in_schema=False)
@router.get("/api/taxii2/{api_root}/")
async def taxii_api_root_info(api_root: str, request: Request):
    """
    TAXII 2.1 API Root Information (Section 4.2).
    Returns title, description, supported TAXII versions, and max_content_length.
    """
    response_data = {
        "title": f"GARUDA Threat Feed ({api_root})",
        "description": "Primary STIX 2.1 threat intelligence feeds and collections",
        "versions": [TAXII21_MEDIA_TYPE],
        "max_content_length": 10485760,  # 10MB
    }
    return taxii_json_response(response_data)


# ==============================================================================
# Endpoint 3: List Collections (/<api-root>/collections/)
# ==============================================================================


@router.get("/taxii2/{api_root}/collections", include_in_schema=False)
@router.get("/taxii2/{api_root}/collections/")
@router.get("/api/taxii2/{api_root}/collections", include_in_schema=False)
@router.get("/api/taxii2/{api_root}/collections/")
async def taxii_list_collections(api_root: str, request: Request):
    """
    TAXII 2.1 List Collections (Section 5.1).
    Returns list of threat intelligence collections available on the API root.
    """
    # Check subscriber auth
    api_key = _extract_api_key(request)
    subscriber = None
    if api_key:
        subscriber = await authenticate_taxii_key(api_key)
        if not subscriber:
            return taxii_error_response(
                title="Unauthorized",
                description="Invalid or deactivated TAXII subscriber API key.",
                status_code=401,
                error_id="TAXII-AUTH-401",
            )

    collections = await get_taxii_collections()
    allowed_collections = subscriber.get("allowed_collections", ["*"]) if subscriber else ["*"]

    coll_list = []
    for c in collections:
        slug = c.get("slug")
        if "*" not in allowed_collections and slug not in allowed_collections:
            continue
        coll_list.append({
            "id": str(c["id"]),
            "title": c["title"],
            "description": c.get("description"),
            "alias": slug,
            "can_read": bool(c.get("can_read", True)),
            "can_write": bool(c.get("can_write", False)),
            "media_types": c.get("media_types", ["application/stix+json;version=2.1"]),
        })

    sub_id = str(subscriber.get("id")) if subscriber else None
    await log_taxii_access(
        endpoint=f"/taxii2/{api_root}/collections/",
        subscriber_id=sub_id,
        objects_returned=len(coll_list),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return taxii_json_response({"collections": coll_list})


# ==============================================================================
# Endpoint 4: Single Collection Metadata (/<api-root>/collections/<id>/)
# ==============================================================================


@router.get("/taxii2/{api_root}/collections/{collection_id}", include_in_schema=False)
@router.get("/taxii2/{api_root}/collections/{collection_id}/")
@router.get("/api/taxii2/{api_root}/collections/{collection_id}", include_in_schema=False)
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/")
async def taxii_get_collection(api_root: str, collection_id: str, request: Request):
    """
    TAXII 2.1 Get Collection (Section 5.2).
    Returns metadata for an individual collection.
    """
    coll = await get_taxii_collection_by_id_or_slug(collection_id)
    if not coll:
        return taxii_error_response(
            title="Collection Not Found",
            description=f"Collection '{collection_id}' does not exist on API root '{api_root}'.",
            status_code=404,
            error_id="TAXII-NOT-FOUND-404",
        )

    api_key = _extract_api_key(request)
    subscriber = None
    if api_key:
        subscriber = await authenticate_taxii_key(api_key, collection_slug=coll.get("slug"))
        if not subscriber:
            return taxii_error_response(
                title="Unauthorized",
                description="Invalid API key or unauthorized for this collection.",
                status_code=401,
                error_id="TAXII-AUTH-401",
            )

    response_data = {
        "id": str(coll["id"]),
        "title": coll["title"],
        "description": coll.get("description"),
        "alias": coll.get("slug"),
        "can_read": bool(coll.get("can_read", True)),
        "can_write": bool(coll.get("can_write", False)),
        "media_types": coll.get("media_types", ["application/stix+json;version=2.1"]),
    }
    return taxii_json_response(response_data)


# ==============================================================================
# Endpoint 5: Get Objects (/<api-root>/collections/<id>/objects/)
# ==============================================================================


@router.get("/taxii2/{api_root}/collections/{collection_id}/objects", include_in_schema=False)
@router.get("/taxii2/{api_root}/collections/{collection_id}/objects/")
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/objects", include_in_schema=False)
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/objects/")
async def taxii_get_objects(
    api_root: str,
    collection_id: str,
    request: Request,
    added_after: Optional[str] = Query(None),
    limit: Optional[int] = Query(None, ge=1, le=1000),
    next: Optional[str] = Query(None),
):
    """
    TAXII 2.1 Get Objects (Section 5.3).
    Returns paginated STIX 2.1 objects envelope with filtering on added_after,
    match[type], match[id], match[version], limit, and next.
    """
    coll = await get_taxii_collection_by_id_or_slug(collection_id)
    if not coll:
        return taxii_error_response(
            title="Collection Not Found",
            description=f"Collection '{collection_id}' does not exist on API root '{api_root}'.",
            status_code=404,
            error_id="TAXII-NOT-FOUND-404",
        )

    # Validate subscriber auth
    api_key = _extract_api_key(request)
    subscriber = None
    if api_key:
        subscriber = await authenticate_taxii_key(api_key, collection_slug=coll.get("slug"))
        if not subscriber:
            return taxii_error_response(
                title="Unauthorized",
                description="Invalid API key or unauthorized for this collection.",
                status_code=401,
                error_id="TAXII-AUTH-401",
            )
    else:
        # Check if collection is restricted
        # If strict auth required, reject requests without key
        if not coll.get("can_read", True):
            return taxii_error_response(
                title="Unauthorized",
                description="Authentication credentials required to access this threat collection.",
                status_code=401,
                error_id="TAXII-AUTH-401",
            )

    # Extract filter parameters per TAXII 2.1 specification
    match_type = request.query_params.get("match[type]") or request.query_params.get("match_type")
    match_id = request.query_params.get("match[id]") or request.query_params.get("match_id")
    match_version = request.query_params.get("match[version]") or request.query_params.get("match_version")

    added_after_dt = _parse_iso_datetime(added_after)
    offset = int(next) if next and next.isdigit() else 0

    objects, more, next_token = await query_stix_objects(
        collection_id=str(coll["id"]),
        added_after=added_after_dt,
        limit=limit or 100,
        next_offset=offset,
        match_type=match_type,
        match_id=match_id,
        match_version=match_version,
    )

    envelope: Dict[str, Any] = {
        "more": more,
        "objects": objects,
    }
    if more and next_token:
        envelope["next"] = next_token

    # Log access audit
    sub_id = str(subscriber.get("id")) if subscriber else None
    await log_taxii_access(
        endpoint=f"/taxii2/{api_root}/collections/{coll['slug']}/objects/",
        subscriber_id=sub_id,
        collection_id=str(coll["id"]),
        objects_returned=len(objects),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    headers = {}
    if objects:
        first_ts = objects[0].get("modified") or objects[0].get("created")
        last_ts = objects[-1].get("modified") or objects[-1].get("created")
        if first_ts:
            headers["X-TAXII-Date-Added-First"] = str(first_ts)
        if last_ts:
            headers["X-TAXII-Date-Added-Last"] = str(last_ts)

    return taxii_json_response(envelope, headers=headers)


# ==============================================================================
# Endpoint 6: Single Object Retrieval (/<api-root>/collections/<id>/objects/<object-id>/)
# ==============================================================================


@router.get("/taxii2/{api_root}/collections/{collection_id}/objects/{object_id}", include_in_schema=False)
@router.get("/taxii2/{api_root}/collections/{collection_id}/objects/{object_id}/")
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/objects/{object_id}", include_in_schema=False)
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/objects/{object_id}/")
async def taxii_get_object_by_id(
    api_root: str,
    collection_id: str,
    object_id: str,
    request: Request,
):
    """
    TAXII 2.1 Get An Object (Section 5.4).
    Returns an envelope containing the requested STIX object.
    """
    coll = await get_taxii_collection_by_id_or_slug(collection_id)
    if not coll:
        return taxii_error_response(
            title="Collection Not Found",
            description=f"Collection '{collection_id}' not found.",
            status_code=404,
            error_id="TAXII-NOT-FOUND-404",
        )

    api_key = _extract_api_key(request)
    subscriber = None
    if api_key:
        subscriber = await authenticate_taxii_key(api_key, collection_slug=coll.get("slug"))
        if not subscriber:
            return taxii_error_response(
                title="Unauthorized",
                description="Invalid API key or unauthorized for this collection.",
                status_code=401,
                error_id="TAXII-AUTH-401",
            )

    objects, _, _ = await query_stix_objects(
        collection_id=str(coll["id"]),
        match_id=object_id,
        limit=10,
    )

    if not objects:
        return taxii_error_response(
            title="Object Not Found",
            description=f"STIX object '{object_id}' not found in collection '{collection_id}'.",
            status_code=404,
            error_id="TAXII-NOT-FOUND-404",
        )

    envelope = {
        "more": False,
        "objects": objects,
    }
    return taxii_json_response(envelope)


# ==============================================================================
# Endpoint 7: Collection Manifest (/<api-root>/collections/<id>/manifest/)
# ==============================================================================


@router.get("/taxii2/{api_root}/collections/{collection_id}/manifest", include_in_schema=False)
@router.get("/taxii2/{api_root}/collections/{collection_id}/manifest/")
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/manifest", include_in_schema=False)
@router.get("/api/taxii2/{api_root}/collections/{collection_id}/manifest/")
async def taxii_get_manifest(
    api_root: str,
    collection_id: str,
    request: Request,
    added_after: Optional[str] = Query(None),
    limit: Optional[int] = Query(None, ge=1, le=1000),
    next: Optional[str] = Query(None),
):
    """
    TAXII 2.1 Get Object Manifests (Section 5.5).
    Returns lightweight object metadata records for efficient state synchronization.
    """
    coll = await get_taxii_collection_by_id_or_slug(collection_id)
    if not coll:
        return taxii_error_response(
            title="Collection Not Found",
            description=f"Collection '{collection_id}' not found.",
            status_code=404,
            error_id="TAXII-NOT-FOUND-404",
        )

    api_key = _extract_api_key(request)
    subscriber = None
    if api_key:
        subscriber = await authenticate_taxii_key(api_key, collection_slug=coll.get("slug"))
        if not subscriber:
            return taxii_error_response(
                title="Unauthorized",
                description="Invalid API key or unauthorized for this collection.",
                status_code=401,
                error_id="TAXII-AUTH-401",
            )

    match_type = request.query_params.get("match[type]") or request.query_params.get("match_type")
    match_id = request.query_params.get("match[id]") or request.query_params.get("match_id")
    match_version = request.query_params.get("match[version]") or request.query_params.get("match_version")

    added_after_dt = _parse_iso_datetime(added_after)
    offset = int(next) if next and next.isdigit() else 0

    manifest_records, more, next_token = await query_stix_manifest(
        collection_id=str(coll["id"]),
        added_after=added_after_dt,
        limit=limit or 100,
        next_offset=offset,
        match_type=match_type,
        match_id=match_id,
        match_version=match_version,
    )

    envelope: Dict[str, Any] = {
        "more": more,
        "objects": manifest_records,
    }
    if more and next_token:
        envelope["next"] = next_token

    return taxii_json_response(envelope)


# ==============================================================================
# Endpoint 7: Subscriber Management & Feed Telemetry
# ==============================================================================

from pydantic import BaseModel, Field
import secrets


class CreateSubscriberRequest(BaseModel):
    label: str = Field(..., description="Subscriber name / organisation identifier")
    allowed_collections: Optional[List[str]] = Field(default=["*"], description="List of authorized collection slugs")


@router.get("/api/intelligence/subscribers")
@router.get("/intelligence/subscribers")
async def list_subscribers():
    """Retrieve all TAXII feed subscribers (masked keys)."""
    from garuda.database import get_taxii_subscribers
    subs = await get_taxii_subscribers()
    masked = []
    for s in subs:
        raw_key = s.get("api_key", "")
        masked_key = f"...{raw_key[-8:]}" if len(raw_key) >= 8 else raw_key
        masked.append({
            "id": s.get("id"),
            "name": s.get("name") or s.get("label", "SIEM Consumer"),
            "label": s.get("name") or s.get("label", "SIEM Consumer"),
            "allowed_collections": s.get("allowed_collections", ["*"]),
            "active": s.get("active", True),
            "created_at": s.get("created_at"),
            "last_access": s.get("last_access"),
            "objects_pulled": s.get("objects_pulled", 0),
            "api_key_masked": masked_key,
        })
    return {"status": "ok", "subscribers": masked}


@router.post("/api/intelligence/subscribers")
@router.post("/intelligence/subscribers")
async def create_subscriber(req: CreateSubscriberRequest):
    """Generate a new TAXII subscriber and return full API key once."""
    from garuda.database import register_taxii_subscriber
    generated_key = f"taxii_sec_{secrets.token_hex(20)}"
    sub = await register_taxii_subscriber(
        name=req.label,
        api_key=generated_key,
        allowed_collections=req.allowed_collections,
    )
    return {
        "status": "ok",
        "message": "Subscriber created successfully. Save the API key now — it cannot be retrieved again.",
        "subscriber": {
            "id": sub.get("id"),
            "name": req.label,
            "label": req.label,
            "allowed_collections": req.allowed_collections,
            "created_at": sub.get("created_at"),
        },
        "api_key": generated_key,
    }


@router.delete("/api/intelligence/subscribers/{sub_id}")
@router.delete("/intelligence/subscribers/{sub_id}")
async def delete_subscriber(sub_id: str):
    """Revoke a TAXII subscriber access key."""
    from garuda.database import revoke_taxii_subscriber
    success = await revoke_taxii_subscriber(sub_id)
    return {"status": "ok", "message": f"Subscriber {sub_id} revoked.", "id": sub_id}


@router.get("/api/intelligence/access-log")
@router.get("/intelligence/access-log")
async def list_access_logs(limit: int = Query(100, ge=1, le=500)):
    """Retrieve TAXII feed access telemetry log."""
    from garuda.database import get_taxii_access_logs
    logs = await get_taxii_access_logs(limit=limit)
    return {"status": "ok", "total": len(logs), "logs": logs}

