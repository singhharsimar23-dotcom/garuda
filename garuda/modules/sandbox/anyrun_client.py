"""
ANY.RUN sandbox API client.

VERIFY: Check https://any.run/api-documentation/ before assuming field names —
API versioning may have changed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger("garuda.modules.sandbox.anyrun_client")

ANYRUN_BASE = "https://api.any.run/v1"
MAX_SUBMISSIONS_PER_DAY = 10
POLL_INTERVAL_SEC = 10


def _auth_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"API-Key {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


async def submit_url(url: str, api_key: str) -> str | None:
    """
    Submit URL for sandbox analysis.

    POST {ANYRUN_BASE}/analysis
    Returns task_id string or None on failure.
    """
    if not api_key:
        logger.warning("[sandbox] ANYRUN_API_KEY not configured — skipping submission")
        return None

    payload = {
        "obj_type": "url",
        "obj_url": url,
        "env_os": "windows",
        "env_version": "10",
        "opt_network_connect": True,
        "opt_timeout": 60,
        # VERIFY: privacy_type=0 is public submission
        "privacy_type": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{ANYRUN_BASE}/analysis",
                headers=_auth_headers(api_key),
                json=payload,
            )
            data = resp.json()
            if resp.status_code >= 400 or data.get("error"):
                logger.warning(
                    "[sandbox] ANY.RUN submit failed (%s): %s",
                    resp.status_code,
                    data.get("message", resp.text),
                )
                return None

            task_id = (
                data.get("data", {}).get("taskid")
                or data.get("data", {}).get("task_id")
                or data.get("taskid")
                or data.get("task_id")
            )
            if not task_id:
                logger.warning("[sandbox] ANY.RUN response missing taskid: %s", data)
                return None
            return str(task_id)
    except Exception as exc:
        logger.error("[sandbox] ANY.RUN submit error: %s", exc)
        return None


async def poll_results(task_id: str, api_key: str, timeout_sec: int = 180) -> dict | None:
    """
    GET {ANYRUN_BASE}/analysis/{task_id}
    Poll every 10 seconds until status is done or timeout.
    """
    if not api_key or not task_id:
        return None

    deadline = asyncio.get_event_loop().time() + timeout_sec

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while asyncio.get_event_loop().time() < deadline:
                resp = await client.get(
                    f"{ANYRUN_BASE}/analysis/{task_id}",
                    headers=_auth_headers(api_key),
                )
                if resp.status_code >= 400:
                    logger.warning("[sandbox] ANY.RUN poll HTTP %s for %s", resp.status_code, task_id)
                    await asyncio.sleep(POLL_INTERVAL_SEC)
                    continue

                data = resp.json()
                status = _extract_status(data)
                if status in {"done", "finished", "complete", "completed"}:
                    return data

                await asyncio.sleep(POLL_INTERVAL_SEC)
    except Exception as exc:
        logger.error("[sandbox] ANY.RUN poll error for %s: %s", task_id, exc)

    logger.warning("[sandbox] ANY.RUN poll timeout for task %s after %ss", task_id, timeout_sec)
    return None


def _extract_status(data: dict) -> str:
    """Extract analysis status from response — field names may vary."""
    for path in (
        ("data", "status"),
        ("data", "analysis", "status"),
        ("status",),
    ):
        node: Any = data
        for key in path:
            if not isinstance(node, dict):
                break
            node = node.get(key)
        else:
            if node is not None:
                return str(node).lower()
    return ""


def _safe_list(node: Any) -> list:
    return node if isinstance(node, list) else []


def _dig(data: dict, *keys: str, default: Any = None) -> Any:
    node: Any = data
    for key in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(key)
    return node if node is not None else default


def extract_iocs(results: dict, task_id: str = "") -> dict:
    """
    Extract IOCs from completed ANY.RUN analysis.

    VERIFY field paths against actual response — fixture at
    fixtures/sandbox/anyrun_sample_response.json.
    """
    analysis = _dig(results, "data", "analysis", default={})
    if not isinstance(analysis, dict):
        analysis = _dig(results, "data", default={})
    if not isinstance(analysis, dict):
        analysis = {}

    network = analysis.get("network") or {}
    if not isinstance(network, dict):
        network = {}

    c2_domains: set[str] = set()
    for entry in _safe_list(network.get("dns")):
        if isinstance(entry, dict):
            domain = entry.get("domain") or entry.get("name") or entry.get("query")
            if domain and isinstance(domain, str):
                c2_domains.add(domain.lower().rstrip("."))

    c2_ips: set[str] = set()
    for entry in _safe_list(network.get("connections")):
        if isinstance(entry, dict):
            ip = entry.get("remoteIP") or entry.get("remote_ip") or entry.get("ip")
            if ip:
                c2_ips.add(str(ip))

    mitre_techniques: set[str] = set()
    for entry in _safe_list(analysis.get("behaviors")):
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("technique") or entry.get("mitre_id")
            if name:
                mitre_techniques.add(str(name))

    dropped_hashes: list[str] = []
    dropped_filenames: list[str] = []
    is_boss_linux = False

    for entry in _safe_list(analysis.get("files")):
        if not isinstance(entry, dict):
            continue
        sha = entry.get("sha256") or entry.get("hash") or entry.get("sha256hash")
        filename = entry.get("filename") or entry.get("name") or ""
        if sha:
            dropped_hashes.append(str(sha))
        if filename:
            dropped_filenames.append(str(filename))
            if str(filename).lower().endswith(".desktop"):
                is_boss_linux = True

    verdict = (
        analysis.get("verdict")
        or analysis.get("threat_level")
        or _dig(results, "data", "verdict", default="unknown")
        or "unknown"
    )
    verdict_str = str(verdict).lower()
    if verdict_str in {"malicious", "suspicious", "no threats", "clean"}:
        pass
    elif "mal" in verdict_str:
        verdict_str = "malicious"
    elif verdict_str == "unknown":
        verdict_str = "unknown"

    report_url = f"https://app.any.run/tasks/{task_id}" if task_id else ""

    return {
        "c2_domains": sorted(c2_domains),
        "c2_ips": sorted(c2_ips),
        "mitre_techniques": sorted(mitre_techniques),
        "dropped_hashes": dropped_hashes,
        "dropped_filenames": dropped_filenames,
        "is_boss_linux": is_boss_linux,
        "verdict": verdict_str,
        "report_url": report_url,
    }
