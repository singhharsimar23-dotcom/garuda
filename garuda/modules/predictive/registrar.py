"""
Porkbun domain registrar integration for predictive honeypot pre-registration.

API docs: https://porkbun.com/api/json/v3/documentation
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from garuda.config import settings
from garuda.database import insert_predictive_domain_audit, upsert_predictive_domain
from garuda.intelligence.honeypot import HONEYPOT_DOMAINS

logger = logging.getLogger("garuda.modules.predictive.registrar")

PORKBUN_BASE = "https://api.porkbun.com/api/json/v3"
CLOUDFLARE_NAMESERVERS = ["ns1.cloudflare.com", "ns2.cloudflare.com"]


def _auth_body(api_key: str, api_secret: str, extra: Optional[dict] = None) -> dict:
    payload = {
        "apikey": api_key,
        "secretapikey": api_secret,
    }
    if extra:
        payload.update(extra)
    return payload


def _parse_porkbun_response(data: dict, context: str) -> dict:
    """Validate Porkbun response schema; raise ValueError on unexpected shape."""
    if not isinstance(data, dict):
        raise ValueError(f"Porkbun {context}: expected JSON object, got {type(data).__name__}")

    status = data.get("status")
    if status not in ("SUCCESS", "ERROR"):
        raise ValueError(
            f"Porkbun {context}: unexpected status field '{status}' — response schema mismatch"
        )

    if status == "ERROR":
        message = data.get("message", "unknown error")
        raise ValueError(f"Porkbun {context} error: {message}")

    return data


async def check_availability_porkbun(
    domain: str,
    api_key: str,
    api_secret: str,
) -> bool:
    """
    Check domain availability via Porkbun checkDomain endpoint.

    POST {PORKBUN_BASE}/domain/checkDomain/{domain}
    Returns True when domain is available for registration.
    """
    domain = domain.strip().lower()
    url = f"{PORKBUN_BASE}/domain/checkDomain/{domain}"

    async with httpx.AsyncClient(timeout=20.0) as client:
        res = await client.post(url, json=_auth_body(api_key, api_secret))
        res.raise_for_status()
        data = res.json()

    parsed = _parse_porkbun_response(data, "checkDomain")

    response_obj = parsed.get("response")
    if not isinstance(response_obj, dict):
        raise ValueError(
            "Porkbun checkDomain: missing or invalid 'response' object — schema mismatch"
        )

    avail = str(response_obj.get("avail", response_obj.get("available", ""))).lower()
    return avail in ("yes", "available", "true", "1")


async def _get_registration_cost_pennies(
    domain: str,
    api_key: str,
    api_secret: str,
) -> int:
    """Fetch exact registration cost in USD cents from checkDomain."""
    url = f"{PORKBUN_BASE}/domain/checkDomain/{domain}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        res = await client.post(url, json=_auth_body(api_key, api_secret))
        res.raise_for_status()
        data = res.json()

    parsed = _parse_porkbun_response(data, "checkDomain-cost")
    response_obj = parsed.get("response") or {}

    price = response_obj.get("price")
    if price is not None:
        try:
            return int(float(price) * 100)
        except (TypeError, ValueError):
            pass

    registration = response_obj.get("registration")
    if isinstance(registration, dict) and registration.get("price") is not None:
        try:
            return int(float(registration["price"]) * 100)
        except (TypeError, ValueError):
            pass

    # Fallback to configured default cost.
    return int(settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD * 100)


async def _update_nameservers(
    domain: str,
    api_key: str,
    api_secret: str,
    nameservers: list[str],
) -> None:
    """POST /domain/updateNs/{domain} — set Cloudflare nameservers."""
    url = f"{PORKBUN_BASE}/domain/updateNs/{domain}"
    body = _auth_body(api_key, api_secret, {"ns": nameservers})

    async with httpx.AsyncClient(timeout=20.0) as client:
        res = await client.post(url, json=body)
        res.raise_for_status()
        data = res.json()

    _parse_porkbun_response(data, "updateNs")


async def configure_honeypot_route(domain: str) -> None:
    """
    Register domain with existing Module 5 honeypot tracking.

    Cloudflare Worker route configuration requires zone-level API access;
    nameservers are pointed to Cloudflare during registration.
    """
    domain = domain.strip().lower()
    if domain not in HONEYPOT_DOMAINS:
        HONEYPOT_DOMAINS.append(domain)
    logger.info("[registrar] Honeypot route configured for %s (ns→Cloudflare)", domain)


async def register_domain_porkbun(
    domain: str,
    api_key: str,
    api_secret: str,
    *,
    analyst_id: str,
    justification: str,
    prediction_score: Optional[float] = None,
    narrative_keywords: Optional[list[str]] = None,
) -> dict:
    """
    Register domain with Cloudflare nameservers and persist to predictive_domains.

    Never called without analyst approval — enforced at API layer.
    """
    domain = domain.strip().lower()
    cost_pennies = await _get_registration_cost_pennies(domain, api_key, api_secret)
    cost_usd = round(cost_pennies / 100.0, 2)

    url = f"{PORKBUN_BASE}/domain/create/{domain}"
    body = _auth_body(api_key, api_secret, {
        "cost": cost_pennies,
        "agreeToTerms": "yes",
        "whoisPrivacy": True,
    })

    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.post(url, json=body)
        res.raise_for_status()
        data = res.json()

    parsed = _parse_porkbun_response(data, "create")
    order_id = parsed.get("orderId")

    await _update_nameservers(domain, api_key, api_secret, CLOUDFLARE_NAMESERVERS)
    await configure_honeypot_route(domain)

    now_iso = datetime.now(timezone.utc).isoformat()
    record = await upsert_predictive_domain({
        "domain": domain,
        "prediction_score": prediction_score,
        "narrative_keywords": narrative_keywords or [],
        "status": "registered",
        "registered_at": now_iso,
        "registration_cost_usd": cost_usd,
        "analyst_approved_by": analyst_id,
        "analyst_justification": justification,
    })

    await insert_predictive_domain_audit(
        action="predictive_domain_registered",
        analyst_id=analyst_id,
        justification=justification,
        metadata={
            "domain": domain,
            "cost_estimate_usd": cost_usd,
            "order_id": order_id,
            "rationale": justification[:200],
        },
    )

    return {
        "status": "registered",
        "domain": domain,
        "order_id": order_id,
        "cost_usd": cost_usd,
        "nameservers": CLOUDFLARE_NAMESERVERS,
        "record": record,
    }


async def count_monthly_registrations() -> int:
    """Count domains registered in the current calendar month."""
    from garuda.database import count_predictive_registrations_this_month
    return await count_predictive_registrations_this_month()


async def check_registration_budget() -> tuple[bool, str]:
    """
    Budget gate: monthly registration spend vs DOMAIN_REGISTRATION_BUDGET_USD_MONTHLY.

    Returns (allowed, message).
    """
    from garuda.database import get_monthly_registration_spend_usd

    spend = await get_monthly_registration_spend_usd()
    budget = settings.DOMAIN_REGISTRATION_BUDGET_USD_MONTHLY
    projected = spend + settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD

    if projected > budget:
        return False, (
            f"Monthly domain registration budget exhausted: "
            f"${spend:.2f} spent of ${budget:.2f} limit "
            f"(~{int(budget / settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD)} domains/month max). "
            f"Analyst approval required — no auto-registration."
        )

    count = await count_monthly_registrations()
    max_count = max(1, int(budget / settings.DEFAULT_DOMAIN_REGISTRATION_COST_USD))
    if count >= max_count:
        return False, (
            f"Monthly registration count at limit: {count}/{max_count} domains "
            f"(${budget:.2f} budget). Analyst approval required — no auto-registration."
        )

    return True, "within_budget"
