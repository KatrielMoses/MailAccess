"""Optional BYOK ipgeolocation.io enrichment; failures never escape callers."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)
BASE_URL = "https://api.ipgeolocation.io"
IPGEO_SIGNUP_URL = "https://app.ipgeolocation.io/signup"
_NO_IPGEO: ContextVar[bool] = ContextVar("mailaccess_no_ipgeo", default=False)
# Key fingerprints keep plan/failure state isolated when the operator changes keys.
_STATES: dict[str, dict[str, Any]] = {}
# A quota-exhausted key is retried after this pause; a rejected key stays off.
QUOTA_RETRY_SECONDS = 3600


class _RedactKey(logging.Filter):
    """httpx logs request URLs at INFO; query credentials must stay private."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(self._redact(value) for value in record.args)
        return True

    @staticmethod
    def _redact(value):
        if isinstance(value, (str, httpx.URL)) and str(value).startswith(BASE_URL):
            url = httpx.URL(value)
            if "apiKey" in url.params:
                return str(url.copy_set_param("apiKey", "REDACTED"))
        return value


logging.getLogger("httpx").addFilter(_RedactKey())


def set_no_ipgeo(value: bool):
    return _NO_IPGEO.set(bool(value))


def ipgeo_active(*, no_ipgeo: bool | None = None, cfg: Any = None) -> bool:
    cfg = cfg if cfg is not None else settings
    return bool(str(getattr(cfg, "ipgeolocation_api_key", "") or "").strip()) and not (
        getattr(cfg, "ipgeo_disabled", False) or (_NO_IPGEO.get() if no_ipgeo is None else no_ipgeo)
    )


def public_ips(ips) -> list[str]:
    out: dict[str, None] = {}
    for raw in ips:
        try:
            addr = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if addr.is_global and not (addr.is_multicast or addr.is_reserved):
            out.setdefault(str(addr), None)
    return list(out)


def key_fingerprint(key: str | None = None) -> str:
    return hashlib.sha256(str(key or settings.ipgeolocation_api_key or "").encode()).hexdigest()


def _state(key: str | None = None) -> dict[str, Any]:
    fingerprint = key_fingerprint(key)
    return _STATES.setdefault(
        fingerprint,
        {"tier": None, "blocked": False, "blocked_until": None, "warned": set(), "credits": 0, "calls": 0},
    )


def current_tier() -> str | None:
    return _state()["tier"]


def _warn(state: dict, reason: str) -> None:
    if reason not in state["warned"]:
        state["warned"].add(reason)
        _LOG.warning("ipgeolocation.io %s; continuing without fresh IP data", reason)


def normalise(item: dict, *, tier: str, fetched_at: str | None = None) -> dict:
    def block(name):
        value = item.get(name)
        return value if isinstance(value, dict) else {}

    location, asn, company, security, abuse = (
        block(n) for n in ("location", "asn", "company", "security", "abuse")
    )
    emails = abuse.get("emails")
    return {
        "ip": item["ip"],
        "country_code": location.get("country_code2"),
        "country": location.get("country_name"),
        "region": location.get("state_prov"),
        "city": location.get("city"),
        "asn": asn.get("as_number"),
        "org": asn.get("organization"),
        "company": company.get("name") if tier == "paid" else None,
        "company_type": company.get("type") if tier == "paid" else None,
        **{
            dest: security.get(src) if tier == "paid" else None
            for dest, src in {
                "is_cloud": "is_cloud_provider",
                "cloud_provider": "cloud_provider_name",
                "threat_score": "threat_score",
                "is_vpn": "is_vpn",
                "is_proxy": "is_proxy",
                "is_tor": "is_tor",
                "is_residential_proxy": "is_residential_proxy",
                "is_relay": "is_relay",
            }.items()
        },
        "abuse_email": (
            emails[0]
            if isinstance(emails, list) and emails
            else emails
            if isinstance(emails, str)
            else None
        )
        if tier == "paid"
        else None,
        "tier": tier,
        "fetched_at": fetched_at or datetime.now(timezone.utc).isoformat(),
        "from_cache": False,
    }


async def _lookup(ips: list[str], *, key: str, single: bool = False) -> dict[str, dict]:
    state = _state(key)
    if state["blocked"]:
        if state["blocked_until"] is None or time.monotonic() < state["blocked_until"]:
            return {}
        state["blocked"], state["blocked_until"] = False, None
        state["warned"].discard("quota exhausted")
    if not ips:
        return {}
    try:
        async with httpx.AsyncClient(timeout=max(0.1, settings.ipgeo_timeout_seconds)) as client:
            for attempt in range(2):
                params = {"apiKey": key}
                if state["tier"] != "free":
                    params["include"] = "security,abuse"
                state["calls"] += 1
                if single:
                    response = await client.get(
                        f"{BASE_URL}/v3/ipgeo", params={**params, "ip": ips[0]}
                    )
                else:
                    response = await client.post(
                        f"{BASE_URL}/v3/ipgeo-bulk", params=params, json={"ips": ips[:50000]}
                    )
                charged = response.headers.get("X-Credits-Charged")
                _LOG.info(
                    "ipgeolocation.io call charged %s credits",
                    charged if charged is not None else "unreported",
                )
                if charged is not None:
                    try:
                        state["credits"] += float(charged)
                    except ValueError:
                        pass
                try:
                    data = response.json()
                except ValueError:
                    _warn(state, "returned invalid JSON")
                    return {}
                message = str(data.get("message", "")).lower() if isinstance(data, dict) else ""
                # Live free-plan denial is also 401: inspect the subscription
                # message BEFORE treating 401 as a bad key.
                if (
                    response.status_code in (401, 403)
                    and "subscription" in message
                    and ("not supported" in message or "paid" in message)
                ):
                    state["tier"] = "free"
                    if attempt == 0:
                        continue
                if response.status_code != 200:
                    if response.status_code == 401:
                        state["blocked"] = True
                        _warn(state, "key rejected")
                    elif response.status_code == 429 and (
                        "limit" in message or "remaining" in message or "billing" in message
                    ):
                        state["blocked"] = True
                        state["blocked_until"] = time.monotonic() + QUOTA_RETRY_SECONDS
                        _warn(state, "quota exhausted")
                    else:
                        _warn(state, f"unavailable (HTTP {response.status_code})")
                    return {}
                items = [data] if single else data
                if not isinstance(items, list):
                    _warn(state, "returned an unexpected response")
                    return {}
                results = {}
                stamp = datetime.now(timezone.utc).isoformat()
                for item in items:
                    if (
                        not isinstance(item, dict)
                        or item.get("ip") not in ips
                        or item.get("message")
                        or item.get("error")
                    ):
                        continue
                    # Missing requested modules after a known-paid response is
                    # partial, not a clean empty answer. Never persist it.
                    security = isinstance(item.get("security"), dict)
                    abuse = isinstance(item.get("abuse"), dict)
                    if security != abuse or (state["tier"] == "paid" and not security):
                        continue
                    tier = "paid" if security and abuse else "free"
                    if not any(name in item for name in ("location", "asn", "security", "abuse")):
                        if not item.get("empty"):
                            continue
                    state["tier"] = tier
                    results[item["ip"]] = normalise(item, tier=tier, fetched_at=stamp)
                return results
    except (httpx.HTTPError, ValueError, TypeError):
        # Never include exception text: HTTP URLs carry the API key.
        _warn(state, "request failed or timed out")
    return {}


async def lookup_many(ips, *, no_ipgeo: bool | None = None) -> dict[str, dict]:
    cleaned = public_ips(ips)[:50000]
    if not ipgeo_active(no_ipgeo=no_ipgeo) or not cleaned:
        return {}
    return await _lookup(cleaned, key=str(settings.ipgeolocation_api_key).strip())


async def check_key(key: str) -> dict:
    state = _state(key)
    # An explicit test re-probes plan/credentials after a subscription upgrade.
    state["tier"], state["blocked"], state["blocked_until"] = None, False, None
    before = state["credits"]
    records = await _lookup(["8.8.8.8"], key=key, single=True)
    return {"ok": bool(records), "tier": state["tier"], "credits": state["credits"] - before}
