"""Optional BYOK WhoisFreaks client: WHOIS history, reverse WHOIS, dated subdomains.

Failures never escape callers. The API key travels in the query string, so no
URL or exception text is ever logged or returned.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import settings
from .ipgeo_client import _RedactKey

_LOG = logging.getLogger(__name__)
BASE_URL = "https://api.whoisfreaks.com"
WHOISFREAKS_SIGNUP_URL = "https://whoisfreaks.com/"
_NO_WHOISFREAKS: ContextVar[bool] = ContextVar("mailaccess_no_whoisfreaks", default=False)
_STATES: dict[str, dict[str, Any]] = {}
_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}
# A quota-exhausted key is retried after this pause; a rejected key stays off.
QUOTA_RETRY_SECONDS = 3600
# Credits per call (the API returns no credit header).
COSTS = {
    "history": 2,
    "reverse_company": 5,
    "reverse_company_broad": 5,
    "reverse_email": 5,
    "subdomains": 2,
    "live": 1,
    "usage": 0,
}
_PATHS = {
    "history": "/v2.0/whois/history",
    "reverse_company": "/v2.0/whois/reverse",
    "reverse_company_broad": "/v2.0/whois/reverse",
    "live": "/v2.0/whois/live",
    "reverse_email": "/v2.0/whois/reverse",
    "subdomains": "/v1.0/subdomains",
    "usage": "/v1.0/whoisapi/usage",
}
# The shape key each endpoint must carry for a 200 to count as a real answer.
_ROWS_KEY = {
    "history": "whois_domains_historical",
    "reverse_company": "whois_domains_historical",
    "reverse_company_broad": "whois_domains_historical",
    "reverse_email": "whois_domains_historical",
    "subdomains": "subdomains",
}
# Rate-limit buckets: history/reverse/subdomains share one (3 a minute on this plan);
# live WHOIS has its own (20 a minute); usage is free and unmetered.
_BUCKET = {"live": "live", "usage": None}
# Fallback pause when a 429 carries no usable reset header.
_DEFAULT_RESET_SECONDS = 20.0

logging.getLogger("httpx").addFilter(_RedactKey(BASE_URL))


@dataclass
class WFResult:
    """``ok`` (data set), ``empty`` (clean 404/403), ``error`` or ``skipped``."""

    status: str
    data: Any = None

    @property
    def clean(self) -> bool:
        """True when the answer is safe to cache (real data or a clean empty)."""
        return self.status in ("ok", "empty")


def set_no_whoisfreaks(value: bool):
    return _NO_WHOISFREAKS.set(bool(value))


def whoisfreaks_active(*, no_whoisfreaks: bool | None = None, cfg: Any = None) -> bool:
    cfg = cfg if cfg is not None else settings
    return bool(str(getattr(cfg, "whoisfreaks_api_key", "") or "").strip()) and not (
        getattr(cfg, "whoisfreaks_disabled", False)
        or (_NO_WHOISFREAKS.get() if no_whoisfreaks is None else no_whoisfreaks)
    )


def key_fingerprint(key: str | None = None) -> str:
    return hashlib.sha256(str(key or settings.whoisfreaks_api_key or "").encode()).hexdigest()


def _state(key: str | None = None) -> dict[str, Any]:
    return _STATES.setdefault(
        key_fingerprint(key),
        {
            "blocked": False,
            "blocked_until": None,
            "warned": set(),
            "credits": 0,
            "calls": 0,
            "buckets": {
                "shared": {"remaining": None, "reset_at": 0.0},
                "live": {"remaining": None, "reset_at": 0.0},
            },
        },
    )


def credits_spent(key: str | None = None) -> int:
    return int(_state(key)["credits"])


def _warn(state: dict, reason: str) -> None:
    if reason not in state["warned"]:
        state["warned"].add(reason)
        _LOG.warning("WhoisFreaks %s; continuing without fresh WHOIS data", reason)


def _lock(key: str, bucket: str) -> asyncio.Lock:
    loop_id = id(asyncio.get_running_loop())
    return _LOCKS.setdefault((key_fingerprint(key), loop_id, bucket), asyncio.Lock())


def _sleep(seconds: float):
    return asyncio.sleep(seconds)


def _track_headers(bucket: dict, headers: Any) -> None:
    try:
        remaining = headers.get("x-ratelimit-remaining-requests")
        reset_ns = headers.get("x-ratelimit-remaining-time")
        if remaining is not None:
            bucket["remaining"] = int(float(remaining))
        if reset_ns is not None:
            bucket["reset_at"] = time.monotonic() + max(0.0, float(reset_ns)) / 1e9
    except (TypeError, ValueError):
        pass


def _message(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return ""
    return str(data.get("message", "")).lower() if isinstance(data, dict) else ""


async def _acquire(lock: asyncio.Lock, deadline: float | None) -> bool:
    """Take the bucket lock, but never wait past the caller's deadline."""
    if deadline is None:
        await lock.acquire()
        return True
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        await asyncio.wait_for(lock.acquire(), timeout=remaining)
    except asyncio.TimeoutError:
        return False
    return True


async def _pace(bucket: dict, deadline: float | None) -> bool:
    """Wait for an exhausted bucket only if that fits the caller's deadline."""
    if bucket["remaining"] is None or bucket["remaining"] > 0:
        return True
    wait = bucket["reset_at"] - time.monotonic()
    if wait <= 0:
        bucket["remaining"] = None
        return True
    if deadline is not None and time.monotonic() + wait > deadline:
        return False
    await _sleep(wait + 0.05)
    bucket["remaining"] = None
    return True


async def _request(
    kind: str, params: dict[str, Any], *, key: str, deadline: float | None = None
) -> WFResult:
    state = _state(key)
    if state["blocked"]:
        if state["blocked_until"] is None or time.monotonic() < state["blocked_until"]:
            return WFResult("skipped")
        state["blocked"], state["blocked_until"] = False, None
        state["warned"].discard("quota exhausted")
    path = _PATHS[kind]
    bucket_name = _BUCKET.get(kind, "shared")
    shared = bucket_name is not None
    bucket = state["buckets"][bucket_name] if shared else None
    try:
        async with httpx.AsyncClient(
            timeout=max(0.1, settings.whoisfreaks_timeout_seconds)
        ) as client:
            retried_transient = retried_limit = False
            while True:
                if shared:
                    # One in-flight call per key keeps bursts inside the bucket.
                    lock = _lock(key, bucket_name)
                    if not await _acquire(lock, deadline):
                        return WFResult("skipped")
                    try:
                        if deadline is not None and time.monotonic() >= deadline:
                            return WFResult("skipped")
                        if not await _pace(bucket, deadline):
                            return WFResult("skipped")
                        state["calls"] += 1
                        response = await client.get(
                            f"{BASE_URL}{path}", params={**params, "apiKey": key}
                        )
                        _track_headers(bucket, response.headers)
                    finally:
                        lock.release()
                else:
                    state["calls"] += 1
                    response = await client.get(
                        f"{BASE_URL}{path}", params={**params, "apiKey": key}
                    )
                code = response.status_code
                message = _message(response)
                if code == 429:
                    if not shared:
                        return WFResult("skipped")
                    if bucket["remaining"] is None or bucket["reset_at"] <= time.monotonic():
                        bucket["reset_at"] = time.monotonic() + _DEFAULT_RESET_SECONDS
                    bucket["remaining"] = 0
                    if retried_limit:
                        return WFResult("skipped")
                    retried_limit = True
                    continue  # _pace waits for the reset or skips past the deadline
                if code == 401:
                    if "credit" in message or "subscription" in message or "plan" in message:
                        state["blocked"] = True
                        state["blocked_until"] = time.monotonic() + QUOTA_RETRY_SECONDS
                        _warn(state, "quota exhausted")
                    else:
                        state["blocked"] = True
                        _warn(state, "key rejected")
                    return WFResult("error")
                if code == 413:
                    state["blocked"] = True
                    state["blocked_until"] = time.monotonic() + QUOTA_RETRY_SECONDS
                    _warn(state, "quota exhausted")
                    return WFResult("error")
                if code in (404, 403):
                    state["credits"] += COSTS[kind] if code == 404 else 0
                    return WFResult("empty")
                if code == 408 or code >= 500:
                    if retried_transient:
                        _warn(state, f"unavailable (HTTP {code})")
                        return WFResult("error")
                    retried_transient = True
                    continue
                if code != 200:
                    _warn(state, f"unavailable (HTTP {code})")
                    return WFResult("error")
                state["credits"] += COSTS[kind]
                try:
                    data = response.json()
                except ValueError:
                    _warn(state, "returned invalid JSON")
                    return WFResult("error")
                if not isinstance(data, dict):
                    _warn(state, "returned an unexpected response")
                    return WFResult("error")
                rows_key = _ROWS_KEY.get(kind)
                if rows_key and not isinstance(data.get(rows_key), list):
                    _warn(state, "returned an unexpected response")
                    return WFResult("error")
                return WFResult("ok", data)
    except Exception:  # noqa: BLE001 - nothing may raise into a module
        # Never include exception text: HTTP URLs carry the API key.
        _warn(state, "request failed or timed out")
    return WFResult("error")


def _active_key(no_whoisfreaks: bool | None) -> str | None:
    if not whoisfreaks_active(no_whoisfreaks=no_whoisfreaks):
        return None
    return str(settings.whoisfreaks_api_key).strip()


async def _call(kind: str, params: dict[str, Any], deadline: float | None, no_wf: bool | None):
    key = _active_key(no_wf)
    if key is None:
        return WFResult("skipped")
    return await _request(kind, params, key=key, deadline=deadline)


async def history(
    domain: str, page: int = 1, *, deadline: float | None = None, no_whoisfreaks: bool | None = None
) -> WFResult:
    return await _call("history", {"domainName": domain, "page": page}, deadline, no_whoisfreaks)


async def reverse_company(
    name: str, page: int = 1, *, deadline: float | None = None, no_whoisfreaks: bool | None = None
) -> WFResult:
    # Exact matching only: the default substring search returns noise.
    params = {"company": name, "exact": "true", "mode": "mini", "page": page}
    return await _call("reverse_company", params, deadline, no_whoisfreaks)


async def reverse_company_broad(
    name: str, page: int = 1, *, deadline: float | None = None, no_whoisfreaks: bool | None = None
) -> WFResult:
    """Substring company search (``exact=false``); callers must filter the noise."""
    params = {"company": name, "exact": "false", "mode": "mini", "page": page}
    return await _call("reverse_company_broad", params, deadline, no_whoisfreaks)


async def live(
    domain: str, page: int = 1, *, deadline: float | None = None, no_whoisfreaks: bool | None = None
) -> WFResult:
    """Current WHOIS record (1 credit). ``page`` is accepted for lookup symmetry."""
    return await _call("live", {"domainName": domain}, deadline, no_whoisfreaks)


async def reverse_email(
    email: str, page: int = 1, *, deadline: float | None = None, no_whoisfreaks: bool | None = None
) -> WFResult:
    params = {"email": email, "mode": "mini", "page": page}
    return await _call("reverse_email", params, deadline, no_whoisfreaks)


async def subdomains(
    domain: str, page: int = 1, *, deadline: float | None = None, no_whoisfreaks: bool | None = None
) -> WFResult:
    params = {"domain": domain, "status": "active", "page": page}
    return await _call("subdomains", params, deadline, no_whoisfreaks)


async def usage(key: str | None = None) -> dict | None:
    """Remaining credits from the free usage endpoint; the echoed key is dropped."""
    key = str(key or settings.whoisfreaks_api_key or "").strip()
    if not key:
        return None
    result = await _request("usage", {}, key=key)
    credits = result.data.get("apiCredits") if result.status == "ok" else None
    if not isinstance(credits, dict):
        return None
    try:
        total, served = int(credits["totalCredits"]), int(credits["servedRequest"])
    except (KeyError, TypeError, ValueError):
        return None
    # Only the two counters survive; the response's apiKey field is never kept.
    return {"total_credits": total, "served": served, "remaining": total - served}


async def check_key(key: str) -> dict:
    """One free call: success means the key is accepted by the usage endpoint."""
    state = _state(key)
    state["blocked"], state["blocked_until"] = False, None
    info = await usage(key)
    return {"ok": info is not None, "remaining": info["remaining"] if info else None}
