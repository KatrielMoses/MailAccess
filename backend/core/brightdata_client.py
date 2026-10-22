"""Optional BYOK Bright Data client: LinkedIn people-profile lookups (Pro).

One profile URL per call through the Web Scraper API (people-profile dataset). Failures
never escape callers: every problem comes back as ``None``. The key is never logged.

* 200: the record list comes back inline (first record used).
* 202: an async snapshot. Poll its progress at most ``MAX_POLLS`` times,
  ``POLL_INTERVAL_S`` apart, then read the snapshot; otherwise give up (None).
* Whole call bounded by ``settings.brightdata_timeout_seconds`` (25 s).
* 401/403: the key is rejected and stays off. 429: quota exhausted, retried after the
  server's Retry-After or ``QUOTA_RETRY_SECONDS``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from contextvars import ContextVar
from typing import Any

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)
BASE_URL = "https://api.brightdata.com"
DATASET_ID = "gd_l1viktl72bvl7bjuj0"  # LinkedIn people profiles
POLL_INTERVAL_S = 7.0
MAX_POLLS = 3
QUOTA_RETRY_SECONDS = 3600
_NO_BRIGHTDATA: ContextVar[bool] = ContextVar("mailaccess_no_brightdata", default=False)
_STATES: dict[str, dict[str, Any]] = {}


class _RedactKey(logging.Filter):
    """Belt and braces: the key travels in a header httpx doesn't log, but if it ever
    reaches a log record (message or args) it is replaced."""

    def __init__(self, prefix: str = BASE_URL) -> None:
        super().__init__()
        self._prefix = prefix

    def filter(self, record: logging.LogRecord) -> bool:
        key = str(settings.brightdata_api_key or "")
        if key:
            if isinstance(record.msg, str) and key in record.msg:
                record.msg = record.msg.replace(key, "REDACTED")
            if isinstance(record.args, tuple):
                record.args = tuple(
                    str(a).replace(key, "REDACTED") if key in str(a) else a for a in record.args
                )
        return True


logging.getLogger("httpx").addFilter(_RedactKey())
_LOG.addFilter(_RedactKey())


def set_no_brightdata(value: bool):
    return _NO_BRIGHTDATA.set(bool(value))


def brightdata_active(*, no_brightdata: bool | None = None, cfg: Any = None) -> bool:
    """Key set, not persistently disabled, not opted out for this run."""
    cfg = cfg if cfg is not None else settings
    return bool(str(getattr(cfg, "brightdata_api_key", "") or "").strip()) and not (
        getattr(cfg, "brightdata_disabled", False)
        or (_NO_BRIGHTDATA.get() if no_brightdata is None else no_brightdata)
    )


def key_fingerprint(key: str | None = None) -> str:
    return hashlib.sha256(str(key or settings.brightdata_api_key or "").encode()).hexdigest()


def _state(key: str | None = None) -> dict[str, Any]:
    return _STATES.setdefault(
        key_fingerprint(key),
        {"rejected": False, "blocked_until": None, "calls": 0, "warned": set()},
    )


def _warn(state: dict, reason: str) -> None:
    if reason not in state["warned"]:
        state["warned"].add(reason)
        _LOG.warning("Bright Data %s; continuing without the LinkedIn card", reason)


def available(key: str | None = None) -> bool:
    """False while the key is rejected or inside a quota back-off window."""
    state = _state(key)
    if state["rejected"]:
        return False
    until = state["blocked_until"]
    if until is not None and time.monotonic() < until:
        return False
    if until is not None:
        state["blocked_until"] = None
        state["warned"].discard("quota exhausted")
    return True


def _first_record(data: Any) -> dict | None:
    records = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    for rec in records:
        # include_errors=true: a failed URL comes back as a record with an error field.
        if isinstance(rec, dict) and not rec.get("error") and not rec.get("error_code"):
            return rec
    return None


def _handle_status(state: dict, response: httpx.Response) -> bool:
    """True when the response is usable; records rejection / quota otherwise."""
    if response.status_code in (401, 403):
        state["rejected"] = True
        _warn(state, "key rejected")
        return False
    if response.status_code == 429:
        try:
            wait = float(response.headers.get("retry-after") or QUOTA_RETRY_SECONDS)
        except ValueError:
            wait = QUOTA_RETRY_SECONDS
        state["blocked_until"] = time.monotonic() + max(1.0, wait)
        _warn(state, "quota exhausted")
        return False
    return response.status_code in (200, 202)


async def fetch_profile(
    profile_url: str, *, transport: httpx.AsyncBaseTransport | None = None
) -> dict | None:
    """The Bright Data record for one LinkedIn profile URL, or None."""
    key = str(settings.brightdata_api_key or "").strip()
    if not key or not available(key):
        return None
    state = _state(key)
    timeout = max(1.0, float(settings.brightdata_timeout_seconds))
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    async def _call() -> dict | None:
        async with httpx.AsyncClient(timeout=timeout, transport=transport, headers=headers) as client:
            state["calls"] += 1
            response = await client.post(
                f"{BASE_URL}/datasets/v3/scrape",
                params={"dataset_id": DATASET_ID, "format": "json", "include_errors": "true"},
                json=[{"url": profile_url}],
            )
            if not _handle_status(state, response):
                return None
            try:
                body = response.json()
            except ValueError:
                return None
            if response.status_code == 200:
                return _first_record(body)
            snapshot_id = body.get("snapshot_id") if isinstance(body, dict) else None
            if not snapshot_id:
                return None
            for _ in range(MAX_POLLS):
                await asyncio.sleep(POLL_INTERVAL_S)
                progress = await client.get(f"{BASE_URL}/datasets/v3/progress/{snapshot_id}")
                if not _handle_status(state, progress):
                    return None
                status = str((progress.json() or {}).get("status") or "").lower()
                if status == "ready":
                    snap = await client.get(
                        f"{BASE_URL}/datasets/v3/snapshot/{snapshot_id}", params={"format": "json"}
                    )
                    if not _handle_status(state, snap) or snap.status_code != 200:
                        return None
                    return _first_record(snap.json())
                if status == "failed":
                    return None
            return None

    try:
        return await asyncio.wait_for(_call(), timeout=timeout)
    except (asyncio.TimeoutError, httpx.HTTPError, ValueError) as exc:
        _LOG.info("Bright Data lookup gave no result (%s)", type(exc).__name__)
        return None
