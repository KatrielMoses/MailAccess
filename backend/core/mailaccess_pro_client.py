"""0.17.0 Phase 1 — client for the MailAccess Pro corpus lead engine.

Modeled on :mod:`apollo_client`, with one deliberate difference: the base URL is
read from ``settings.mailaccess_pro_base_url`` (host-as-config), never hardcoded.
That is what makes the Pi5 → Hetzner migration a config change rather than a code
change — the moat engine's *location* is operational, not baked in.

The engine is queried ONLY by this backend, over a private mesh, and is
authenticated with the ``X-MailAccess-Engine-Secret`` shared secret
(defense-in-depth before the Tailscale mesh exists). The secret and the full row
payloads are never logged at info level.

Error-handling contract: on *any* transport / HTTP / decode error the client
raises :class:`ProEngineUnavailable`. The route turns that into a well-formed
``status: "unavailable"`` envelope (invariant 4 — fail open to Stream 1), never a
5xx to the caller.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from typing import Any

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)

_SEARCH_PATH = "/api/internal/search"
# C2 — TOTAL wall-clock budget for one engine call (connect + full body). Enforced
# with asyncio.wait_for so a drip response that keeps a per-read timeout from ever
# firing cannot run past this. Kept as the single knob the tests tune.
_TIMEOUT = 15.0
# C2 — hard cap on the buffered response body so a very large / never-terminating
# body can't exhaust memory. 32 MiB comfortably exceeds a 500-row corpus page.
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_SECRET_HEADER = "X-MailAccess-Engine-Secret"


class ProEngineUnavailable(RuntimeError):
    """The Pro corpus engine could not be reached / returned an unusable response.

    Raised for connect/read timeouts, transport errors, non-2xx HTTP status, and
    malformed JSON. The caller (``/v1/enrich``) fails open on this.
    """


def _base_url() -> str:
    return str(getattr(settings, "mailaccess_pro_base_url", "") or "").rstrip("/")


def _engine_secret() -> str:
    return str(getattr(settings, "mailaccess_pro_engine_secret", "") or "")


async def search(
    query: str,
    *,
    mode: str,
    limit: int,
    offset: int,
    verified_only: bool = False,
) -> dict[str, Any]:
    """Query the corpus engine's internal search endpoint.

    Returns the parsed ``{rows, organizations, total, mode, has_more}`` block.
    Raises :class:`ProEngineUnavailable` on any transport/HTTP/decode failure or a
    non-object response body.
    """
    base = _base_url()
    if not base:
        raise ProEngineUnavailable("mailaccess_pro_base_url is not configured")

    url = f"{base}{_SEARCH_PATH}"
    params = {
        "q": query,
        "mode": mode,
        "limit": str(limit),
        "offset": str(offset),
        "verified_only": "true" if verified_only else "false",
    }
    headers = {_SECRET_HEADER: _engine_secret()}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            # C2 — the whole request (connect + streamed body) is bounded by ONE
            # total deadline; a per-read timeout resets on every dripped byte, so
            # only this wait_for guarantees termination.
            payload = await asyncio.wait_for(
                _fetch_json(client, url, params, headers, mode), timeout=_TIMEOUT
            )
    except (httpx.HTTPError, OSError) as exc:
        # Never include the secret or the params in the log line.
        _LOG.warning("Pro engine transport error (mode=%s): %s", mode, type(exc).__name__)
        raise ProEngineUnavailable("pro engine transport error") from exc
    except asyncio.TimeoutError as exc:
        _LOG.warning("Pro engine total deadline exceeded (mode=%s)", mode)
        raise ProEngineUnavailable("pro engine total deadline exceeded") from exc

    # C3 — validate the upstream SHAPE before trusting it. A malformed object
    # (``rows``/``organizations`` not a list, ``total`` neither a finite number nor
    # null) is an unusable response → fail open to ``unavailable``, never a 500.
    if not isinstance(payload, dict):
        raise ProEngineUnavailable("pro engine returned a non-object body")
    rows = payload.get("rows")
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise ProEngineUnavailable("pro engine 'rows' is not a list")
    orgs = payload.get("organizations")
    if orgs is None:
        orgs = []
    if not isinstance(orgs, list):
        raise ProEngineUnavailable("pro engine 'organizations' is not a list")
    total = payload.get("total")
    if total is not None and (
        isinstance(total, bool)
        or not isinstance(total, int | float)
        or not math.isfinite(total)
    ):
        raise ProEngineUnavailable("pro engine 'total' is not a finite number or null")

    return {
        "rows": rows,
        "organizations": orgs,
        "total": total,
        "mode": payload.get("mode") or mode,
        "has_more": bool(payload.get("has_more")),
    }


async def _fetch_json(
    client: httpx.AsyncClient,
    url: str,
    params: dict[str, str],
    headers: dict[str, str],
    mode: str,
) -> Any:
    """Stream the engine response, enforcing the response-size cap, and decode JSON.

    Streaming (rather than ``client.get``) lets us abort a body that grows past
    :data:`_MAX_RESPONSE_BYTES` instead of buffering it whole. The caller wraps this
    in ``asyncio.wait_for`` for the total wall-clock deadline."""
    async with client.stream("GET", url, params=params, headers=headers) as resp:
        if resp.status_code != 200:
            _LOG.warning("Pro engine returned HTTP %d (mode=%s)", resp.status_code, mode)
            raise ProEngineUnavailable(f"pro engine HTTP {resp.status_code}")
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > _MAX_RESPONSE_BYTES:
                raise ProEngineUnavailable("pro engine response exceeded size cap")
            chunks.append(chunk)
    body = b"".join(chunks)
    try:
        return json.loads(body)
    except ValueError as exc:  # includes json.JSONDecodeError
        _LOG.warning("Pro engine returned non-JSON body (mode=%s)", mode)
        raise ProEngineUnavailable("pro engine returned malformed JSON") from exc
