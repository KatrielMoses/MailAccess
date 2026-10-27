"""Optional BYOK Oxylabs Web Search client (Pro).

A thin wrapper over the Oxylabs Web Search API (``webapi.oxylabs.io/v1/search``, Bearer
auth). Used to discover a subject's public social profiles (Instagram / Facebook /
LinkedIn) from search results — name, handle, profile URL, and the SERP snippet (which
carries IG follower stats and LinkedIn job title/company). No bot-evasion: it's a search
query. Failures never escape callers (return ``[]``); the token is never logged.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)
_SEARCH_URL = "https://webapi.oxylabs.io/v1/search"
_TIMEOUT_S = 40.0
_QUOTA_RETRY_S = 1800
_STATE: dict[str, Any] = {"rejected": False, "blocked_until": None, "warned": set()}


class _Redact(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        tok = str(settings.oxylabs_search_token or "")
        if tok and isinstance(record.msg, str) and tok in record.msg:
            record.msg = record.msg.replace(tok, "REDACTED")
        return True


logging.getLogger("httpx").addFilter(_Redact())
_LOG.addFilter(_Redact())


def oxylabs_active(cfg: Any = None) -> bool:
    cfg = cfg if cfg is not None else settings
    return bool(str(getattr(cfg, "oxylabs_search_token", "") or "").strip())


def _available() -> bool:
    if _STATE["rejected"]:
        return False
    until = _STATE["blocked_until"]
    return not (until is not None and time.monotonic() < until)


def _warn(reason: str) -> None:
    if reason not in _STATE["warned"]:
        _STATE["warned"].add(reason)
        _LOG.warning("Oxylabs %s; continuing without the social discovery", reason)


async def web_search(
    query: str, *, max_results: int = 6, transport: httpx.AsyncBaseTransport | None = None
) -> list[dict]:
    """Return Oxylabs Web Search results (each ``{title, url, outline, metadata}``), or [].

    Pro + BYOK: needs ``oxylabs_search_token``. Never raises.
    """
    token = str(getattr(settings, "oxylabs_search_token", "") or "").strip()
    if not token or not _available() or not query.strip():
        return []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S, transport=transport) as client:
            resp = await client.post(
                _SEARCH_URL,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"query": query, "max_results": max_results},
            )
            if resp.status_code in (401, 403):
                _STATE["rejected"] = True
                _warn("token rejected")
                return []
            if resp.status_code == 429:
                try:
                    wait = float(resp.headers.get("retry-after") or _QUOTA_RETRY_S)
                except ValueError:
                    wait = _QUOTA_RETRY_S
                _STATE["blocked_until"] = time.monotonic() + max(1.0, wait)
                _warn("quota exhausted")
                return []
            if resp.status_code != 200:
                return []
            data = resp.json()
        results = data.get("results") if isinstance(data, dict) else None
        return [r for r in (results or []) if isinstance(r, dict)]
    except (httpx.HTTPError, ValueError) as exc:
        _LOG.info("Oxylabs web_search gave no result (%s)", type(exc).__name__)
        return []
