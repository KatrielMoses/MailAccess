"""0.17.0 Phase 2 — the LOCAL Pro connector (Stream 2 discovery source).

Distinct from :mod:`mailaccess_pro_client` (Phase 1), which runs on the hosted
backend and queries the corpus engine directly. THIS connector runs in the
user's local harvest pipeline and calls ``/v1/enrich`` through the public website
(``mailaccess.pro``). It must never see or address the engine — the moat data
only ever transits as per-query projected results (invariants 3 & 5).

It is a DISCOVERY source, not an enrichment field-filler: the orchestrator injects
each returned lead as a net-new ``HarvestedEmail`` row (evidence for the 1E
resolver), never through the enrichment waterfall (frozen contract, Blocker 1).

Fail-open, hard (invariant 4): no key, any transport/HTTP error, malformed body,
or a non-``ok`` envelope (``unavailable``/``empty``) all resolve to an empty lead
list. Stream 1 (the open-source result) must survive a completely dead API — this
function NEVER raises into the pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)

_ENRICH_PATH = "/v1/enrich"
# C2 — TOTAL wall-clock budget for one hosted call (connect + full streamed body),
# enforced with asyncio.wait_for so a drip response cannot outlive it.
_TIMEOUT = 20.0
# C2 — hard cap on the buffered response body (defense against a runaway body).
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024

_EMPTY: dict[str, Any] = {"status": "unavailable", "leads": []}

# C1 (second trust boundary) — re-validate each projected lead the hosted API
# returned before it enters the local pipeline. The hosted route already applies
# the §2 schema, but the connector is a SEPARATE boundary and must not trust it:
# non-scalars are dropped, strings are length-bounded, ``source`` is enum-checked,
# ``corpus_verified`` is a strict bool, and ``linkedin_slug`` matches the slug shape.
_MAX_NAME_LEN = 200
_MAX_TITLE_LEN = 200
_MAX_EMAIL_LEN = 254
_KNOWN_CORPUS_SOURCES = frozenset(
    {"linkedin", "apollo", "pdl", "github", "crawl", "web", "corpus", "press"}
)
_LINKEDIN_SLUG_RE = re.compile(r"^[A-Za-z0-9%][A-Za-z0-9\-_%]{0,99}$")


def _api_url() -> str:
    return str(getattr(settings, "mailaccess_pro_api_url", "") or "").rstrip("/")


def _pro_key() -> str | None:
    key = getattr(settings, "mailaccess_pro_key", None)
    return str(key) if key else None


def _bounded_str(value: Any, maxlen: int) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v if v and len(v) <= maxlen else None


def _sanitize_lead(lead: Any) -> dict[str, Any] | None:
    """Coerce one projected lead to strictly-typed scalars, or drop it (None).

    Every field is validated independently so a nested dict/list (e.g. smuggled PII
    under ``source``) can never survive: it is reduced to None. A lead with no email
    is useless downstream and is dropped."""
    if not isinstance(lead, dict):
        return None
    email = _bounded_str(lead.get("email"), _MAX_EMAIL_LEN)
    if not email:
        return None
    slug = lead.get("linkedin_slug")
    if not (isinstance(slug, str) and _LINKEDIN_SLUG_RE.match(slug)):
        slug = None
    url = f"https://linkedin.com/in/{slug}" if slug else None
    source = lead.get("source")
    if not (isinstance(source, str) and source in _KNOWN_CORPUS_SOURCES):
        source = None
    return {
        "name": _bounded_str(lead.get("name"), _MAX_NAME_LEN),
        "title": _bounded_str(lead.get("title"), _MAX_TITLE_LEN),
        "email": email,
        "linkedin_slug": slug,
        "linkedin_url": url,
        "source": source,
        "corpus_verified": lead.get("corpus_verified") is True,
    }


async def fetch_leads(
    query: str,
    *,
    type: str = "domain",
    limit: int = 500,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Fetch projected corpus leads for *query* from the hosted ``/v1/enrich``.

    Returns the projected envelope (``{status, leads, ...}``). On ANY failure
    condition — missing key, transport/HTTP error, bad JSON, or a non-``ok``
    status — returns ``{"status": ..., "leads": []}``: an empty lead list, never
    an exception. The caller treats an empty list as "Stream 1 only".
    """
    key = _pro_key()
    if not key:
        return dict(_EMPTY)
    base = _api_url()
    if not base:
        return dict(_EMPTY)

    body: dict[str, Any] = {"query": query, "type": type, "limit": limit}
    if cursor:
        body["cursor"] = cursor

    env = await _post_json(base, body, key)
    if env is None:
        return dict(_EMPTY)

    if not isinstance(env, dict) or env.get("status") != "ok":
        # unavailable / empty / disambiguation → no leads to inject.
        status = env.get("status") if isinstance(env, dict) else "unavailable"
        return {"status": status, "leads": []}

    leads = env.get("leads")
    # C1 — sanitize each lead at THIS boundary (drop non-scalars / bad shapes).
    return {
        "status": "ok",
        "leads": _sanitize_leads(leads),
        "has_more": bool(env.get("has_more")),
        "cursor": env.get("cursor"),
    }


def _sanitize_leads(leads: Any) -> list[dict[str, Any]]:
    if not isinstance(leads, list):
        return []
    out: list[dict[str, Any]] = []
    for ld in leads:
        clean = _sanitize_lead(ld)
        if clean is not None:
            out.append(clean)
    return out


async def _post_json(base: str, body: dict[str, Any], key: str) -> Any | None:
    """Bounded, size-capped POST to ``/v1/enrich`` → parsed JSON, or None on any
    failure (transport / non-200 / total-deadline / size-cap / bad JSON). The
    connector is fail-open, so every failure collapses to ``None`` here."""
    headers = {"Authorization": f"Bearer {key}"}
    url = f"{base}{_ENRICH_PATH}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            return await asyncio.wait_for(
                _stream_json(client, url, body, headers), timeout=_TIMEOUT
            )
    except (httpx.HTTPError, OSError):
        _LOG.debug("mailaccess_pro connector transport error; Stream 1 only", exc_info=True)
        return None
    except asyncio.TimeoutError:
        _LOG.debug("mailaccess_pro connector total deadline exceeded; Stream 1 only")
        return None
    except ValueError:  # bad JSON / size cap surfaced as ValueError
        _LOG.debug("mailaccess_pro connector unusable body; Stream 1 only")
        return None


async def _stream_json(
    client: httpx.AsyncClient, url: str, body: dict[str, Any], headers: dict[str, str]
) -> Any:
    async with client.stream("POST", url, json=body, headers=headers) as resp:
        if resp.status_code != 200:
            _LOG.debug("mailaccess_pro connector HTTP %d; Stream 1 only", resp.status_code)
            raise ValueError("non-200")
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > _MAX_RESPONSE_BYTES:
                raise ValueError("response too large")
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


async def resolve_company(company: str) -> dict[str, Any]:
    """Resolve a company name → domain via ``/v1/enrich`` (``type: company``).

    Returns the raw envelope shape the CLI needs to branch on:
    ``{status, company, candidates}``. ``status`` is one of ``ok``
    (``company.domain`` is the resolved domain), ``disambiguation``
    (``candidates`` lists ``{name, domain, employees}``), ``empty`` (no match),
    or ``unavailable`` (no key / wrong mode / dead API). Fail-open: any error →
    ``{"status": "unavailable"}`` — never raises.
    """
    key = _pro_key()
    if not key:
        return {"status": "unavailable"}
    base = _api_url()
    if not base:
        return {"status": "unavailable"}

    body = {"query": company, "type": "company"}
    env = await _post_json(base, body, key)
    if not isinstance(env, dict):
        return {"status": "unavailable"}

    status = env.get("status")
    if status == "ok":
        return {"status": "ok", "company": env.get("company") or {}}
    if status == "disambiguation":
        candidates = env.get("candidates")
        return {
            "status": "disambiguation",
            "candidates": [c for c in candidates if isinstance(c, dict)]
            if isinstance(candidates, list)
            else [],
        }
    if status == "empty":
        return {"status": "empty"}
    return {"status": "unavailable"}
