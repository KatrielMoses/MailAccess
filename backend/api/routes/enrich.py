"""0.17.0 Phase 1 — ``POST /v1/enrich``: the hosted paid lead-enrichment tier.

This is the single authenticated, governed, host-agnostic seam between MailAccess
and the private corpus lead engine (§2 of the frozen Phase-0 contract). A valid
Pro key gets projected corpus leads for a domain or company; everything else is a
well-formed envelope, never a 5xx.

Auth: a Pro key in ``Authorization: Bearer <key>`` (or ``X-MailAccess-Pro-Key``),
validated against the entitlement store. Invalid/absent → a uniform 401 (we never
reveal whether a key exists-but-inactive vs. never-existed). This is the ONLY real
HTTP error the route emits.

Lawful-basis gate (server-authoritative): while
``settings.mailaccess_pro_lawful_basis_established`` is False the tier is
``unavailable`` (reason ``lead_tier_not_yet_available``) regardless of key
validity — the Phase-6 public-launch gate, enforced here and not only in a client.

Projection is a HARD PII boundary: each engine row is reduced to
``name, title, email, linkedin_slug, linkedin_url, source, corpus_verified`` and
nothing else — ``phone, city, state, country, website, industry, seniority`` must
not cross this boundary. ``corpus_verified`` is provenance only (invariant 2): it
is never a confirmed-verification claim.

Fail-open taxonomy (invariant 4): engine unreachable/timeout/bad-JSON →
``unavailable``; lawful-basis off → ``unavailable``; no results → ``empty``;
ambiguous company → ``disambiguation``. Only auth failure is a 401.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ...config import settings
from ...core import mailaccess_pro_client as pro_client
from ...core import suppression
from ...core.mailaccess_pro_client import ProEngineUnavailable
from ...core.pro_keys import hash_key, validate_pro_key
from ...core.pro_query_queue import ProQueueUnavailable, get_queue
from ...core.suppression import SuppressionUnavailable

_LOG = logging.getLogger(__name__)

router = APIRouter()

_PROVENANCE = "MailAccess Pro corpus"
_REASON_LAWFUL_BASIS = "lead_tier_not_yet_available"
_REASON_ENGINE = "engine_unavailable"
# Round 2 Item B — 500-cap depth policy (replaces the limit=100 page). A request
# `limit` is clamped to this; a domain's servable set is capped here too.
_MAX_LIMIT = 500
_DEFAULT_LIMIT = 50
_DEPTH_CAP = 500
# Item B edge case (DEFAULT LOCKED): when total > 500 but verified < 500, fill the
# 500 verified-first then top up with unverified. Owner may flip to strictly
# verified-only by setting this False.
_PRO_OVER_CAP_FILL_UNVERIFIED = True
# The engine's max rows per page is unknown/variable; paginate in chunks this big
# (bounded by _DEPTH_CAP) under the single concurrency-1 acquire.
_ENGINE_PAGE = 500
# C4 — hard ceiling on pages per _collect so a duplicate / has_more-forever engine
# response can never loop unboundedly even if every page adds one new distinct row.
_MAX_PAGES = 8
# C2 — overall wall-clock budget for one /v1/enrich serve, spanning company
# resolution + all paginated depth + the personal fetch. A serve that exceeds it
# fails open to an ``unavailable`` envelope (never an indefinite hang).
_SERVE_DEADLINE_SECONDS = 60.0
_REASON_TIMEOUT = "engine_timeout"
_REASON_BUSY = "engine_busy"
# D1 — the suppression store could not be read; fail CLOSED (serve nothing) rather
# than emit a lead that might belong to an objecting subject.
_REASON_SUPPRESSION = "suppression_unavailable"

# Personal / consumer providers. Brief B (B2) — this is the SINGLE source of truth
# for consumer-provider detection, used to reject a "consumer domain is not a
# company" query target. Two layers:
#
# * ``_PERSONAL_PROVIDERS_EXACT`` — a comprehensive list of exact consumer domains,
#   including regional TLD variants that a short brand heuristic could miss;
# * ``_PERSONAL_PROVIDER_BRANDS`` — a first-label brand heuristic so regional /
#   novel variants (``yahoo.co.uk``, ``hotmail.fr``, ``gmx.de``) are caught without
#   enumerating every ccTLD. Only unambiguous consumer brands are listed, so a
#   corporate subdomain is not mis-flagged.
_PERSONAL_PROVIDERS_EXACT = frozenset(
    {
        # Google
        "gmail.com", "googlemail.com",
        # Yahoo (+ common regional)
        "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.ca", "yahoo.com.au",
        "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it", "yahoo.com.br",
        "ymail.com", "rocketmail.com",
        # Microsoft
        "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.it",
        "outlook.com", "outlook.fr", "outlook.de", "live.com", "live.co.uk",
        "msn.com",
        # Apple
        "icloud.com", "me.com", "mac.com",
        # AOL / Verizon
        "aol.com", "aim.com",
        # Proton
        "proton.me", "protonmail.com", "pm.me",
        # Others
        "zoho.com", "yandex.com", "yandex.ru", "mail.com", "mail.ru", "hey.com",
        "gmx.com", "gmx.net", "gmx.de", "gmx.us", "web.de", "fastmail.com",
        "tutanota.com", "tuta.com", "hushmail.com", "inbox.com", "email.com",
    }
)
# First-label brands that mark a consumer provider regardless of TLD. Kept to
# unambiguous consumer brands only (no generic bases like ``mail`` / ``web`` /
# ``me`` that could appear as a corporate subdomain label).
_PERSONAL_PROVIDER_BRANDS = frozenset(
    {
        "gmail", "googlemail", "yahoo", "ymail", "rocketmail", "hotmail",
        "outlook", "live", "msn", "aol", "aim", "icloud", "proton", "protonmail",
        "gmx", "yandex", "hey", "fastmail", "tutanota", "hushmail",
    }
)

# PII fields that must NEVER appear in a projected lead (asserted by the gate test).
_DROPPED_FIELDS = frozenset(
    {"phone", "city", "state", "country", "website", "industry", "seniority"}
)

# C1 — strict projected-lead schema bounds. Any value that is not a scalar of the
# right shape (a nested dict/list where a scalar is expected, an over-long string,
# an unknown source, a non-strict-True verified flag) is rejected to None so it can
# never carry forbidden PII across the boundary or misrepresent provenance.
_MAX_NAME_LEN = 200
_MAX_TITLE_LEN = 200
_MAX_EMAIL_LEN = 254
# The enum of corpus sources we recognize (provenance only). An unknown/absent or
# non-string source projects to None rather than passing an arbitrary value.
_KNOWN_CORPUS_SOURCES = frozenset(
    {"linkedin", "apollo", "pdl", "github", "crawl", "web", "corpus", "press"}
)
# A LinkedIn public-profile slug: alphanumerics plus - and _ (percent-escapes for
# non-ASCII names), bounded length. Anchored so a path/query can't smuggle content.
_LINKEDIN_SLUG_RE = re.compile(r"^[A-Za-z0-9%][A-Za-z0-9\-_%]{0,99}$")
# Hosts whose ``/in/<slug>`` we trust as a LinkedIn profile origin.
_LINKEDIN_HOSTS = frozenset({"linkedin.com", "www.linkedin.com"})

# A bare-domain shape (label.tld ...), used to route ``type: auto``.
_DOMAIN_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)


def _bounded_str(value: Any, maxlen: int) -> str | None:
    """A stripped string within ``maxlen`` — or None. Rejects every non-string
    (dict/list/number/bool), so a nested object can never cross as a scalar."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > maxlen:
        return None
    return v


def _valid_source(value: Any) -> str | None:
    """A known corpus source string (provenance only), else None."""
    return value if isinstance(value, str) and value in _KNOWN_CORPUS_SOURCES else None


class EnrichRequest(BaseModel):
    query: str = Field(..., min_length=1)
    type: str = "auto"  # domain | company | auto
    limit: int = _DEFAULT_LIMIT
    cursor: str | None = None


def _extract_pro_key(
    request: Request, authorization: str | None, x_pro_key: str | None
) -> str | None:
    """Pull the Pro key from ``Authorization: Bearer`` or ``X-MailAccess-Pro-Key``."""
    if authorization:
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()
    if x_pro_key and x_pro_key.strip():
        return x_pro_key.strip()
    return None


def _looks_like_domain(text: str) -> bool:
    t = (text or "").strip().lower()
    if "@" in t or " " in t:
        return False
    return bool(_DOMAIN_RE.match(t))


def _resolve_type(req_type: str, query: str) -> str:
    t = (req_type or "auto").strip().lower()
    if t == "auto":
        return "domain" if _looks_like_domain(query) else "company"
    return "company" if t == "company" else "domain"


def _clamp_limit(limit: int) -> int:
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return _DEFAULT_LIMIT
    return max(1, min(n, _MAX_LIMIT))


def _linkedin_host(raw: str) -> str | None:
    """The lowercased host of a URL-ish string (scheme optional), else None."""
    s = raw.strip()
    for pre in ("http://", "https://"):
        if s.lower().startswith(pre):
            s = s[len(pre) :]
            break
    host = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0].lower()
    return host or None


def _parse_linkedin(raw: Any) -> tuple[str | None, str | None]:
    """Extract ``/in/{slug}`` → (slug, canonical url), or (None, None).

    C1 — the origin is validated: the URL's host must BE linkedin.com (or
    www.linkedin.com), so an unrelated host carrying ``/in/synthetic`` is rejected.
    The slug must match the bounded slug pattern; anything else → (None, None).
    """
    if not isinstance(raw, str) or "/in/" not in raw:
        return None, None
    host = _linkedin_host(raw)
    if host not in _LINKEDIN_HOSTS:
        return None, None
    slug = raw.split("/in/", 1)[1].strip().strip("/")
    # Stop at the first path/query/fragment boundary after the slug.
    slug = slug.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
    if not slug or not _LINKEDIN_SLUG_RE.match(slug):
        return None, None
    return slug, f"https://linkedin.com/in/{slug}"


def _project_lead(row: dict[str, Any]) -> dict[str, Any]:
    """Engine row → the frozen §2 lead object (hard PII boundary, C1 typed schema).

    Every field is a bounded scalar of a fixed type: ``name``/``title``/``email``
    are length-bounded strings (a nested dict/list is rejected to None), ``source``
    is a known-enum string, ``linkedin_slug``/``linkedin_url`` come only from a
    validated linkedin.com origin, and ``corpus_verified`` is a STRICT boolean
    (``is_verified is True`` — the string ``"false"`` is not truthy here).
    """
    slug, url = _parse_linkedin(row.get("linkedin_url"))
    return {
        "name": _bounded_str(row.get("full_name"), _MAX_NAME_LEN),
        "title": _bounded_str(row.get("title"), _MAX_TITLE_LEN),
        "email": _bounded_str(row.get("email"), _MAX_EMAIL_LEN),
        "linkedin_slug": slug,
        "linkedin_url": url,
        "source": _valid_source(row.get("source")),
        # Provenance only — NEVER a confirmed-verification claim (invariant 2).
        # Strict identity: an upstream ``"false"`` string can never become True.
        "corpus_verified": row.get("is_verified") is True,
    }


def _email_domain(email: Any) -> str | None:
    if not isinstance(email, str) or "@" not in email:
        return None
    return email.rsplit("@", 1)[1].strip().lower() or None


def _is_consumer_domain(domain: Any) -> bool:
    """Whether a bare domain is a personal / consumer provider (B2, centralized).

    Exact-list first, then a first-label brand heuristic so regional variants
    (``yahoo.co.uk``) are caught without enumerating every ccTLD."""
    d = str(domain or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        return False
    if d in _PERSONAL_PROVIDERS_EXACT:
        return True
    return d.split(".", 1)[0] in _PERSONAL_PROVIDER_BRANDS


def _emp_int(v: Any) -> int:
    """Coerce an engine-supplied ``employees`` value to an int for ordering/output.

    The live engine returns this field as a string (``'3'``) or ``None``, so a raw
    ``int()``/comparison anywhere on the path would ``TypeError`` (Fix 1a). Any
    unparseable value → 0."""
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def _rank_orgs(orgs: list[dict[str, Any]], query: str) -> list[tuple[int, dict[str, Any]]]:
    """Item A step 2 — rank org candidates: exact name > prefix > substring, then
    employees desc. Drops non-matching (score 0) junk so 10 unrelated substring
    orgs never surface."""
    q = (query or "").strip().lower()
    scored: list[tuple[int, dict[str, Any]]] = []
    for o in orgs:
        name = str(o.get("company") or "").strip().lower()
        if not name:
            continue
        if name == q:
            score = 3
        elif name.startswith(q):
            score = 2
        elif q and q in name:
            score = 1
        else:
            continue
        scored.append((score, o))
    # ``employees`` is engine-supplied and may be a string/None — coerce so the sort
    # key never mixes types (Fix 1a).
    scored.sort(key=lambda t: (t[0], _emp_int(t[1].get("employees"))), reverse=True)
    return scored


def _org_candidate(org: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": org.get("company"),
        "domain": org.get("domain"),
        "employees": _emp_int(org.get("employees")),
    }


def _validate_engine_block(block: Any) -> None:
    """C3 (defense-in-depth) — reject a malformed engine block at the route boundary
    too, so even a block that bypassed the client's own validation can never crash
    the route into a 500. Raises :class:`ProEngineUnavailable` (→ ``unavailable``).

    ``rows``/``organizations`` must be lists (or absent); ``total`` must be a finite
    number or null. A non-dict block is malformed."""
    if not isinstance(block, dict):
        raise ProEngineUnavailable("malformed engine block")
    rows = block.get("rows")
    if rows is not None and not isinstance(rows, list):
        raise ProEngineUnavailable("engine 'rows' is not a list")
    orgs = block.get("organizations")
    if orgs is not None and not isinstance(orgs, list):
        raise ProEngineUnavailable("engine 'organizations' is not a list")
    total = block.get("total")
    if total is not None and (
        isinstance(total, bool)
        or not isinstance(total, int | float)
        or not math.isfinite(total)
    ):
        raise ProEngineUnavailable("engine 'total' is not a finite number or null")


async def _collect(
    query: str, *, mode: str = "domain", verified_only: bool = False, cap: int
) -> tuple[list[dict[str, Any]], int | None, list[dict[str, Any]]]:
    """Assemble up to ``cap`` DISTINCT-by-email engine rows for a query, paginating
    by offset (all under the caller's single concurrency-1 acquire).

    C4 — the cap counts distinct leads, not rows: duplicate addresses are collapsed
    while filling, so a huge reported ``total`` of repeated rows can never inflate
    the served set or drive an unbounded loop. Termination is bounded three ways:
    the distinct cap, engine exhaustion (``has_more`` false / empty page), a page
    that adds no new distinct address (no-progress guard), and a hard page ceiling.

    Returns ``(rows, total, organizations)`` where ``rows`` are distinct, ``total``
    is the engine's reported match count and ``organizations`` is the first page's
    org block."""
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total: int | None = None
    organizations: list[dict[str, Any]] = []
    offset = 0
    pages = 0
    while len(rows) < cap and pages < _MAX_PAGES:
        block = await pro_client.search(
            query,
            mode=mode,
            limit=min(cap - len(rows), _ENGINE_PAGE),
            offset=offset,
            verified_only=verified_only,
        )
        _validate_engine_block(block)
        pages += 1
        if total is None:
            t = block.get("total")
            total = int(t) if isinstance(t, int | float) else None
            organizations = [
                o for o in block.get("organizations", []) if isinstance(o, dict)
            ]
        batch = [r for r in block.get("rows", []) if isinstance(r, dict)]
        if not batch:
            break
        added = 0
        for r in batch:
            email = r.get("email")
            dedup_key = email.strip().lower() if isinstance(email, str) and email.strip() else None
            if dedup_key is None or dedup_key in seen:
                continue
            seen.add(dedup_key)
            rows.append(r)
            added += 1
            if len(rows) >= cap:
                break
        offset += len(batch)
        if not block.get("has_more"):
            break
        if added == 0:
            break  # a full page produced no new distinct address → stop (no progress)
    return rows[:cap], total, organizations


def _envelope(
    *,
    status: str,
    leads: list[dict[str, Any]] | None = None,
    company: dict[str, Any] | None = None,
    candidates: list[dict[str, Any]] | None = None,
    has_more: bool = False,
    cursor: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    env: dict[str, Any] = {
        "status": status,
        "company": company,
        "leads": leads or [],
        "has_more": has_more,
        "cursor": cursor,
        "provenance": _PROVENANCE,
    }
    if candidates is not None:
        env["candidates"] = candidates
    if reason is not None:
        env["reason"] = reason
    return env


@router.post("/enrich")
async def enrich(
    request: Request,
    body: EnrichRequest,
    authorization: str | None = Header(default=None),
    x_mailaccess_pro_key: str | None = Header(default=None),
) -> dict[str, Any]:
    # 1. Auth — uniform 401 for absent/invalid/inactive (no existence oracle).
    key = _extract_pro_key(request, authorization, x_mailaccess_pro_key)
    if not await validate_pro_key(key):
        raise HTTPException(status_code=401, detail="invalid or missing Pro key")

    # 2. Lawful-basis gate (server-authoritative). Enforced even for a valid key.
    if not settings.mailaccess_pro_lawful_basis_established:
        return _envelope(status="unavailable", reason=_REASON_LAWFUL_BASIS)

    query = body.query.strip()
    limit = _clamp_limit(body.limit)
    query_type = _resolve_type(body.type, query)
    key_hash = hash_key(key or "")

    # 3. Engine call, serialized per key (concurrency-1 FIFO) + globally bounded.
    #    Every failure fails OPEN to an unavailable envelope (invariant 4):
    #    * ProQueueUnavailable — the bounded queue wait was exceeded (a stalled key
    #      can never make a fresh request hang indefinitely);
    #    * asyncio.TimeoutError — the C2 overall serve deadline (company resolution +
    #      all paginated depth + personal fetch) was exceeded;
    #    * ProEngineUnavailable — transport/HTTP/decode/shape failure or a per-call
    #      total deadline / response-size cap in the engine client.
    try:
        async with get_queue().acquire(key_hash):
            return await asyncio.wait_for(
                _serve(query, query_type, limit), timeout=_SERVE_DEADLINE_SECONDS
            )
    except ProQueueUnavailable:
        return _envelope(status="unavailable", reason=_REASON_BUSY)
    except (ProEngineUnavailable, asyncio.TimeoutError):
        return _envelope(status="unavailable", reason=_REASON_ENGINE)
    except Exception:
        # Fix 1a (defense) — the route must NEVER 500 on a malformed engine field or
        # any other unexpected error. A raw ``int()``/comparison on an engine-supplied
        # value (e.g. a string ``employees``) that slipped a coercion still fails open
        # to the unavailable envelope, so the CLI degrades gracefully to Stream 1.
        _LOG.exception("mailaccess_pro /v1/enrich unexpected error; serving unavailable")
        return _envelope(status="unavailable", reason=_REASON_ENGINE)


async def _resolve_company(query: str) -> dict[str, Any]:
    """Item A — resolve a company name → domain via ranked ACTUAL org records only.

    A company-name query resolves solely by ranking the engine's ``organizations``
    list (exact > prefix > substring, employees only ORDER within a tier). No domain
    is ever fabricated from the query token: a single exact-name org resolves; a
    prefix/substring/multiple top-tier match is ``disambiguation``; no match is
    ``empty``. Returns ``{status, domain?, company?, candidates?}``.
    """
    resolved = await pro_client.search(
        query, mode="company", limit=_DEPTH_CAP, offset=0, verified_only=False
    )
    _validate_engine_block(resolved)
    orgs = [
        o
        for o in resolved.get("organizations", [])
        if isinstance(o, dict) and o.get("domain")
    ]
    ranked = _rank_orgs(orgs, query)
    if not ranked:
        return {"status": "empty"}
    top_score = ranked[0][0]
    top_tier = [o for (s, o) in ranked if s == top_score]
    # B3 (re-audit) — auto-resolve ONLY a single EXACT-name org (score 3). A prefix
    # or substring match to an unrelated org ("Acme" → "Acme Scam") is not identity,
    # and ≥2 orgs sharing the top score are genuinely ambiguous (employee count is
    # not identity) → disambiguation in both cases. Never serve one org's leads
    # under another requested name.
    if len(top_tier) == 1 and top_score >= 3:
        chosen = top_tier[0]
        return {
            "status": "ok",
            "domain": str(chosen.get("domain")),
            "company": _org_candidate(chosen),
        }
    return {
        "status": "disambiguation",
        "candidates": [_org_candidate(o) for o in top_tier[:10]],
    }


async def _serve(query: str, query_type: str, limit: int) -> dict[str, Any]:
    company: dict[str, Any] | None = None

    if query_type == "company":
        resolved = await _resolve_company(query)
        status = resolved["status"]
        if status == "disambiguation":
            # D1 (re-audit) — the disambiguation path must consult suppression too,
            # or a suppressed company's names/domains leak in the candidate list.
            return await _suppress_disambiguation(query, resolved.get("candidates") or [])
        if status != "ok":
            return _envelope(status=status)
        domain = resolved["domain"]
        company = resolved["company"]
    else:
        domain = query

    return await _serve_domain(domain, company, limit)


async def _suppress_disambiguation(
    query: str, candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    """D1 (re-audit) — filter the disambiguation candidate list through suppression
    so a suppressed company never appears even as a candidate name/domain. Fails
    CLOSED (unavailable) if the store can't be read; empty if nothing survives."""
    try:
        index = await suppression.load_index()
    except SuppressionUnavailable:
        return _envelope(status="unavailable", reason=_REASON_SUPPRESSION)
    if suppression.subject_suppressed(index, company=query):
        return _envelope(status="empty")
    kept = [
        c
        for c in candidates
        if not suppression.subject_suppressed(index, domain=_norm_domain(c.get("domain")))
        and not (
            str(c.get("name") or "").strip()
            and suppression.subject_suppressed(index, company=str(c.get("name")))
        )
    ]
    if not kept:
        return _envelope(status="empty")
    return _envelope(status="disambiguation", candidates=kept)


def _norm_domain(value: Any) -> str:
    d = str(value or "").strip().lower()
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]
    if d.startswith("www."):
        d = d[4:]
    return d.split("/", 1)[0].rstrip(".")


def _org_name_for_domain(orgs: list[dict[str, Any]], domain: str) -> str | None:
    """The organization NAME whose ``domain`` matches ``domain`` (from the domain
    query's org block). None when the roster carries no matching org name — we
    then skip the personal group rather than guess a company name."""
    target = _norm_domain(domain)
    for o in orgs:
        if _norm_domain(o.get("domain")) == target:
            name = str(o.get("company") or "").strip()
            if name:
                return name
    return None


async def _serve_domain(
    domain: str, company: dict[str, Any] | None, limit: int
) -> dict[str, Any]:
    """Item B (500-cap depth) for a domain."""
    # B2 — a consumer / personal-provider domain is NOT a company. A query for
    # gmail.com / yahoo.co.uk / … can never yield "business" leads; return empty
    # rather than serving on-provider addresses as if they were company contacts.
    target = _norm_domain(domain)
    if _is_consumer_domain(target):
        return _envelope(status="empty", company=company)

    # One unfiltered pass: learn `total`, the org block (for company-scope
    # suppression), and hold rows for the ≤500 case and the over-cap unverified fill.
    all_rows, total, orgs = await _collect(domain, verified_only=False, cap=_DEPTH_CAP)

    if total is not None and total > _DEPTH_CAP:
        # Over cap → top 500 verified, then (default) fill to 500 with unverified.
        rows, _vtotal, _ = await _collect(domain, verified_only=True, cap=_DEPTH_CAP)
        rows = list(rows)
        if _PRO_OVER_CAP_FILL_UNVERIFIED and len(rows) < _DEPTH_CAP:
            seen = {r.get("email") for r in rows}
            for r in all_rows:
                if len(rows) >= _DEPTH_CAP:
                    break
                if not r.get("is_verified") and r.get("email") not in seen:
                    rows.append(r)
                    seen.add(r.get("email"))
    else:
        rows = all_rows

    # B2 — a lead is "business" ONLY by POSITIVE on-domain validation: its email
    # domain must equal the queried domain. "Absent from a consumer denylist" is
    # not sufficient — an off-domain (or personal-provider) address can never wear
    # the business affordance, regardless of what upstream claims about it.
    business = [r for r in rows if _email_domain(r.get("email")) == target]
    leads = [_project_lead(r) for r in business][:limit]

    company_name = _org_name_for_domain(orgs, domain) or (company or {}).get("name")

    # D1 — consult the suppression index before serving. Every candidate is filtered;
    # a whole-domain / whole-company objection serves nothing; a store that can't be
    # read fails CLOSED (unavailable) rather than emit a lead that might belong to an
    # objecting subject.
    try:
        index = await suppression.load_index()
    except SuppressionUnavailable:
        return _envelope(status="unavailable", reason=_REASON_SUPPRESSION)
    if suppression.subject_suppressed(index, domain=target) or (
        company_name and suppression.subject_suppressed(index, company=company_name)
    ):
        return _envelope(status="empty", company=company)
    leads = suppression.filter_rows(leads, index)

    if not leads:
        return _envelope(status="empty", company=company)
    return _envelope(status="ok", leads=leads, company=company)


# ── Coverage count (free-tier upsell teaser) ──────────────────────────────────
# A keyless, count-only view of the corpus: "how many business contacts would Pro
# add for this domain". It returns ONLY an integer — never rows, never PII — so it
# is safe to expose without a Pro key. It honors the SAME gates as /v1/enrich
# (lawful-basis, consumer-domain rejection, suppression fail-closed) so the teaser
# can never advertise a subject who has objected, and the number equals what a Pro
# harvest would actually serve (on-domain, deduped, suppressed, capped) — never the
# engine's raw match total, which would over-promise.
_COVERAGE_TTL_SECONDS = 24 * 3600
# Per-domain in-process cache (a count is stable day-to-day). Bounds engine load
# from a keyless endpoint; the lock serializes cache-miss engine hits so a burst of
# distinct domains cannot fan out concurrently. Put a per-IP rate limit at the edge
# proxy as the primary abuse control.
_COVERAGE_CACHE: dict[str, tuple[float, int]] = {}
_COVERAGE_LOCK = asyncio.Lock()


async def _servable_domain_count(domain: str) -> int:
    """Distinct on-domain, non-suppressed corpus contacts for ``domain`` — the count
    a Pro harvest would actually append. Mirrors ``_serve_domain``'s servable set
    (minus the projection; we only need the length). Capped at ``_DEPTH_CAP``.

    Raises :class:`SuppressionUnavailable` so the route can fail CLOSED.
    """
    target = _norm_domain(domain)
    if _is_consumer_domain(target):
        return 0
    rows, _total, orgs = await _collect(domain, verified_only=False, cap=_DEPTH_CAP)
    business = [r for r in rows if _email_domain(r.get("email")) == target]
    index = await suppression.load_index()
    company_name = _org_name_for_domain(orgs, domain)
    if suppression.subject_suppressed(index, domain=target) or (
        company_name and suppression.subject_suppressed(index, company=company_name)
    ):
        return 0
    leads = suppression.filter_rows([_project_lead(r) for r in business], index)
    return len(leads)


@router.get("/coverage")
async def coverage(domain: str) -> dict[str, Any]:
    """Unauthenticated corpus-coverage COUNT for ``domain`` (free-tier upsell).

    Returns ``{available, domain, count}`` — an integer only, never rows/PII.
    ``available`` is False (with a ``reason``) when the tier is dark, the domain is
    invalid/consumer, the engine is unreachable, or suppression can't be read
    (fail-closed). Cached per domain (24h) and serialized against the engine.
    """
    d = _norm_domain(domain)
    if not d or not _looks_like_domain(d):
        return {"available": False, "reason": "invalid_domain"}
    # Same server-authoritative gate as /v1/enrich — the teaser stays dark until the
    # lawful basis is established.
    if not settings.mailaccess_pro_lawful_basis_established:
        return {"available": False, "reason": _REASON_LAWFUL_BASIS}

    now = time.monotonic()
    cached = _COVERAGE_CACHE.get(d)
    if cached is not None and now - cached[0] < _COVERAGE_TTL_SECONDS:
        return {"available": True, "domain": d, "count": cached[1]}

    try:
        async with _COVERAGE_LOCK:
            # Re-check under the lock — a concurrent miss may have filled it.
            cached = _COVERAGE_CACHE.get(d)
            if cached is not None and time.monotonic() - cached[0] < _COVERAGE_TTL_SECONDS:
                return {"available": True, "domain": d, "count": cached[1]}
            count = await asyncio.wait_for(
                _servable_domain_count(d), timeout=_SERVE_DEADLINE_SECONDS
            )
    except SuppressionUnavailable:
        # Fail CLOSED — never advertise a count we cannot prove is suppression-clean.
        return {"available": False, "reason": _REASON_SUPPRESSION}
    except (ProEngineUnavailable, ProQueueUnavailable, asyncio.TimeoutError):
        return {"available": False, "reason": _REASON_ENGINE}
    except Exception:
        _LOG.exception("mailaccess_pro /v1/coverage unexpected error; serving unavailable")
        return {"available": False, "reason": _REASON_ENGINE}

    _COVERAGE_CACHE[d] = (time.monotonic(), count)
    return {"available": True, "domain": d, "count": count}
