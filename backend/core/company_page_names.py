"""Direct-fetch company page name extractor.

Tries a small list of common about/team/leadership URLs on the
target's own domain, downloads each (5s timeout, follow redirects
max 2), strips HTML, and matches capitalised token sequences
against ``name_quality.PERSON_RE``.

The existing :mod:`backend.core.name_extractor` is structured for
incoming module findings, not raw text, so we replicate the field
strip + Unicode-aware pattern match locally.  Patterns are
intentionally conservative — this is a quick pre-filter pass; the
:mod:`backend.core.name_consensus` engine applies the heavy
clustering later.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from html import unescape
from typing import Any

import httpx

from .cf_decode import cf_decode as _cf_decode_real
from .http_client import build_client
from .hydration_extractor import HydrationDataExtractor
from .name_quality import is_plausible_person_name
from .site_discovery import PageCandidate
from .site_discovery import discover_team_pages as _discover_team_pages
from .stealth_client import StealthSession
from .structured_data_extractor import PersonRecord
from .structured_data_extractor import extract_people as _extract_people

_LOG = logging.getLogger(__name__)

# Confidence baseline — self-disclosed on a controlled corporate page
# is more reliable than a random match anywhere else, but unverified
# against a structured registry.
_COMPANY_PAGE_CONFIDENCE = 0.6

# Phase 4: role-context multipliers.
_COMPANY_PAGE_NO_ROLE_PENALTY = 0.7   # name found without nearby role → 0.7×
_COMPANY_PAGE_JSON_LD_BONUS = 1.2     # name from JSON-LD Person schema → 1.2×

# Common about/team/leadership URL paths. Ordered roughly by
# likelihood per research.
_PAGE_PATHS: tuple[str, ...] = (
    "/about",
    "/about-us",
    "/about_us",
    "/team",
    "/our-team",
    "/our_team",
    "/people",
    "/leadership",
    "/staff",
    "/who-we-are",
    "/company/team",
    "/company/about",
    "/company/leadership",
)

_FETCH_TIMEOUT = 5.0
_MAX_REDIRECTS = 2

# Strip HTML tags.  Tolerant of unclosed tags, scripts, comments.
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(
    r"<(?:script|style|noscript|svg|iframe)[^>]*>.*?</(?:script|style|noscript|svg|iframe)>",
    flags=re.IGNORECASE | re.DOTALL,
)

# Phase 4: JSON-LD script tag extractor.
_JSON_LD_RE = re.compile(
    r'<script[^>]*\btype\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script\s*>',
    flags=re.IGNORECASE | re.DOTALL,
)

# Page furniture extraction — title and meta description frequently
# mirror nav / heading copy verbatim, so any candidate name that
# appears as an exact substring of either is page furniture, not a
# person.  The QA pass on ine.com / lavellenetworks.com surfaced
# this as the primary source of garbage "name" extractions.
_TITLE_RE = re.compile(
    r"<title[^>]*>(.*?)</title>",
    flags=re.IGNORECASE | re.DOTALL,
)
_META_DESC_RE = re.compile(
    r'<meta\s+[^>]*name\s*=\s*["\']description["\'][^>]*content\s*=\s*["\']([^"\']*)["\']',
    flags=re.IGNORECASE | re.DOTALL,
)
# Some sites use the property attribute instead of name.
_META_DESC_PROP_RE = re.compile(
    r'<meta\s+[^>]*property\s*=\s*["\']og:description["\'][^>]*content\s*=\s*["\']([^"\']*)["\']',
    flags=re.IGNORECASE | re.DOTALL,
)
_HEADING_RE = re.compile(
    r"<h[23][^>]*>(.*?)</h[23]>",
    flags=re.IGNORECASE | re.DOTALL,
)

# Borrowed from name_consensus.PERSON_RE composition (Latin + non-Latin).
_LATIN_TOKEN = r"[A-Z][a-zA-Z''\-]+"
_NONLATIN_TOKEN = r"[Ѐ-ӿ؀-ۿ一-鿿ऀ-ॿ]+"
_ANY_TOKEN = rf"(?:{_LATIN_TOKEN}|{_NONLATIN_TOKEN})"
# Use a less-strict in-line pattern so multi-name sentences parse,
# not just single-line "First Last".
_IN_LINE_NAME_RE = re.compile(
    rf"\b{_ANY_TOKEN}(?:\s+{_ANY_TOKEN}){{1,3}}",
    re.UNICODE,
)

# Stricter inline pattern — two- to four-token names with each
# token at least 3 characters long and starting with an uppercase
# letter then at least one lowercase.  Filters out all-caps
# navigation labels like "Home About Team" while still accepting
# "John Smith", "Mary Jane Watson", and "Jean-Luc Picard".
_WESTERN_TOKEN = r"[A-Z][a-z][A-Za-z'\-]{1,30}"  # at least 3 chars
_WESTERN_LINE_NAME_RE = re.compile(
    rf"\b{_WESTERN_TOKEN}(?:\s+{_WESTERN_TOKEN}){{1,3}}?\b"
)

# "Name, Title" pairing — many company pages use "John Smith, CEO".
# Non-greedy repetition count so we find "John Smith, CEO" rather than
# "Our Team John Smith, CEO Executive Officer" (a longer-token match
# that swallows "Our Team" into the name).
_TITLE_AFTER_NAME_RE = re.compile(
    rf"\b({_WESTERN_TOKEN}(?:\s+{_WESTERN_TOKEN}){{1,3}}?)\s*"
    r"[,\-]\s*"
    r"([A-Z][A-Za-z &\-/\.]{2,40})"
)


# Phase 4: source type distinguishes role-context levels for confidence.
# "with_role"   — name found alongside a title ("John Smith, CTO")
# "no_role"     — name found standalone in body text
# "json_ld"     — name extracted from JSON-LD Person schema (highest quality)
SourceType = str  # literal: "with_role" | "no_role" | "json_ld"


@dataclass
class CompanyPageName:
    name: str
    source_url: str
    title_or_role: str | None
    confidence: float
    source_type: SourceType = "no_role"          # Phase 4 field; default = no_role
    email: str | None = None                     # Phase 4: from JSON-LD Person.email


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------
def _html_to_text(html: str) -> str:
    if not html:
        return ""
    no_scripts = _SCRIPT_RE.sub(" ", html)
    # Decode entities BEFORE stripping tags so "&eacute;" becomes "é"
    # before the surrounding markup is washed away.
    text = unescape(no_scripts)
    text = _TAG_RE.sub(" ", text)
    # Strip any entity references that survived (malformed/invalid).
    text = re.sub(r"&[#a-zA-Z0-9]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_page_metadata(html: str) -> tuple[str | None, str | None]:
    """Return ``(title, meta_description)`` extracted from raw HTML.

    Page furniture (titles, meta descriptions) frequently mirror nav /
    heading copy verbatim — e.g. an H1 reading "Azure DevOps" almost
    always shows up in the page title or meta description too.  The
    candidate-name extractor uses this signal as a "skip if this name
    appears verbatim in title/meta" check.

    Returns ``(None, None)`` if neither element is present.
    """
    if not html:
        return None, None
    title_match = _TITLE_RE.search(html)
    title = _html_to_text(title_match.group(1)) if title_match else None
    meta_match = _META_DESC_RE.search(html) or _META_DESC_PROP_RE.search(html)
    meta_desc = _html_to_text(meta_match.group(1)) if meta_match else None
    return title, meta_desc


def _extract_page_headings(html: str) -> tuple[str, ...]:
    headings: list[str] = []
    for match in _HEADING_RE.finditer(html or ""):
        heading = _html_to_text(match.group(1))
        if heading:
            headings.append(heading)
    return tuple(headings)


def _candidate_in_page_furniture(name: str, page_furniture: tuple[str | None, ...]) -> bool:
    """Return True when *name* appears verbatim in the page title or meta description.

    QA-found case: H1 / H2 / nav text like "Azure DevOps" appears in
    ``<title>`` and ``<meta name="description">`` essentially verbatim.
    A candidate matching one of those fields is page furniture, not a
    person.  We compare case-insensitively on the exact normalised
    string (whitespace collapsed).
    """
    if not name:
        return False
    needle = re.sub(r"\s+", " ", name.strip()).lower()
    if not needle:
        return False
    for field in page_furniture:
        if not field:
            continue
        haystack = re.sub(r"\s+", " ", field.strip()).lower()
        if not haystack:
            continue
        # Exact substring match — "Azure DevOps" is contained in
        # "Azure DevOps Certification - INE" but "Azure Devops" (typo)
        # would NOT be, which is the desired conservative behaviour.
        if needle in haystack:
            return True
    return False


def _matches_company_name(name: str, domain: str | None) -> bool:
    if not name or not domain:
        return False
    registrable = domain.strip().lower().rsplit(".", 1)[0]
    cleaned_name = re.sub(r"[^a-z0-9]+", "", name.lower())
    cleaned_domain = re.sub(r"[^a-z0-9]+", "", registrable)
    if not cleaned_name or not cleaned_domain:
        return False
    if cleaned_name == cleaned_domain:
        return True
    tokens = [part for part in re.split(r"\s+", name.lower()) if part]
    if len(tokens) >= 2:
        sorted_joined = "".join(sorted(re.sub(r"[^a-z0-9]+", "", token) for token in tokens))
        if sorted_joined == cleaned_domain:
            return True
    return False


# ----------------------------------------------------------------------
# Phase 4: JSON-LD Person schema extractor
# ----------------------------------------------------------------------
def _extract_json_ld_persons(html: str) -> list[dict[str, Any]]:
    """Extract Person entities from JSON-LD <script> blocks in *html*.

    Handles the common ``@graph`` wrapper format used by many CMSes /
    schema-org generators, as well as top-level ``@type: Person`` nodes.
    Returns a list of dicts with keys: ``name``, ``jobTitle`` (optional),
    ``email`` (optional).
    """
    found: list[dict[str, Any]] = []
    for m in _JSON_LD_RE.finditer(html):
        raw = m.group(1)
        try:
            data = json.loads(raw)
        except Exception:  # noqa: BLE001 — malformed JSON-LD is not fatal
            continue
        found.extend(_walk_json_ld(data))
    return found


def _walk_json_ld(node: Any) -> list[dict[str, Any]]:
    """Recursively walk a JSON-LD tree, collecting Person entities."""
    results: list[dict[str, Any]] = []
    if isinstance(node, dict):
        # Check if this node is a Person.
        typ = node.get("type") or node.get("@type", "")
        # @type can be a string or a list.
        types: list[str] = [typ] if isinstance(typ, str) else typ
        if any(t in ("Person", "person", "https://schema.org/Person") for t in types):
            name = node.get("name") or ""
            if isinstance(name, str) and name.strip():
                results.append(
                    {
                        "name": name.strip(),
                        "jobTitle": node.get("jobTitle") or node.get("jobTitle"),
                        "email": node.get("email") or None,
                    }
                )
        # Recurse into children.
        for val in node.values():
            results.extend(_walk_json_ld(val))
    elif isinstance(node, list):
        for item in node:
            results.extend(_walk_json_ld(item))
    return results


# ----------------------------------------------------------------------
# Phase 4: role-context aware name extractor
# ----------------------------------------------------------------------
def _extract_names_from_text(
    text: str,
    domain: str | None = None,
    *,
    page_furniture: tuple[str | None, ...] = (None, None),
) -> list[tuple[str, str | None, SourceType]]:
    """Return ``[(name, role_or_None, source_type)]`` tuples extracted from page text.

    Uses two complementary passes:
    1. Strict "Name, Title" pattern (very high precision) → ``source_type="with_role"``.
    2. Loose "Capitalised token sequence" pattern → ``source_type="no_role"``.

    Pass ``domain`` to drop candidates that match the target company
    name itself ("Acme Welcome" → reject because "acme" == the
    registrable part of the target domain).

    Pass ``page_furniture=(title, meta_description)`` to drop candidates
    that appear verbatim in the page title or meta description
    (FIX 1 item #5: nav / H1 / H2 text often mirrors title/meta).
    """
    from .name_quality import matches_domain as _matches_domain

    # Phase 4: source_type distinguishes role context.
    found: list[tuple[str, str | None, SourceType]] = []
    seen: set[str] = set()

    def _matches_company_token(name: str) -> bool:
        """Token-level check: any individual token in *name* matches the
        target company's registrable name (e.g. "Acme Welcome" while
        target is acme.com → reject).
        """
        if not domain:
            return False
        from .name_quality import matches_domain as _md
        for token in name.split():
            if _md(token, domain):
                return True
        return False

    def _keep(name: str, role: str | None, source_type: SourceType) -> None:
        cleaned_name = name.strip()
        if not is_plausible_person_name(cleaned_name):
            return
        if _matches_company_token(cleaned_name):
            return
        if _matches_company_name(cleaned_name, domain):
            return
        if domain and _matches_domain(cleaned_name, domain):
            return
        if _candidate_in_page_furniture(cleaned_name, page_furniture):
            return
        key = cleaned_name.lower()
        if key in seen:
            return
        seen.add(key)
        found.append((cleaned_name, role, source_type))

    # Pass 1: "Name, Title" or "Name - Title" patterns → with_role.
    for match in _TITLE_AFTER_NAME_RE.finditer(text):
        name = match.group(1).strip()
        role = match.group(2).strip()
        if not is_plausible_person_name(name):
            continue
        # Cap the role at the next capitalised name so we don't
        # slurp whole sentences.
        role = role.split("\n")[0].strip()
        cut = re.search(r"\b[A-Z][a-z]+\b", role[10:])
        if cut:
            role = role[: cut.start() + 10].strip(" ,;-")
        if role and role.lower().startswith(("and", "or", "the ")):
            continue
        _keep(name, role, "with_role")

    # Pass 2: standalone capitalised sequences → no_role.
    #
    # We scan the text manually because ``re.finditer`` is position-
    # greedy and may consume a position-based match that would
    # otherwise expose a 2-token person name later in the same
    # window.  Splitting into tokens upfront and trying every
    # window of length 2-4 starting at every token boundary gives
    # complete coverage.
    _TOKEN_RE = re.compile(r"[A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ'\-]*")
    tokens = _TOKEN_RE.findall(text)
    for i in range(len(tokens)):
        for window_size in (2, 3, 4):
            window = tokens[i : i + window_size]
            if len(window) != window_size:
                continue
            candidate = " ".join(window)
            if not _WESTERN_LINE_NAME_RE.fullmatch(candidate):
                continue
            if not is_plausible_person_name(candidate):
                continue
            if _matches_company_token(candidate):
                continue
            if _matches_company_name(candidate, domain):
                continue
            if domain and _matches_domain(candidate, domain):
                continue
            if _candidate_in_page_furniture(candidate, page_furniture):
                continue
            key = candidate.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append((candidate, None, "no_role"))

    return found


async def _fetch_page(
    client: httpx.AsyncClient | StealthSession,
    url: str,
) -> str | None:
    """Fetch a single page; return decoded text or ``None`` on any failure.

    Accepts either an :class:`httpx.AsyncClient` (legacy) or a
    :class:`StealthSession` (0.11.1 Phase 1).  The dispatch is
    transparent to callers because both expose ``async get(url)``.
    """
    try:
        if isinstance(client, StealthSession):
            # StealthSession builds Chrome headers + Sec-Fetch-* on
            # its own; we don't pass an explicit UA override.
            response = await client.get(url)
        else:
            response = await client.get(
                url,
                timeout=_FETCH_TIMEOUT,
                follow_redirects=True,
            )
    except httpx.TimeoutException:
        return None
    except Exception as exc:  # noqa: BLE001 — defensive
        _LOG.debug("company_page_names: fetch %s: %s", url, exc)
        return None

    if response.status_code != 200:
        return None
    try:
        return response.text
    except Exception:
        return None


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
async def discover_company_page_names(
    domain: str,
    transport: httpx.AsyncClient | None = None,
    max_pages: int = 5,
    *,
    stealth: StealthSession | None = None,
) -> list[CompanyPageName]:
    """Try the candidate about/team pages on *domain* and extract names.

    Stops after *max_pages* successful page fetches (defaults to 5)
    so we don't burn bandwidth hunting for paths the company doesn't
    expose.  Returns an empty list when nothing of value is found.

    Parameters
    ----------
    transport:
        Optional ``httpx.AsyncClient`` to share across pages.  When
        ``None`` the function builds a one-shot client.  Ignored when
        ``stealth`` is provided.
    stealth:
        Optional :class:`StealthSession` (0.11.1 Phase 1).  When
        supplied, takes precedence over ``transport`` and the
        function never builds its own client.  The StealthSession is
        owned by the caller and is NOT closed when the function
        returns.
    """
    cleaned = (domain or "").strip().lower()
    if not cleaned or "." not in cleaned:
        return []

    effective_cap = max(1, int(max_pages))
    limit = min(effective_cap, len(_PAGE_PATHS))

    names: list[CompanyPageName] = []
    seen_names: dict[str, CompanyPageName] = {}

    async def _run() -> None:
        # 0.11.1 Phase 1: StealthSession takes precedence when
        # supplied; otherwise fall back to the legacy httpx path.
        # ``owns_client`` is True only when we built the httpx client
        # ourselves (so we still own closing it).  A borrowed
        # ``transport`` or a caller-owned ``stealth`` outlives us.
        if stealth is not None:
            client: httpx.AsyncClient | StealthSession = stealth
            owns_client = False
        elif transport is not None:
            client = transport
            owns_client = False
        else:
            client = build_client(timeout=_FETCH_TIMEOUT)
            owns_client = True
        try:
            for offset in range(limit):
                if len(names) >= effective_cap * 8:  # rough upper bound
                    break
                path = _PAGE_PATHS[offset]
                url = f"https://{cleaned}{path}"
                html = await _fetch_page(client, url)
                if not html:
                    continue
                text = _html_to_text(html)
                if not text:
                    continue
                # FIX 1: extract page furniture (title, meta description)
                # so we can drop candidates that appear verbatim there.
                # Nav / H1 / H2 text from training / vendor / enterprise
                # sites is the primary source of garbage name candidates
                # (Azure DevOps, Cert Prep Want, etc.).
                page_furniture = _extract_page_metadata(html) + _extract_page_headings(html)
                page_names = _extract_names_from_text(
                    text, domain=cleaned, page_furniture=page_furniture
                )
                for name, role, source_type in page_names:
                    if not is_plausible_person_name(name):
                        continue
                    key = name.lower()
                    if key in seen_names:
                        continue
                    # Phase 4: apply role-context multipliers.
                    multiplier = (
                        1.0
                        if source_type == "with_role"
                        else _COMPANY_PAGE_NO_ROLE_PENALTY
                    )
                    entry = CompanyPageName(
                        name=name,
                        source_url=url,
                        title_or_role=role,
                        confidence=round(_COMPANY_PAGE_CONFIDENCE * multiplier, 4),
                        source_type=source_type,
                    )
                    seen_names[key] = entry
                    names.append(entry)

                # Phase 4: emit JSON-LD Person entities as separate high-confidence records.
                for person in _extract_json_ld_persons(html):
                    pname = person.get("name", "")
                    if not is_plausible_person_name(pname):
                        continue
                    pkey = pname.lower()
                    if pkey in seen_names:
                        continue
                    entry = CompanyPageName(
                        name=pname,
                        source_url=url,
                        title_or_role=person.get("jobTitle"),
                        confidence=round(
                            _COMPANY_PAGE_CONFIDENCE * _COMPANY_PAGE_JSON_LD_BONUS, 4
                        ),
                        source_type="json_ld",
                        email=person.get("email"),
                    )
                    seen_names[pkey] = entry
                    names.append(entry)
        finally:
            if owns_client and not isinstance(client, StealthSession):
                await client.aclose()

    await _run()
    return names


def discover_for_tests(
    page_html_by_url: dict[str, str],
    domain: str | None = None,
    *,
    metadata_by_url: dict[str, tuple[str | None, str | None]] | None = None,
) -> list[CompanyPageName]:
    """Test-only helper to derive CompanyPageName records from raw HTML.

    Pass ``domain`` to enable the company-name self-match filter.
    Pass ``metadata_by_url`` (URL → (title, meta_description) tuples)
    to enable the FIX-1 page-furniture verbatim filter — this is
    how the ``test_*_title_verbatim_*`` tests opt in.
    """
    out: list[CompanyPageName] = []
    seen: set[str] = set()
    for url, raw_html in page_html_by_url.items():
        furniture = (
            metadata_by_url.get(url, (None, None))
            if metadata_by_url
            else (None, None)
        )
        # Convert to plain text for the token-based name extractor.
        text = _html_to_text(raw_html)
        headings = _extract_page_headings(raw_html)
        for name, role, source_type in _extract_names_from_text(
            text, domain=domain, page_furniture=furniture + headings
        ):
            if not is_plausible_person_name(name):
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            # Phase 4: apply role-context multipliers.
            multiplier = (
                1.0 if source_type == "with_role" else _COMPANY_PAGE_NO_ROLE_PENALTY
            )
            out.append(
                CompanyPageName(
                    name=name,
                    source_url=url,
                    title_or_role=role,
                    confidence=round(_COMPANY_PAGE_CONFIDENCE * multiplier, 4),
                    source_type=source_type,
                )
            )
        # Phase 4: emit JSON-LD Person entities from the raw HTML.
        for person in _extract_json_ld_persons(raw_html):
            pname = person.get("name", "")
            if not is_plausible_person_name(pname):
                continue
            pkey = pname.lower()
            if pkey in seen:
                continue
            seen.add(pkey)
            out.append(
                CompanyPageName(
                    name=pname,
                    source_url=url,
                    title_or_role=person.get("jobTitle"),
                    confidence=round(
                        _COMPANY_PAGE_CONFIDENCE * _COMPANY_PAGE_JSON_LD_BONUS, 4
                    ),
                    source_type="json_ld",
                    email=person.get("email"),
                )
            )
    return out


# ======================================================================
# 0.11.1 Phase 2 — Site Intelligence Rebuild
# ======================================================================
# The legacy code above is *preserved* on purpose:
#   * ``discover_company_page_names`` is still used by ``test_company_page_names.py``
#     and the legacy pre-Phase-2 orchestration path.  Keeping it as-is
#     means existing tests stay green and callers that haven't migrated
#     to :func:`discover_and_extract` keep working unchanged.
#   * ``discover_for_tests`` is a synchronous HTML→CompanyPageName
#     helper used by the existing test suite.  It exercises the body-
#     text extraction path (the same path that ``--aggressive`` mode
#     uses internally to ``extractor``).
#
# The new pipeline lives below and is the one Phase 2 wants callers
# to use going forward.  It discovers team pages dynamically and
# extracts Person records from structured-data sources (JSON-LD,
# microdata, RDFa, hCard, mailto:, DOM team-card pattern).  Body-text
# extraction is gated behind ``aggressive=True`` per spec.
# ----------------------------------------------------------------------
async def _cf_decode(html: str) -> str:
    """Wrap the real :func:`backend.core.cf_decode.cf_decode` for call-site stability.

    0.11.1 Phase 3 — replaces the Phase-2 no-op stub with the real
    Cloudflare email decoder.  Kept ``async`` so the
    ``discover_and_extract`` call site (``await _cf_decode(html)``)
    keeps compiling without further edits.
    """
    return _cf_decode_real(html)


async def _candidate_fetcher(
    session: Any,
    url: str,
    *,
    timeout: float,
) -> str | None:
    """Fetch one URL through *session*; return decoded text or ``None``.

    Accepts any object with ``async get(url) -> response`` — used for
    both :class:`StealthSession` (the canonical caller) and bare
    ``httpx.AsyncClient`` instances in the legacy path.
    """
    try:
        response = await session.get(url, timeout=timeout)
    except TypeError:
        # Some sessions (notably ``StealthSession``) don't accept a
        # ``timeout`` kwarg — fall back to a positional call.
        try:
            response = await session.get(url)
        except Exception:  # noqa: BLE001
            return None
    except Exception:  # noqa: BLE001
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status != 200:
        return None
    try:
        return str(response.text or "")
    except Exception:  # noqa: BLE001
        return None


def _normalise_text(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").strip())


def _dedupe_person_records(
    records: Iterable[PersonRecord],
) -> list[PersonRecord]:
    """Deduplicate PersonRecord by (lower(name), lower(email)).

    When two records share a name or email, keep the one with the
    higher confidence and fall back on name over email when the
    confidences tie.  The loser's email is preserved when the
    winner has none.

    Separate from :func:`structured_data_extractor._dedupe_records`
    because this version is per-page — we extend its logic with a
    cross-page pass too (different pages might surface the same
    identity with subtly different spellings).
    """
    merged: list[PersonRecord] = []

    def _key(r: PersonRecord) -> tuple[str, str]:
        return (
            (r.name or "").strip().lower(),
            (r.email or "").strip().lower(),
        )

    for new in records:
        if not (new.name or "").strip():
            continue
        nname, nemail = _key(new)
        new_tokens = (
            set(nname.split()) if nname else set()
        )
        target_idx = -1
        for idx, existing in enumerate(merged):
            ename, eemail = _key(existing)
            if nname and nname == ename:
                target_idx = idx
                break
            if nemail and nemail == eemail:
                target_idx = idx
                break
            # Subset-token collision: LinkedIn slugs frequently
            # append a company / differentiator token to the
            # canonical name (``/in/tracy-wallace-tec`` →
            # ``Tracy Wallace Tec``). Strict name equality misses
            # that — collapse when one record's name-tokens are
            # a proper subset of the other AND both names are
            # at least 2 tokens long (a 1-token "subset" match
            # is too ambiguous, e.g. "Sam" subset-of "Sam Smith").
            if (
                new_tokens
                and len(new_tokens) >= 2
                and not (ename and eemail)
            ):
                existing_tokens = (
                    set(ename.split()) if ename else set()
                )
                if (
                    existing_tokens
                    and len(existing_tokens) >= 2
                    and (
                        new_tokens < existing_tokens
                        or existing_tokens < new_tokens
                    )
                ):
                    target_idx = idx
                    break
        if target_idx == -1:
            merged.append(new)
            continue
        target = merged[target_idx]
        if new.confidence > target.confidence:
            winner, loser = new, target
            merged[target_idx] = winner
        elif new.confidence == target.confidence:
            # Tie-break. Real-world cases that hit this branch:
            #   * DOM team-card h3 ("Tracy Wallace", title attached,
            #     confidence 0.65) vs LinkedIn-slug
            #     ("Tracy Wallace Tec", no title, confidence 0.65)
            #     where the slug contains a trailing company /
            #     differentiator token. The longer slug artifact
            #     drops the title and the "real" record. Prefer
            #     the record with a title attached — DOM cards,
            #     JSON-LD and hCard always carry one, slug
            #     artifacts never do.
            #   * Two microdata/hCard extractions of the same
            #     person, same confidence. The "longer name wins"
            #     heuristic (used previously) actively harms the
            #     slug case, so fall back to the name that's
            #     not a strict superset of the other.
            new_has_title = bool((new.title or "").strip())
            target_has_title = bool((target.title or "").strip())
            if new_has_title != target_has_title:
                winner, loser = (
                    (new, target) if new_has_title else (target, new)
                )
            else:
                # Tokens of one name are a subset of the other:
                # the shorter form is the canonical name. Otherwise
                # keep the older record (first-inserted-wins) to
                # match per-page dedup semantics.
                new_tokens = set((new.name or "").lower().split())
                target_tokens = set((target.name or "").lower().split())
                if new_tokens and target_tokens:
                    if new_tokens < target_tokens:
                        winner, loser = new, target
                    elif target_tokens < new_tokens:
                        winner, loser = target, new
                    else:
                        winner, loser = target, new
                else:
                    winner, loser = target, new
        else:
            winner, loser = target, new
        if not winner.email and loser.email:
            winner.email = loser.email
        if not winner.title and loser.title:
            winner.title = loser.title
    return merged


async def discover_and_extract(
    domain: str,
    session: Any,
    *,
    aggressive: bool = False,
    max_candidates: int | None = None,
    timeout: float = 5.0,
    include_homepage: bool = True,
    candidate_paths: list[str] | tuple[str, ...] | None = None,
) -> list[PersonRecord]:
    """Run the full 0.11.1 Phase 2 site-intelligence pipeline.

    Steps:

    1. Call :func:`backend.core.site_discovery.discover_team_pages`
       to locate team / leadership / people pages on *domain*.
    2. For each confirmed candidate (and optionally the homepage),
       fetch the HTML, run it through
       :func:`backend.core.structured_data_extractor.extract_people`
       with ``is_team_page=True`` when the URL is a discovered
       candidate and ``is_team_page=False`` for the homepage.
    3. Apply :func:`_dedupe_person_records` to collapse duplicates.
    4. Return the list sorted by ``confidence`` descending.

    Parameters
    ----------
    domain:
        Bare hostname, e.g. ``"example.com"``.
    session:
        Async HTTP session — preferred shape is
        :class:`backend.core.stealth_client.StealthSession`.  Any
        object exposing ``async get(url) -> response`` works.
    aggressive:
        When ``True`` the inner :func:`extract_people` enables its
        body-text extraction method (low-confidence fallback).
        Defaults to ``False`` per spec.
    max_candidates:
        Override for the per-page candidate probe cap.  Defaults to
        ``15`` — pull from
        ``settings.site_discovery_max_candidates`` at the call
        site to honour operator overrides.
    timeout:
        Per-request timeout in seconds; defaults to 5.
    include_homepage:
        When ``True`` (default) the homepage is fetched and
        run through the extractor as a low-priority candidate
        (some sites put team JSON-LD on their landing page for
        SEO).  Toggle ``False`` to skip.
    candidate_paths:
        Optional orchestrator-provided paths from
        IndustryVocabularyRouter, added to the site discovery queue.
    """
    cleaned = (domain or "").strip().lower()
    if not cleaned or "." not in cleaned:
        return []

    # 1. Discover team pages.
    candidates: list[PageCandidate] = await _discover_team_pages(
        cleaned,
        session,
        max_candidates=max_candidates,
        timeout=timeout,
        candidate_paths=candidate_paths,
    )

    # Optionally prepend the homepage as a low-priority candidate.
    if include_homepage:
        candidates.append(
            PageCandidate(
                url=f"https://{cleaned}/",
                score=0.5,
                source="homepage_root",
            )
        )

    # 2. Fetch + extract for each candidate in parallel.
    async def _extract_one(candidate: PageCandidate) -> list[PersonRecord]:
        html = await _candidate_fetcher(
            session, candidate.url, timeout=timeout
        )
        if not html:
            return []
        html = await _cf_decode(html)
        is_team = candidate.source != "homepage_root"
        try:
            records = _extract_people(
                html,
                candidate.url,
                cleaned,
                is_team_page=is_team,
                aggressive=aggressive,
            )
            # Framework hydration often contains the complete instructor or
            # team-card dataset even when the visible HTML is sparse.  Merge
            # those records into the same PersonRecord stream so the normal
            # company-page dedupe and email side-channel remain authoritative.
            for hit in HydrationDataExtractor.find_hits_from_html(
                html, page_url=candidate.url
            ):
                if not hit.name:
                    continue
                records.append(
                    PersonRecord(
                        name=hit.name,
                        email=hit.email,
                        title=hit.role,
                        source_type=f"hydration_{hit.framework}",
                        confidence=0.68,
                        page_url=candidate.url,
                    )
                )
            return records
        except Exception as exc:  # noqa: BLE001 — defensive
            _LOG.debug(
                "discover_and_extract: extract_people failed on %s: %s",
                candidate.url,
                exc,
            )
            return []

    nested = await asyncio.gather(
        *(_extract_one(c) for c in candidates),
        return_exceptions=True,
    )
    flat: list[PersonRecord] = []
    for outcome in nested:
        if isinstance(outcome, BaseException):
            continue
        flat.extend(outcome)

    return sorted(
        _dedupe_person_records(flat),
        key=lambda r: (-r.confidence, r.name),
    )


async def _convert_person_records_to_company_page_names(
    records: list[PersonRecord],
) -> list[CompanyPageName]:
    """Bridge :class:`PersonRecord` records into the legacy
    :class:`CompanyPageName` shape so legacy callers
    (``discover_company_page_names`` + ``employee_name_discovery`` pre
    Phase 2) can consume the new pipeline output unchanged.

    The conversion is lossy by design — :class:`CompanyPageName`
    has fewer fields than :class:`PersonRecord`.  ``source_type`` is
    retained so legacy consumers can decide whether the name came
    from JSON-LD, body text, etc.

    Async only because the import path stays consistent with the
    rest of this module; no I/O is performed.
    """
    out: list[CompanyPageName] = []
    for record in records:
        if not (record.name or "").strip():
            continue
        # Confidence from a structured block is usually > 0.55; cap
        # at the legacy 0.6 * multiplier when source_type is the
        # legacy body-text or json_ld paths.  We use the legacy
        # baselines so the existing
        # test_company_page_names tests stay meaningful — the
        # structured-data confidence (0.85/0.90) would otherwise
        # muddy the legacy "with_role"/"no_role" comparison paths.
        if record.source_type == "json_ld":
            confidence = round(_COMPANY_PAGE_CONFIDENCE * _COMPANY_PAGE_JSON_LD_BONUS, 4)
            source_type: SourceType = "json_ld"
        elif record.source_type in ("microdata", "rdfa", "hcard"):
            confidence = round(_COMPANY_PAGE_CONFIDENCE * 1.0, 4)
            source_type = "no_role"
        elif record.source_type in ("dom_team_card", "heading_plus_title"):
            confidence = round(_COMPANY_PAGE_CONFIDENCE * 0.9, 4)
            source_type = "with_role"
        elif record.source_type == "mailto":
            # Team-page mailto: 0.7 → legacy multiplier
            # 0.6 × 1.17 ≈ 0.7; general-page mailto: 0.4 → 0.6 × 0.67
            confidence = round(_COMPANY_PAGE_CONFIDENCE * (record.confidence / 0.6), 4)
            source_type = "no_role"
        elif record.source_type == "body_text_aggressive":
            confidence = round(_COMPANY_PAGE_CONFIDENCE * _COMPANY_PAGE_NO_ROLE_PENALTY, 4)
            source_type = "no_role"
        else:
            confidence = round(_COMPANY_PAGE_CONFIDENCE, 4)
            source_type = "no_role"
        out.append(
            CompanyPageName(
                name=record.name,
                source_url=record.page_url,
                title_or_role=record.title,
                confidence=confidence,
                source_type=source_type,
                email=record.email,
            )
        )
    return out


__all__ = [
    "CompanyPageName",
    "SourceType",
    "discover_company_page_names",
    "discover_for_tests",
    "discover_and_extract",
    "PersonRecord",
]


# Re-export the new symbols for ergonomic imports.
