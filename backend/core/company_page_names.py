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

import json
import logging
import re
from dataclasses import dataclass
from html import unescape
from typing import Any

import httpx

from .http_client import build_client
from .name_quality import is_plausible_person_name

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


def _candidate_in_page_furniture(name: str, page_furniture: tuple[str | None, str | None]) -> bool:
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
    page_furniture: tuple[str | None, str | None] = (None, None),
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


async def _fetch_page(client: httpx.AsyncClient, url: str) -> str | None:
    """Fetch a single page; return decoded text or ``None`` on any failure."""
    try:
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
) -> list[CompanyPageName]:
    """Try the candidate about/team pages on *domain* and extract names.

    Stops after *max_pages* successful page fetches (defaults to 5)
    so we don't burn bandwidth hunting for paths the company doesn't
    expose.  Returns an empty list when nothing of value is found.
    """
    cleaned = (domain or "").strip().lower()
    if not cleaned or "." not in cleaned:
        return []

    effective_cap = max(1, int(max_pages))
    limit = min(effective_cap, len(_PAGE_PATHS))

    names: list[CompanyPageName] = []
    seen_names: dict[str, CompanyPageName] = {}

    async def _run() -> None:
        owns_client = transport is None
        client = transport if transport is not None else build_client(timeout=_FETCH_TIMEOUT)
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
                page_furniture = _extract_page_metadata(html)
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
            if owns_client:
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
        for name, role, source_type in _extract_names_from_text(
            text, domain=domain, page_furniture=furniture
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
