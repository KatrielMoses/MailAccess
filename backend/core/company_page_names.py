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

import logging
import re
from dataclasses import dataclass
from html import unescape

import httpx

from .http_client import build_client
from .name_quality import is_plausible_person_name

_LOG = logging.getLogger(__name__)

# Confidence baseline — self-disclosed on a controlled corporate page
# is more reliable than a random match anywhere else, but unverified
# against a structured registry.
_COMPANY_PAGE_CONFIDENCE = 0.6

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


@dataclass
class CompanyPageName:
    name: str
    source_url: str
    title_or_role: str | None
    confidence: float


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


def _extract_names_from_text(
    text: str,
    domain: str | None = None,
) -> list[tuple[str, str | None]]:
    """Return ``[(name, role_or_None)]`` tuples extracted from page text.

    Uses two complementary passes:
    1. Strict "Name, Title" pattern (very high precision).
    2. Loose "Capitalised token sequence" pattern, filtered through
       :func:`name_quality.is_plausible_person_name` (lower precision
       but higher recall).

    Pass ``domain`` to drop candidates that match the target company
    name itself ("Acme Welcome" → reject because "acme" == the
    registrable part of the target domain).
    """
    from .name_quality import matches_domain as _matches_domain

    found: list[tuple[str, str | None]] = []
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

    def _keep(name: str, role: str | None) -> None:
        cleaned_name = name.strip()
        if not is_plausible_person_name(cleaned_name):
            return
        if _matches_company_token(cleaned_name):
            return
        if domain and _matches_domain(cleaned_name, domain):
            return
        key = cleaned_name.lower()
        if key in seen:
            return
        seen.add(key)
        found.append((cleaned_name, role))

    # Pass 1: "Name, Title" or "Name - Title" patterns.
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
        _keep(name, role)

    # Pass 2: standalone capitalised sequences.
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
            key = candidate.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append((candidate, None))

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
                page_names = _extract_names_from_text(text, domain=cleaned)
                for name, role in page_names:
                    if not is_plausible_person_name(name):
                        continue
                    key = name.lower()
                    if key in seen_names:
                        continue
                    entry = CompanyPageName(
                        name=name,
                        source_url=url,
                        title_or_role=role,
                        confidence=_COMPANY_PAGE_CONFIDENCE,
                    )
                    seen_names[key] = entry
                    names.append(entry)
        finally:
            if owns_client:
                await client.aclose()

    await _run()
    return names


def discover_for_tests(
    page_text_by_url: dict[str, str],
    domain: str | None = None,
) -> list[CompanyPageName]:
    """Test-only helper to derive CompanyPageName records from
    already-rendered page text.  Pass ``domain`` to enable the
    company-name self-match filter.
    """
    out: list[CompanyPageName] = []
    for url, text in page_text_by_url.items():
        for name, role in _extract_names_from_text(text, domain=domain):
            if not is_plausible_person_name(name):
                continue
            out.append(
                CompanyPageName(
                    name=name,
                    source_url=url,
                    title_or_role=role,
                    confidence=_COMPANY_PAGE_CONFIDENCE,
                )
            )
    return out
