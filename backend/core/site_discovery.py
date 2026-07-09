"""Discover team/leadership/people pages on a target domain.

MailAccess 0.11.1 Phase 2 — Site Intelligence Rebuild.

Replaces the fixed-path approach used in
:mod:`backend.core.company_page_names` (which probed a hard-coded
list of ``/about`` / ``/team`` / ``/leadership`` URLs) with a
discovery-first pipeline that:

1. Fetches the site's sitemap(s) and extracts candidate URLs whose
   path segments or filenames match :data:`TEAM_SIGNALS`.
2. In parallel, fetches the homepage and scores every internal
   ``<a href>`` (2x weight when the anchor text matches a team
   keyword).
3. Fetches ``/robots.txt`` and pulls any path mentioned in
   ``Disallow`` / ``Allow`` rules that matches a team keyword —
   these are added to the candidate list even though
   ``robots_disallowed=True`` (the analyst decides whether to
   probe, not the tool).
4. Merges and deduplicates candidates by normalised URL.
5. Probe-fetches the top *N* candidates and returns the
   confirmed-reachable set ordered by score.

The module is dependency-free at runtime (stdlib only).  HTTP
work goes through whatever session the caller supplies — the
:class:`backend.core.stealth_client.StealthSession` from 0.11.1
Phase 1 is the preferred choice, but any async-compatible session
with ``async get(url) -> response`` works (the type annotation is
:data:`Any` for that reason).

Why not use ``httpx`` directly:
    The harvest pipeline runs through Phase 1's :class:`StealthSession`
    for fingerprint reasons.  Site discovery is part of that
    pipeline, so it accepts the same session shape.
"""

from __future__ import annotations

import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

_LOG = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Signals — every URL path/filename/anchor is matched against this set
# ----------------------------------------------------------------------
# Words that, when they appear as a path segment or filename on the
# target's own domain, are strong predictors of "team / people /
# leadership" pages.  Matching is case-insensitive and treats hyphens
# and underscores as transparent — ``/meet-the-team`` matches
# ``"meet the team"`` which matches ``"team"`` via substring scan.
TEAM_SIGNALS: frozenset[str] = frozenset(
    {
        "team",
        "people",
        "leadership",
        "board",
        "management",
        "founders",
        "staff",
        "executives",
        "directors",
        "about",
        "management team",
        "our team",
        "meet the team",
        "who we are",
        "company",
        "organisation",
        "organization",
    }
)

# Sitemap paths to try, in order of preference.
_SITEMAP_PATHS: tuple[str, ...] = (
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/wp-sitemap.xml",
    "/sitemap.txt",
)

# Per-request timeout.  Used both for candidate probes and for the
# sitemap/homepage/robots fetches.
_DEFAULT_TIMEOUT_SECONDS: float = 5.0
# Cap on candidates we will probe after merging all sources.  The
# prompt asks for 15 (settings.site_discovery_max_candidates).
_DEFAULT_MAX_CANDIDATES: int = 15


# ----------------------------------------------------------------------
# PageCandidate — one URL suspected of being a team page
# ----------------------------------------------------------------------
@dataclass
class PageCandidate:
    """A URL that the discovery pipeline thinks is a team page.

    Attributes
    ----------
    url:
        Absolute URL on the target domain.
    score:
        Higher is better.  Combines the TEAM_SIGNALS hit count
        (path-segments + filename tokens) with anchor-text matches.
    source:
        Which discovery phase produced this candidate
        (``"sitemap"``, ``"homepage"``, ``"robots"``, or
        ``"homepage_anchor"`` if the URL was added because its
        anchor text matched a signal).
    robots_disallowed:
        ``True`` only when the URL came from a ``robots.txt`` rule
        that disallows crawling.  We still probe it — analysts
        choose whether to honour ``robots.txt``, not the tool.
    anchor_text:
        The exact anchor text that produced the match, when
        ``source == "homepage"`` / ``"homepage_anchor"``.
        Empty otherwise.
    """

    url: str
    score: float
    source: str = "sitemap"
    robots_disallowed: bool = False
    anchor_text: str = ""
    probed: bool = field(default=False, repr=False)


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------
def _strip_separators(s: str) -> str:
    """Collapse hyphens and underscores to spaces, lowercase."""
    return re.sub(r"[-_]+", " ", s.strip().lower())


def _match_team_signal(text: str) -> int:
    """Score a single token / segment against TEAM_SIGNALS.

    Returns the number of signal hits found.  Two complementary
    passes run:

    * **Substring pass** — multi-word signals like ``"who we are"``
      match the contiguous normalised text (``who-we-are`` →
      ``"who we are"``) directly.  Catches short two- and
      three-word phrases.
    * **N-gram pass** — single tokens like ``"leadership"`` and
      pair tokens like ``"our team"`` are checked against the
      whitespace- + dot-tokenised input.  Catches ``leadership.php``
      (tokenised to ``["leadership", "php"]``) and signals split
      across multiple separators.

    Tokens are derived by splitting on whitespace, hyphens,
    underscores, and dots so URL fragments (``leadership.php``,
    ``our-team``, ``who_we_are``) tokenise cleanly.

    The score is intentionally a simple count rather than a
    weighted sum — we want a fast tie-breakable ordering, not a
    learned relevance model.
    """
    if not text:
        return 0
    norm = _strip_separators(text)
    tokens = re.split(r"[\s\-_]+", norm.replace(".", " "))
    tokens = [t.strip() for t in tokens if t.strip()]
    # Build n-grams for n=1..3 so 3-word signals like
    # ``"who we are"`` can match a contiguous run of tokens.
    tokens_full: list[str] = list(tokens)
    for n in (2, 3):
        for i in range(len(tokens) - n + 1):
            tokens_full.append(" ".join(tokens[i : i + n]))
    hits = 0
    for signal in TEAM_SIGNALS:
        sig_norm = _strip_separators(signal)
        if not sig_norm:
            continue
        # Substring pass — matches contiguous signals in free text.
        if " " in sig_norm and sig_norm in norm:
            hits += 1
            continue
        # Token / n-gram pass — matches exact normalised units.
        if sig_norm in tokens_full:
            hits += 1
    return hits


def _score_url_path(url: str) -> tuple[float, int]:
    """Return ``(score, hits)`` for *url* based on path segments + filename.

    Each path segment and each filename token contributes one hit per
    matching signal.  We deliberately keep the scoring local — no
    per-segment weighting — so the result is interpretable.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return 0.0, 0
    path = parsed.path or "/"
    segments = [seg for seg in path.split("/") if seg]
    if not segments:
        return 0.0, 0
    hits = 0
    for seg in segments:
        hits += _match_team_signal(seg)
    return float(hits), hits


def _score_anchor(anchor: str) -> float:
    """Return the score contribution from an anchor text match.

    Anchor-text matches are worth 2x URL-path matches per the spec.
    """
    return 2.0 * float(_match_team_signal(anchor))


def _is_same_domain(url: str, domain: str) -> bool:
    """True when *url*'s host is *domain* (case-insensitive, bare hostname)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if not parsed.netloc:
        return False
    return parsed.netloc.lower() == domain.lower()


def _normalise_url(url: str, base: str) -> str | None:
    """Resolve *url* against *base* and return its canonical form.

    Strips the URL fragment and lower-cases the host.  Returns
    ``None`` if the input cannot be parsed or is not http(s).
    """
    if not url:
        return None
    s = url.strip()
    if not s:
        return None
    # Skip non-HTML resources that may show up on homepages.
    lowered = s.lower()
    if any(
        lowered.split("?", 1)[0].endswith(ext)
        for ext in (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".zip")
    ):
        return None
    absolute = urljoin(base, s)
    try:
        parsed = urlparse(absolute)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    # Strip the fragment, normalise the scheme to https if http.
    scheme = parsed.scheme or "https"
    path = parsed.path or "/"
    query_suffix = ("?" + parsed.query) if parsed.query else ""
    return f"{scheme}://{parsed.netloc.lower()}{path}{query_suffix}"


def _read_text(response: Any) -> str:
    """Best-effort ``response.text`` access that survives non-curl-cffi shapes."""
    try:
        return str(response.text or "")
    except Exception:  # noqa: BLE001 — defensive: decode may fail on weird encodings
        return ""


def _read_status(response: Any) -> int:
    try:
        return int(getattr(response, "status_code", 0) or 0)
    except Exception:  # noqa: BLE001
        return 0


def _head_ok(response: Any) -> bool:
    """Return True when *response* indicates the URL is reachable.

    Many servers respond to non-HEAD requests with 405 (Method
    Not Allowed) when the probe was actually a GET masquerading as
    a HEAD — we accept 405 as "reachable, just no body wanted".
    """
    code = _read_status(response)
    return code in (200, 204, 301, 302, 303, 307, 308, 405)


# ----------------------------------------------------------------------
# Robots.txt hint extraction
# ----------------------------------------------------------------------
_ROBOTS_LINE_RE = re.compile(
    r"^\s*(?P<directive>Disallow|Allow)\s*:\s*(?P<value>\S*)",
    flags=re.IGNORECASE | re.MULTILINE,
)


def _extract_robots_paths(text: str) -> list[tuple[str, str]]:
    """Return ``[(path, directive)]`` pairs from a ``robots.txt`` body.

    Empty values (which mean "match everything") are skipped — they
    would map to every URL and provide no signal.
    """
    out: list[tuple[str, str]] = []
    if not text:
        return out
    for match in _ROBOTS_LINE_RE.finditer(text):
        directive = (match.group("directive") or "").lower()
        value = (match.group("value") or "").strip()
        if not value or value == "*":
            continue
        out.append((value, directive))
    return out


# ----------------------------------------------------------------------
# Sitemap URL extraction
# ----------------------------------------------------------------------
def _extract_sitemap_urls(xml_text: str) -> list[str]:
    """Parse a sitemap XML body and return every ``<loc>`` URL.

    Uses stdlib :mod:`xml.etree.ElementTree` (no extra deps).  Falls
    back to a regex parse when the body is ``<scheme>...`` style
    plain text (e.g. ``sitemap.txt``).
    """
    out: list[str] = []
    if not xml_text or not xml_text.strip():
        return out
    # Strip XML namespace declarations so stdlib ET can parse.
    cleaned = re.sub(
        r'\sxmlns(:[a-z0-9]+)?\s*=\s*"[^"]+"', "", xml_text, flags=re.IGNORECASE
    )
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        # Try plain-text sitemap (one URL per line).
        for line in xml_text.splitlines():
            line = line.strip()
            if line.lower().startswith(("http://", "https://")):
                out.append(line)
        return out
    # ElementTree treats every <loc> identically regardless of
    # ancestor — works for <urlset><url><loc> and
    # <sitemapindex><sitemap><loc> alike.
    for loc in root.iter("loc"):
        if loc.text and loc.text.strip():
            out.append(loc.text.strip())
    return out


# ----------------------------------------------------------------------
# Homepage <a href> extraction
# ----------------------------------------------------------------------
# Single regex that captures ``href`` value + inner markup of every
# ``<a ...>...</a>`` pair in one pass.  Using a two-stage scan with
# a "starting from the href position" approach was off-by-one and
# caused the inner text to spill into the next anchor — replacing it
# with a full-pair scan is unambiguous and survives nested / malformed
# HTML (the regex refuses to match a non-paired ``<a>`` rather than
# spilling content).
_A_FULL_RE = re.compile(
    r'<a\b[^>]*?\bhref\s*=\s*(?P<quote>["\'])(?P<href>[^"\']+)(?P=quote)[^>]*>'
    r"(?P<inner>.*?)</a\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)


def _strip_tags(s: str) -> str:
    """Tiny stdlib tag stripper sufficient for anchor text only."""
    if not s:
        return ""
    no_script = re.sub(
        r"<(?:script|style)[^>]*>.*?</(?:script|style)>",
        " ",
        s,
        flags=re.IGNORECASE | re.DOTALL,
    )
    no_tags = re.sub(r"<[^>]+>", " ", no_script)
    return re.sub(r"\s+", " ", no_tags).strip()


def _extract_homepage_links(html: str, base: str) -> list[tuple[str, str]]:
    """Return ``[(absolute_url, anchor_text)]`` for every ``<a href>`` in *html*.

    External (different host from *base*) URLs are dropped so we
    don't waste probes on Twitter / LinkedIn links.
    """
    if not html:
        return []
    base_domain = urlparse(base).netloc.lower() if base else ""
    links: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _A_FULL_RE.finditer(html):
        href = match.group("href")
        absolute = _normalise_url(href, base)
        if not absolute:
            continue
        if base_domain and not _is_same_domain(absolute, base_domain):
            continue
        if absolute in seen:
            continue
        anchor = _strip_tags(match.group("inner") or "")
        seen.add(absolute)
        links.append((absolute, anchor))
    return links


# ----------------------------------------------------------------------
# Per-source candidate scoring
# ----------------------------------------------------------------------
def _candidate_from_sitemap(url: str, domain: str) -> PageCandidate | None:
    """Score one sitemap URL; return ``None`` when no signal matches."""
    if not _is_same_domain(url, domain):
        return None
    score, hits = _score_url_path(url)
    if hits <= 0:
        return None
    return PageCandidate(url=url, score=score, source="sitemap")


def _candidates_from_homepage(
    links: list[tuple[str, str]], domain: str
) -> list[PageCandidate]:
    """Score every (url, anchor) pair against TEAM_SIGNALS."""
    out: list[PageCandidate] = []
    seen: set[str] = set()
    for url, anchor in links:
        if not _is_same_domain(url, domain):
            continue
        if url in seen:
            continue
        seen.add(url)
        path_score, _hits = _score_url_path(url)
        anchor_score = _score_anchor(anchor) if anchor else 0.0
        total = path_score + anchor_score
        if total <= 0:
            continue
        source = "homepage_anchor" if anchor_score > path_score else "homepage"
        out.append(
            PageCandidate(
                url=url,
                score=total,
                source=source,
                anchor_text=anchor,
            )
        )
    return out


def _candidates_from_robots(
    rules: list[tuple[str, str]], domain: str
) -> list[PageCandidate]:
    """Turn robots.txt paths into candidate URLs.

    A ``Disallow: /leadership`` rule against ``example.com``
    becomes the candidate ``https://example.com/leadership``.
    """
    out: list[PageCandidate] = []
    for path, directive in rules:
        if not path:
            continue
        # Only consider paths starting with "/" — relative or
        # wildcards like "$" don't map to a concrete URL.
        if not path.startswith("/"):
            continue
        absolute = f"https://{domain.lower()}{path}"
        score, hits = _score_url_path(absolute)
        if hits <= 0:
            continue
        out.append(
            PageCandidate(
                url=absolute,
                score=score,
                source="robots",
                robots_disallowed=(directive == "disallow"),
            )
        )
    return out


# ----------------------------------------------------------------------
# StealthSession-style fetch (async get(url) -> response)
# ----------------------------------------------------------------------
async def _get(session: Any, url: str, *, timeout: float) -> tuple[int, str]:
    """Fetch *url* via *session*; return ``(status, body)`` or ``(-1, "")``."""
    try:
        # StealthSession.get() does not accept a timeout kwarg —
        # its spec lives on the session object itself.  We call it
        # without ``timeout=`` and fall back to a plain call (which
        # httpx.AsyncClient accepts with ``timeout=``).
        response = await session.get(url, timeout=timeout)
    except TypeError:
        # StealthSession path — ``timeout=`` not accepted.
        try:
            response = await session.get(url)
        except Exception:  # noqa: BLE001
            return -1, ""
    except Exception:  # noqa: BLE001
        return -1, ""
    if not _head_ok(response):
        return _read_status(response) or -1, ""
    return _read_status(response), _read_text(response)


async def _probe(session: Any, candidate: PageCandidate, *, timeout: float) -> bool:
    """Probe *candidate* URL to confirm it's reachable.

    Uses ``session.get`` rather than a true HTTP HEAD because
    :class:`backend.core.stealth_client.StealthSession` does not
    expose a ``head()`` method — the cost of a full GET vs a HEAD
    on a 5-second budget is negligible, and the result is the same.

    Returns ``True`` only when the response carries a "success /
    redirect" status (200, 204, 3xx, 405).  A 404 or 5xx returns
    ``False`` so the candidate is dropped from the final list.
    """
    status, _ = await _get(session, candidate.url, timeout=timeout)
    # Mirror :func:`_head_ok` so probe success matches the same
    # reachability semantics.  Plain ``status > 0`` would let 404
    # through (which is what an older draft of this function did).
    reachable = status in (200, 204, 301, 302, 303, 307, 308, 405)
    candidate.probed = reachable
    return reachable


# ----------------------------------------------------------------------
# Top-level discovery pipeline
# ----------------------------------------------------------------------
async def discover_team_pages(
    domain: str,
    session: Any = None,
    *,
    max_candidates: int | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> list[PageCandidate]:
    """Discover team/leadership/people pages on *domain*.

    Returns PageCandidates ordered by descending *score*.  All
    candidates have been probe-fetched (HEAD-shaped GET) and only
    reachable ones survive.

    Parameters
    ----------
    domain:
        Bare hostname (e.g. ``"example.com"``) — no scheme, no path.
    session:
        Any async HTTP session exposing ``async get(url) -> response``
        with ``.text`` and ``.status_code`` attributes.  The
        :class:`StealthSession` from 0.11.1 Phase 1 is the preferred
        caller-supplied session.  When ``None`` a T2 ``StealthSession``
        is created internally (auto-closed when done).
    max_candidates:
        Cap on probe results.  Defaults to
        :data:`_DEFAULT_MAX_CANDIDATES` (15).  Per spec the orchestrator
        passes ``settings.site_discovery_max_candidates`` for this.
    timeout:
        Per-request timeout in seconds.  Defaults to 5.

    Algorithm
    ---------
    1. Fetch all sitemaps in parallel (``asyncio.gather``); score
       every URL whose path/filename signals match.
    2. Concurrently, fetch the homepage + ``/robots.txt``; score
       internal links (with 2x anchor bonus) and any team-signal
       paths in robots.
    3. Deduplicate by normalised URL; keep the highest score.
    4. Probe the top *max_candidates*; drop unreachable entries.
    """
    # Build or borrow a session.
    _own_session: Any = None
    if session is None:
        try:
            from .stealth_client import StealthSession, T2_BALANCED  # noqa: I001

            _own_session = StealthSession(timing_profile=T2_BALANCED)
            session = _own_session
        except ImportError:
            # curl-cffi absent — fall back to a minimal httpx client.
            import httpx

            _fallback = httpx.AsyncClient(timeout=timeout)
            session = _fallback
            _own_session = _fallback

    try:
        cleaned = (domain or "").strip().lower()
        if not cleaned or "." not in cleaned:
            return []
        cap = max(1, int(max_candidates or _DEFAULT_MAX_CANDIDATES))
        base = f"https://{cleaned}"

        # ----- Phase A: sitemap URLs in parallel -----
        sitemap_urls = [f"{base}{p}" for p in _SITEMAP_PATHS]
        sitemap_results = await asyncio.gather(
            *(_get(session, url, timeout=timeout) for url in sitemap_urls),
            return_exceptions=True,
        )
        sitemap_candidates: list[PageCandidate] = []
        for outcome in sitemap_results:
            if isinstance(outcome, BaseException):
                continue
            status, body = outcome
            if status != 200 or not body:
                continue
            for u in _extract_sitemap_urls(body):
                cand = _candidate_from_sitemap(u, cleaned)
                if cand is not None:
                    sitemap_candidates.append(cand)

        # ----- Phase B: homepage link discovery -----
        homepage_candidates: list[PageCandidate] = []
        homepage_status, homepage_body = await _get(session, base, timeout=timeout)
        if homepage_status == 200 and homepage_body:
            links = _extract_homepage_links(homepage_body, base)
            homepage_candidates = _candidates_from_homepage(links, cleaned)

        # ----- Phase B2: one-hop recursion from section-like homepage links -----
        recursive_candidates: list[PageCandidate] = []
        recursive_seeds = []
        for cand in homepage_candidates:
            path_score, _ = _score_url_path(cand.url)
            # Only recurse from URLs whose own path already carries a
            # team/section signal.  This skips noisy homepage cards
            # such as blog headlines that merely *mention* teams.
            if path_score > 0:
                recursive_seeds.append(cand)
        recursive_seeds = sorted(
            recursive_seeds, key=lambda c: (-c.score, c.url)
        )[:5]
        if recursive_seeds:
            recursive_results = await asyncio.gather(
                *(_get(session, cand.url, timeout=timeout) for cand in recursive_seeds),
                return_exceptions=True,
            )
            for seed, outcome in zip(recursive_seeds, recursive_results):
                if isinstance(outcome, BaseException):
                    continue
                status, body = outcome
                if status != 200 or not body:
                    continue
                links = _extract_homepage_links(body, seed.url)
                for cand in _candidates_from_homepage(links, cleaned):
                    cand.source = "homepage_recursive"
                    recursive_candidates.append(cand)

        # ----- Phase C: robots.txt hints (sequential is fine — usually tiny) -----
        robots_candidates: list[PageCandidate] = []
        robots_status, robots_body = await _get(
            session, f"{base}/robots.txt", timeout=timeout
        )
        if robots_status == 200 and robots_body:
            rules = _extract_robots_paths(robots_body)
            robots_candidates = _candidates_from_robots(rules, cleaned)

        # ----- Merge + dedupe by normalised URL -----
        by_url: dict[str, PageCandidate] = {}
        for cand in (
            sitemap_candidates
            + homepage_candidates
            + recursive_candidates
            + robots_candidates
        ):
            existing = by_url.get(cand.url)
            if existing is None or cand.score > existing.score:
                by_url[cand.url] = cand
        merged = sorted(
            by_url.values(), key=lambda c: (-c.score, c.url)
        )
        top = merged[:cap]

        # ----- Probe the top N candidates in parallel -----
        probe_outcomes = await asyncio.gather(
            *(_probe(session, c, timeout=timeout) for c in top),
            return_exceptions=True,
        )
        confirmed: list[PageCandidate] = []
        for cand, outcome in zip(top, probe_outcomes):
            if isinstance(outcome, BaseException):
                continue
            if outcome is True:
                confirmed.append(cand)
        return sorted(confirmed, key=lambda c: (-c.score, c.url))
    finally:
        if _own_session is not None:
            try:
                if hasattr(_own_session, "aclose"):
                    await _own_session.aclose()
            except Exception:  # noqa: BLE001
                pass
            try:
                if hasattr(_own_session, "close"):
                    _own_session.close()
            except Exception:  # noqa: BLE001
                pass


__all__ = [
    "TEAM_SIGNALS",
    "PageCandidate",
    "discover_team_pages",
]
