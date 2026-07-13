"""ContextRouter - Phase-0 routing decision for the orchestrator.

0.11.1 Phase 3 - sits between the homepage fetch and the per-industry
URL fanout. ``ContextRouter.route()`` is the only public entry point:

    config = await router.route("example.com", fetch_cache)

It returns a :class:`RoutingConfig` carrying:

* :attr:`RoutingConfig.tech_flags` - which hydration extractors to spin
  up (Next.js, Nuxt, WordPress, Remix).  Each is a pre-compiled substring
  or regex hit on the raw homepage HTML; no DOM parser is involved.
* :attr:`RoutingConfig.industry_labels` - which industry vocabularies
  to apply, matched by keyword scan against the homepage HTML.
* :attr:`RoutingConfig.url_candidates` - URL paths to probe, derived by
  unioning the matched vocab rows' ``url_candidates`` lists (order
  preserved, deduped, normalised).
* :attr:`RoutingConfig.homepage_status` - the HTTP status the cache
  surfaced for the homepage; ``None`` when the fetch errored or the
  request never reached the network.
* :attr:`RoutingConfig.elapsed_ms` - wall-clock time the whole
  ``route()`` call took, so the caller can self-monitor the 500 ms SLO.

Design rules (locked in this revision):

* Wall-clock budget is **500 ms** end to end.  Regex patterns are
  pre-compiled at module load; the cache is the same one every other
  module shares, so a homepage already fetched by e.g.
  ``employee_name_discovery`` is free.
* Raw HTML only - no BeautifulSoup, no lxml, no ``html.parser``.
* ``route()`` never raises.  Fetch / decode / analysis failures all
  degrade to a ``RoutingConfig`` with empty flags and candidates.
* Industry vocabulary is loaded from ``data/industry_vocabulary.json``
  once and lazily; file-read failures fall back to an empty catalog
  instead of breaking the router.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .concurrent_fetch_cache import ConcurrentFetchCache

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Hard wall-clock budget callers should respect.  ``ContextRouter``
#: measures ``elapsed_ms`` itself; this constant exists for orchestrator
#: code that wants to ``<`` -compare against a named knob rather than a
#: bare magic number.
DEFAULT_BUDGET_MS: Final[int] = 500

#: Where the industry catalog lives, relative to the repo root.
_DATA_PATH: Final[Path] = Path(__file__).resolve().parents[2] / "data" / "industry_vocabulary.json"

# Canonical paths that are almost always worth probing on a company site.
_UNIVERSAL_PATHS: Final[tuple[str, ...]] = (
    "/team",
    "/about",
    "/leadership",
    "/staff",
)

# Lightweight industry detectors.  These stay intentionally narrow so
# the router only expands when the homepage text carries a real signal.
#
# The training regex combines generic LMS signals (course, curriculum,
# syllabus, lms) with cybersecurity-specific cert / discipline
# vocabulary (OSCP/OSWE/OSEP/GIAC, pentest(ing), red/blue team, cyber
# range, CTF, DFIR, threat hunt, SOC analyst, infosec, cybersecurity).
# The cybersec terms distinguish security training platforms (INE,
# SANS, TCM Security) from generic e-commerce course sellers (Udemy,
# Coursera) — both still expand the training-academic vertical, but
# the cybersec vocabulary gives us a clean signal that the
# /instructors-style pages are likely to be individual practitioner
# profiles rather than celebrity-narrator "instructor of the month"
# cards.
_TRAINING_RE: Final[re.Pattern[str]] = re.compile(
    r"\b("
    r"course|curriculum|syllabus|lms|"
    r"oscp|oswe|osep|giac|pentest(?:ing)?|"
    r"red\s?team|blue\s?team|cyber\s?range|"
    r"ctf|capture\s+the\s+flag|dfir|"
    r"threat\s+hunt|soc\s+analyst|infosec|"
    r"cybersecurity"
    r")\b",
    re.IGNORECASE,
)
_LEGAL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(litigation|attorney|law firm|legal)\b",
    re.IGNORECASE,
)
_MEDICAL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(patient|clinic|hospital|healthcare)\b",
    re.IGNORECASE,
)

_DENY_RULES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"\btestimonials?\b", re.IGNORECASE), "/testimonials"),
    (re.compile(r"\bcase[-\s]?stud(?:y|ies)\b", re.IGNORECASE), "/case-studies"),
    (re.compile(r"\bcustomers?\b", re.IGNORECASE), "/customers"),
)

_INDUSTRY_RULES: Final[tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...]] = (
    (
        "training_academic",
        _TRAINING_RE,
        (
            "/instructors",
            "/faculty",
            "/teachers",
            "/authors",
            "/instructor",
            "/profiles",
            "/people",
            "/meet-the-team",
            "/learning/instructors",
        ),
    ),
    (
        "legal",
        _LEGAL_RE,
        ("/partners", "/attorneys", "/professionals"),
    ),
    (
        "medical",
        _MEDICAL_RE,
        ("/providers", "/physicians", "/clinicians"),
    ),
)

_HTML_SCAN_RE: Final[re.Pattern[str]] = re.compile(
    r"<(?:script|style)[^>]*>.*?</(?:script|style)>|<[^>]+>",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Pre-compiled detection patterns
# ---------------------------------------------------------------------------

#: Next.js hydration payload - literally ``__NEXT_DATA__`` as a substring
#: inside a ``<script>`` tag.  Substring (``in``) is fast because Next
#: embeds the variable name verbatim with no whitespace variation.
_NEXT_DATA_MARKER: Final[str] = "__NEXT_DATA__"

#: Nuxt.js hydration payload - ``window.__NUXT__`` referencing the SSR
#: state.  Substring match.
_NUXT_DATA_MARKER: Final[str] = "window.__NUXT__"

#: Remix SSR context - ``window.__remixContext`` literal in the inline
#: bootstrap script.  Substring match.
_REMIX_CONTEXT_MARKER: Final[str] = "window.__remixContext"

#: WordPress ``<meta name="generator" content="WordPress ..."/>`` tag.
#: Attribute order varies by theme, so a regex is required.  Anchor on
#: the ``generator`` name attribute and the ``WordPress`` token inside
#: the ``content`` attribute; the case-insensitive flag covers themes
#: that lower-case the version string.
#: Two lookaheads so attribute order does not matter - themes emit
#: ``name="generator" content="WordPress ..."`` and ``content="WordPress
#: ..." name="generator"`` equally often.  Both anchors are required
#: before the tag closes (no ``>`` allowed in the lookaheads).
_WORDPRESS_RE: Final[re.Pattern[str]] = re.compile(
    r'<meta\b(?=[^>]*\bname=["\']generator["\'])'
    r'(?=[^>]*\bcontent=["\'][^"\']*WordPress)'
    r"[^>]*>",
    re.IGNORECASE,
)


def _normalize_html_input(html: str | bytes | None) -> str:
    """Coerce *html* to ``str`` for fast substring matching.

    ``CachedResponse.text`` is already ``str`` (lazy-decoded with
    ``errors="replace"``), so this is a no-op in the hot path.  We keep
    the explicit coercion so unit tests can pass raw ``bytes`` and so
    defensive callers that hand us ``None`` degrade cleanly.
    """
    if html is None:
        return ""
    if isinstance(html, bytes):
        return html.decode("utf-8", errors="replace")
    if not isinstance(html, str):
        return ""
    return html


def _normalize_path(path: str) -> str:
    """Return a canonical absolute-ish path for *path*.

    Rules:

    1. Non-strings and empty strings map to ``""`` (caller filters).
    2. Leading whitespace stripped.
    3. A leading ``/`` is forced if absent.
    4. Runs of duplicate leading slashes collapse (``//foo`` -> ``/foo``).
    5. Trailing slashes stripped *except* for the root path ``"/"``,
       which is preserved so callers can detect "no path".

    Pure / idempotent.
    """
    if not isinstance(path, str):
        return ""
    cleaned = path.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    while cleaned.startswith("//"):
        cleaned = cleaned[1:]
    if len(cleaned) > 1 and cleaned.endswith("/"):
        cleaned = cleaned.rstrip("/")
    return cleaned


def _scan_homepage_text(homepage: str | bytes | None) -> str:
    """Return lower-cased visible text extracted from homepage bytes.

    The analyzer stays intentionally lightweight: decode, strip script
    and style blocks, remove the remaining tags, then collapse
    whitespace.  That is enough for keyword matching without pulling in
    a DOM parser.
    """
    text = _normalize_html_input(homepage)
    if not text:
        return ""
    stripped = _HTML_SCAN_RE.sub(" ", text)
    return re.sub(r"\s+", " ", stripped).strip().lower()


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TechFlags:
    """Which hydration extractors the orchestrator should spin up.

    ``matched_markers`` is a debug aid that records the actual substring
    hits; the orchestrator need not inspect it for routing decisions.
    """

    next_data: bool = False
    nuxt_data: bool = False
    wordpress_generator: bool = False
    remix_context: bool = False
    matched_markers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class IndustryVocab:
    """Loaded snapshot of ``data/industry_vocabulary.json``.

    Both maps are keyed by industry label (e.g. ``"lms"``,
    ``"legal"``).  Tuples (not lists) keep the dataclass frozen and
    hashable; ``analyze_industry`` iterates in JSON insertion order,
    which is the canonical ordering operators tune by hand.
    """

    keywords_by_label: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    url_candidates_by_label: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not self.keywords_by_label


@dataclass(frozen=True)
class RoutingConfig:
    """The artifact the orchestrator consumes.

    All flags / labels / paths are pre-computed by ``route()``.  An
    orchestrator that only cares "are there ANY tech flags?" can simply
    iterate ``tech_flags.matched_markers``; one that wants only URLs
    can read ``url_candidates`` directly.
    """

    tech_flags: TechFlags
    industry_labels: tuple[str, ...]
    url_candidates: tuple[str, ...]
    homepage_status: int | None
    elapsed_ms: float
    deny_list: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class IndustryVocabularyResult:
    """Output from :class:`IndustryVocabularyRouter`.

    ``target_paths`` is the deduplicated list of high-yield paths to
    feed into downstream extraction modules. ``deny_list`` records paths
    that should be excluded when negative signals indicate a likely
    false-positive trap.
    """

    target_paths: tuple[str, ...]
    deny_list: tuple[str, ...]
    inferred_industries: tuple[str, ...] = field(default_factory=tuple)


class IndustryVocabularyRouter:
    """Homepage analyzer that expands URL paths from industry cues.

    The router always starts with the canonical universal paths and
    adds industry-specific paths when the homepage text contains a
    matching signal. A small deny-list is returned alongside the target
    paths when trap-like signals show up in the homepage copy.
    """

    def __init__(
        self,
        *,
        universal_paths: Sequence[str] | None = None,
    ) -> None:
        base_paths = universal_paths or _UNIVERSAL_PATHS
        seen: set[str] = set()
        cleaned_universal: list[str] = []
        for raw_path in base_paths:
            norm = _normalize_path(raw_path)
            if norm and norm not in seen:
                seen.add(norm)
                cleaned_universal.append(norm)
        self._universal_paths = tuple(cleaned_universal)

    def analyze(self, homepage: str | bytes | None) -> IndustryVocabularyResult:
        """Return deduplicated probe paths and any trap paths to avoid."""
        text = _scan_homepage_text(homepage)
        seen: set[str] = set()
        target_paths: list[str] = []
        matched_industries: list[str] = []

        for path in self._universal_paths:
            if path not in seen:
                seen.add(path)
                target_paths.append(path)

        for label, pattern, paths in _INDUSTRY_RULES:
            if not pattern.search(text):
                continue
            matched_industries.append(label)
            for raw_path in paths:
                norm = _normalize_path(raw_path)
                if norm and norm not in seen:
                    seen.add(norm)
                    target_paths.append(norm)

        deny_seen: set[str] = set()
        deny_list: list[str] = []
        for pattern, raw_path in _DENY_RULES:
            if not pattern.search(text):
                continue
            norm = _normalize_path(raw_path)
            if norm and norm not in deny_seen:
                deny_seen.add(norm)
                deny_list.append(norm)

        if deny_seen:
            target_paths = [path for path in target_paths if path not in deny_seen]

        return IndustryVocabularyResult(
            target_paths=tuple(target_paths),
            deny_list=tuple(deny_list),
            inferred_industries=tuple(matched_industries),
        )

    def route(self, homepage: str | bytes | None) -> IndustryVocabularyResult:
        """Compatibility alias for callers that expect router-style naming."""
        return self.analyze(homepage)


# ---------------------------------------------------------------------------
# Vocabulary loader
# ---------------------------------------------------------------------------


def _load_vocab() -> IndustryVocab:
    """Read and validate ``data/industry_vocabulary.json``.

    Failure modes (missing file, malformed JSON, schema mismatch) all
    log a warning and return an empty :class:`IndustryVocab`.  The
    router must keep working when the catalog is broken - it just
    won't add URL candidates.
    """
    try:
        raw: Any = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _LOG.warning("industry_vocabulary.json unreadable (%s); router skips industry scan", exc)
        return IndustryVocab()

    if not isinstance(raw, dict):
        _LOG.warning("industry_vocabulary.json must be an object; got %s", type(raw).__name__)
        return IndustryVocab()

    keywords_by_label: dict[str, tuple[str, ...]] = {}
    url_candidates_by_label: dict[str, tuple[str, ...]] = {}

    for label, payload in raw.items():
        if not isinstance(label, str) or not isinstance(payload, dict):
            _LOG.warning("industry_vocabulary.json: skipping malformed row %r", label)
            continue
        raw_keywords = payload.get("keywords", [])
        raw_paths = payload.get("url_candidates", [])
        if not isinstance(raw_keywords, list) or not isinstance(raw_paths, list):
            _LOG.warning(
                "industry_vocabulary.json: row %r has non-list keywords/url_candidates", label
            )
            continue
        keywords = tuple(
            kw.strip().lower() for kw in raw_keywords if isinstance(kw, str) and kw.strip()
        )
        paths = tuple(
            normalized
            for normalized in (_normalize_path(p) for p in raw_paths if isinstance(p, str))
            if normalized
        )
        if not keywords or not paths:
            _LOG.warning(
                "industry_vocabulary.json: row %r is empty after cleaning; skipping",
                label,
            )
            continue
        keywords_by_label[label] = keywords
        url_candidates_by_label[label] = paths

    return IndustryVocab(
        keywords_by_label=keywords_by_label,
        url_candidates_by_label=url_candidates_by_label,
    )


# Lazy-loaded at first use.  ``reset_vocab_cache()`` exists for tests
# that patch ``_DATA_PATH`` and need to re-read.
_vocab_cache: IndustryVocab | None = None


def load_industry_vocab() -> IndustryVocab:
    """Return the cached :class:`IndustryVocab`, loading it on first call."""
    global _vocab_cache
    if _vocab_cache is None:
        _vocab_cache = _load_vocab()
    return _vocab_cache


def reset_vocab_cache() -> None:
    """Drop the cached vocabulary so the next ``load_industry_vocab()`` re-reads."""
    global _vocab_cache
    _vocab_cache = None


# ---------------------------------------------------------------------------
# Pure analyzers
# ---------------------------------------------------------------------------


def analyze_tech(html: str | bytes | None) -> TechFlags:
    """Return hydration flags for the raw homepage bytes/str.

    Three of the four checks are literal substring matches, which
    Python executes via fast string search (no regex backtracking).
    Only the WordPress ``<meta>`` check needs a regex because the
    ``name`` and ``content`` attributes appear in either order across
    themes.
    """
    text = _normalize_html_input(html)
    if not text:
        return TechFlags()

    matched: dict[str, str] = {}
    next_data = _NEXT_DATA_MARKER in text
    if next_data:
        matched["next_data"] = _NEXT_DATA_MARKER
    nuxt_data = _NUXT_DATA_MARKER in text
    if nuxt_data:
        matched["nuxt_data"] = _NUXT_DATA_MARKER
    remix_context = _REMIX_CONTEXT_MARKER in text
    if remix_context:
        matched["remix_context"] = _REMIX_CONTEXT_MARKER
    wordpress_generator = _WORDPRESS_RE.search(text) is not None
    if wordpress_generator:
        matched["wordpress_generator"] = "WordPress"

    if not matched:
        return TechFlags()
    return TechFlags(
        next_data=next_data,
        nuxt_data=nuxt_data,
        wordpress_generator=wordpress_generator,
        remix_context=remix_context,
        matched_markers=matched,
    )


def analyze_industry(html: str | bytes | None, vocab: IndustryVocab) -> list[str]:
    """Return matched industry labels in vocab order.

    A single keyword hit per industry is sufficient.  The HTML is
    lower-cased **once** before scanning; per-keyword substring check
    runs in C-speed (``str.__contains__``) so worst case is
    ``len(vocab) * len(keyword_list)`` cheap checks.
    """
    text = _normalize_html_input(html)
    if not text or vocab.is_empty():
        return []
    lowered = text.lower()
    matched: list[str] = []
    for label, keywords in vocab.keywords_by_label.items():
        for kw in keywords:
            if kw in lowered:
                matched.append(label)
                break
    return matched


def build_routing_config(
    tech_flags: TechFlags,
    industry_labels: Sequence[str],
    vocab: IndustryVocab,
    homepage_status: int | None,
    elapsed_ms: float,
) -> RoutingConfig:
    """Combine analyzer outputs into the artifact the orchestrator reads.

    URL candidate derivation:

    1. Walk *industry_labels* in the order returned by
       :func:`analyze_industry` (which preserves vocab insertion
       order).
    2. For each matched label, append its ``url_candidates`` in vocab
       order, skipping any path that's already been seen for an
       earlier label.
    3. Normalise every path through :func:`_normalize_path` so callers
       can join them straight onto an origin without further cleanup.
    """
    seen: set[str] = set()
    candidates: list[str] = []
    for label in industry_labels:
        for raw_path in vocab.url_candidates_by_label.get(label, ()):
            norm = _normalize_path(raw_path)
            if norm and norm not in seen:
                seen.add(norm)
                candidates.append(norm)

    return RoutingConfig(
        tech_flags=tech_flags,
        industry_labels=tuple(industry_labels),
        url_candidates=tuple(candidates),
        homepage_status=homepage_status,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# ContextRouter
# ---------------------------------------------------------------------------


class ContextRouter:
    """Composes the analyzers above with one homepage fetch.

    The router owns no HTTP state - it borrows the orchestrator's
    :class:`ConcurrentFetchCache` and lets that cache share the
    homepage with any other module that needs it.  Construct once per
    ``--domain`` run, reuse across calls if the runner fans out to
    multiple sub-domains.
    """

    def __init__(self, vocab: IndustryVocab | None = None) -> None:
        # ``None`` defers loading until first use; tests can inject a
        # custom vocab to exercise edge cases without touching disk.
        self._vocab = vocab if vocab is not None else load_industry_vocab()

    @property
    def vocab(self) -> IndustryVocab:
        return self._vocab

    def set_vocab(self, vocab: IndustryVocab) -> None:
        """Replace the vocab (test seam - production code should not call this)."""
        self._vocab = vocab

    async def route(
        self,
        domain: str,
        cache: ConcurrentFetchCache,
        *,
        homepage_url: str | None = None,
        budget_ms: int = DEFAULT_BUDGET_MS,
    ) -> RoutingConfig:
        """Fetch *domain*'s homepage via *cache* and return a routing config.

        Parameters
        ----------
        domain:
            Bare host (``"example.com"``) used to derive the default
            homepage URL.  Ignored if *homepage_url* is supplied.
        cache:
            The run-scoped :class:`ConcurrentFetchCache`.  Required -
            the router does not own a transport.
        homepage_url:
            Override for the URL to fetch.  Useful when probing an
            internal staging path or a single-page-app shell URL.
        budget_ms:
            Reserved for future enforcement of the SLO via
            ``asyncio.wait_for`` once the cache contract supports it.
            The router always reports the actual ``elapsed_ms`` on the
            returned :class:`RoutingConfig` regardless.
        """
        # Reference ``budget_ms`` so ruff doesn't complain about an
        # unused parameter while keeping the public signature stable
        # for the eventual timeout enforcement.
        del budget_ms

        start = time.perf_counter()
        url = homepage_url or _homepage_url_for(domain)

        try:
            response = await cache.get(url)
        except Exception as exc:  # noqa: BLE001 - never raise from route()
            _LOG.warning("ContextRouter: homepage fetch failed (%s)", exc)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            empty_tech = TechFlags()
            return build_routing_config(
                empty_tech,
                (),
                self._vocab,
                homepage_status=None,
                elapsed_ms=elapsed_ms,
            )

        status = response.status_code
        # Non-2xx pass-through (per ConcurrentFetchCache contract, only
        # 2xx responses are stored).  We still record the status so the
        # caller can distinguish "down" from "200 with no fingerprints".
        if status < 200 or status >= 300:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return build_routing_config(
                TechFlags(),
                (),
                self._vocab,
                homepage_status=status,
                elapsed_ms=elapsed_ms,
            )

        tech = analyze_tech(response.text)
        industries = analyze_industry(response.text, self._vocab)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return build_routing_config(
            tech,
            industries,
            self._vocab,
            homepage_status=status,
            elapsed_ms=elapsed_ms,
        )


def _homepage_url_for(domain: str) -> str:
    """Build an ``https://<domain>/`` URL from a bare host.

    Trims whitespace and a single trailing slash; does **not** try to
    validate that ``domain`` is a syntactically well-formed hostname -
    the cache + StealthSession will surface that as a fetch failure
    which ``route()`` already handles gracefully.
    """
    cleaned = domain.strip()
    while cleaned.endswith("/"):
        cleaned = cleaned[:-1]
    if not cleaned:
        cleaned = "localhost"
    if "://" not in cleaned:
        return f"https://{cleaned}/"
    return cleaned


__all__ = [
    "DEFAULT_BUDGET_MS",
    "ContextRouter",
    "IndustryVocab",
    "IndustryVocabularyResult",
    "IndustryVocabularyRouter",
    "RoutingConfig",
    "TechFlags",
    "analyze_industry",
    "analyze_tech",
    "build_routing_config",
    "load_industry_vocab",
    "reset_vocab_cache",
]
