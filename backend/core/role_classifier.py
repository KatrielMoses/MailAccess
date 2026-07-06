"""Role / system account classifier.

Classifies an email's local-part as a role/system account vs. a
likely-personal account. Used by the Common Crawl module today and
every future domain-harvest module tomorrow.

A *role* email is one shared by multiple humans (sales@, info@,
postmaster@, ...) or operated by automation (noreply@, bounce@, ...).
We never want to ping-pong sales pitches at ``info@example.com`` - the
classifier tags these so downstream code can suppress notifications
and lower the contact-confidence cap.

Three match tiers, in priority order:

* exact          - the local-part is a known role prefix -> confidence 0.95
* prefix         - local-part starts with a role prefix + separator
                   (``support.team`` / ``info-uk``)        -> 0.80
* partial        - local-part CONTAINS a role prefix as a whole-word
                   segment (``john.support``)              -> 0.40
* none           - nothing matched                          -> 0.00 (likely personal)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

_LOG = logging.getLogger(__name__)

_CORPUS_PATH = Path(__file__).resolve().parents[2] / "data" / "role_prefixes.json"
_ROLE_PREFIXES: frozenset[str] | None = None
_SEPARATOR_RE = re.compile(r"[.\-_+]+")

_EXACT_RE: re.Pattern[str] | None = None
_PREFIX_RE: re.Pattern[str] | None = None
_PARTIAL_RE: re.Pattern[str] | None = None
_PREFIX_START_RE: re.Pattern[str] | None = None


@dataclass
class RoleClassification:
    is_role: bool
    confidence: float
    match_type: str  # "exact" | "prefix" | "partial" | "none"
    matched_prefix: str | None


def _load_corpus() -> frozenset[str]:
    """Read the role corpus and return a normalized frozenset of prefixes."""
    try:
        payload = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        _LOG.warning(
            "role_prefixes.json missing or malformed; "
            "role classifier returns no role matches"
        )
        return frozenset()

    if not isinstance(payload, dict):
        return frozenset()

    categories = payload.get("categories")
    if not isinstance(categories, dict):
        return frozenset()

    prefixes: set[str] = set()
    for items in categories.values():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, str) and item.strip():
                prefixes.add(item.strip().lower())

    return frozenset(prefixes)


def _ensure_loaded() -> frozenset[str]:
    global _ROLE_PREFIXES, _EXACT_RE, _PREFIX_RE, _PARTIAL_RE
    if _ROLE_PREFIXES is not None:
        return _ROLE_PREFIXES

    _ROLE_PREFIXES = _load_corpus()
    sorted_prefixes = sorted(_ROLE_PREFIXES, key=len, reverse=True)
    if sorted_prefixes:
        joined = "|".join(re.escape(p) for p in sorted_prefixes)
        _EXACT_RE = re.compile(rf"^(?:{joined})$")
        _PREFIX_RE = re.compile(rf"^(?:{joined})(?=[.\-_+]|$)")
    return _ROLE_PREFIXES


def _ensure_partial_regex() -> re.Pattern[str] | None:
    """Build the partial regex lazily (depends on corpus contents)."""
    global _PARTIAL_RE
    if _PARTIAL_RE is not None:
        return _PARTIAL_RE
    corpus = _ensure_loaded()
    if not corpus:
        return None
    sorted_prefixes = sorted(corpus, key=len, reverse=True)
    joined = "|".join(re.escape(p) for p in sorted_prefixes)
    _PARTIAL_RE = re.compile(rf"(?<![a-z0-9])(?:{joined})(?![a-z0-9])")
    return _PARTIAL_RE


def _ensure_prefix_start_regex() -> re.Pattern[str] | None:
    """Build the prefix-at-start regex lazily."""
    global _PREFIX_START_RE
    if _PREFIX_START_RE is not None:
        return _PREFIX_START_RE
    corpus = _ensure_loaded()
    if not corpus:
        return None
    sorted_prefixes = sorted(corpus, key=len, reverse=True)
    joined = "|".join(re.escape(p) for p in sorted_prefixes)
    _PREFIX_START_RE = re.compile(rf"^(?:{joined})")
    return _PREFIX_START_RE


def is_role_email(email: str) -> bool:
    """Convenience predicate: ``True`` iff *email* matches a known role prefix."""
    return classify_email(email).is_role


def classify_email(email: str) -> RoleClassification:
    """Classify *email* as a role account or likely-personal account.

    Parameters
    ----------
    email:
        A string of the form ``local@domain``. Anything more complex
        (multiple ``@``, blanks, None) is treated as not a role.
    """
    if not isinstance(email, str):
        return RoleClassification(False, 0.0, "none", None)

    value = email.strip().lower()
    if "@" not in value:
        return RoleClassification(False, 0.0, "none", None)

    local, _, _ = value.partition("@")
    if not local:
        return RoleClassification(False, 0.0, "none", None)

    corpus = _ensure_loaded()
    if not corpus:
        return RoleClassification(False, 0.0, "none", None)

    # Tier 1: exact match.
    if _EXACT_RE is not None and _EXACT_RE.match(local):
        matched = _matched_prefix(local)
        return RoleClassification(True, 0.95, "exact", matched)

    # Tier 2: prefix match - local-part starts with a role prefix and
    # is followed by a separator character.
    if _PREFIX_RE is not None:
        m = _PREFIX_RE.match(local)
        if m:
            return RoleClassification(True, 0.80, "prefix", m.group(0))

    # Tier 3a: prefix-at-start with non-separator continuation.
    prefix_start = _ensure_prefix_start_regex()
    if prefix_start is not None:
        m = prefix_start.match(local)
        if m and len(local) > m.end():
            matched_prefix = m.group(0)
            if len(matched_prefix) >= 4:
                return RoleClassification(True, 0.40, "partial", matched_prefix)

    # Tier 3b: partial match - segment-based hit.
    segments = [seg for seg in _SEPARATOR_RE.split(local) if seg]
    if len(segments) >= 2:
        for segment in segments:
            if segment in corpus:
                if len(segment) < 4:
                    continue
                return RoleClassification(True, 0.40, "partial", segment)

    # Tier 3c: regex fallback.
    partial = _ensure_partial_regex()
    if partial is not None:
        m = partial.search(local)
        if m:
            matched_prefix = m.group(0)
            if len(matched_prefix) < 4:
                return RoleClassification(False, 0.0, "none", None)
            return RoleClassification(True, 0.40, "partial", matched_prefix)

    return RoleClassification(False, 0.0, "none", None)


def _matched_prefix(local: str) -> str:
    """Return the longest matched role prefix for *local* (used in tests)."""
    corpus = _ensure_loaded()
    if not corpus:
        return ""
    matches = sorted(c for c in corpus if local == c)
    if matches:
        return matches[0]
    for candidate in sorted(corpus, key=len, reverse=True):
        if candidate in local:
            return candidate
    return ""


def reset_for_tests() -> None:
    """Drop cached regexes & corpus (test-only)."""
    global _ROLE_PREFIXES, _EXACT_RE, _PREFIX_RE, _PARTIAL_RE, _PREFIX_START_RE
    _ROLE_PREFIXES = None
    _EXACT_RE = None
    _PREFIX_RE = None
    _PARTIAL_RE = None
    _PREFIX_START_RE = None


def set_corpus_for_tests(prefixes: set[str]) -> None:
    """Replace the in-memory corpus - for test isolation only."""
    global _ROLE_PREFIXES, _EXACT_RE, _PREFIX_RE, _PARTIAL_RE, _PREFIX_START_RE
    _ROLE_PREFIXES = frozenset(prefixes)
    _EXACT_RE = None
    _PREFIX_RE = None
    _PARTIAL_RE = None
    _PREFIX_START_RE = None


def corpus_size() -> int:
    """Return number of role prefixes currently loaded (for introspection)."""
    corpus = _ensure_loaded()
    return len(corpus)
