"""Canonical-name and canonical-slug/email normalization for AsyncSignalPool.

Pure stdlib. Independent from :mod:`backend.core.name_consensus` so the
orchestration spine can be deployed without the Phase 2C engine on the
import graph (the latter has a heavier dependency surface via
``rapidfuzz`` + ``unidecode``).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

#: Honorifics and name suffixes that are stripped during normalization.  Both
#: leading (e.g. ``"Dr. Jane Doe"``) and trailing (``"Jane Doe Jr."``) variants
#: are handled.  Stored as lowercase tokens compared against per-token
#: matches.  Keys are matched on whole-token basis; partial matches such as
#: ``"old"`` inside ``"oldfield"`` are intentionally preserved.
_HONORIFICS: Final[frozenset[str]] = frozenset(
    {
        # English / Western
        "mr",
        "mrs",
        "ms",
        "miss",
        "mx",
        "sir",
        "madam",
        "ma'am",
        # Academic / professional titles — treated as honorifics in OSINT
        # contexts because we want "Dr Jane Doe" to cluster with
        # "Jane Doe".
        "dr",
        "prof",
        "professor",
        "rev",
        "reverend",
        # Generational / nobility
        "jr",
        "junior",
        "sr",
        "senior",
        "ii",
        "iii",
        "iv",
        "v",
        "vi",
        "vii",
        "viii",
        "esq",
        # PhD / MD / academic post-nominals
        "phd",
        "md",
        "do",
        "dds",
        "jd",
        "ba",
        "bs",
        "msc",
        "ma",
    }
)

#: Strip punctuation that may appear between tokens (commas, semicolons,
#: slashes, hyphens used as separators).
_PUNCT_RE: Final[re.Pattern[str]] = re.compile(r"[\s,;/\u2013\u2014\\]+")
#: Slug/email normalization collapses separators and drops alnum noise.
_SLUG_SEPARATORS_RE: Final[re.Pattern[str]] = re.compile(r"[._\-+]+")


def _strip_token_edges(token: str) -> str:
    """Trim leading/trailing punctuation from *token*.

    Uses :func:`unicodedata.category` so non-ASCII letters such as
    ``"Ł"``, ``"ñ"``, ``"张"`` survive — only proper punctuation
    (``Pc/Pd/Pe/Pf/Po``), whitespace (``Z*``), and control/format
    characters (``Cc/Cf``) are stripped.
    """
    if not token:
        return token
    chars = list(token)
    start = 0
    end = len(chars)
    while start < end and _is_trim_char(chars[start]):
        start += 1
    while end > start and _is_trim_char(chars[end - 1]):
        end -= 1
    return "".join(chars[start:end])


def _is_trim_char(ch: str) -> bool:
    cat = unicodedata.category(ch)
    # Punctuation (Pc/Pd/Pe/Pf/Po), whitespace (Zs/Zl/Zp + control C*),
    # plus a curated set of stray characters we want stripped.
    if cat.startswith("P") or cat.startswith("Z") or cat.startswith("C"):
        return True
    if cat.startswith("L") or cat.startswith("N"):
        return False
    # Symbol/format categories — strip.
    return True


def normalize_name(raw: object) -> str:
    """Return a canonical form of *raw* suitable for use as a cluster key.

    Pipeline:

    1. ``None`` or non-string input -> empty string.
    2. ``unicodedata.normalize("NFKC", ...)`` to fold compatibility glyphs.
    3. Strip diacritics via :func:`_strip_diacritics` so ``"François"``
       and ``"Francois"`` share the same key.
    4. Lowercase.
    5. Strip leading and trailing honorific tokens (matched on the
       ``_HONORIFICS`` allowlist).
    6. Collapse internal whitespace and drop short tokens.  A leading or
       trailing apostrophe / period is trimmed per-token.

    Returns ``""`` when nothing remains.  Callers that need a
    ``None`` sentinel should compare against the empty string and reject
    it themselves; this keeps the function total.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    text = unicodedata.normalize("NFKC", raw)
    text = _strip_diacritics(text).lower()
    # Replace punctuation with whitespace before tokenising so a comma-only
    # token drops, not a single character (which is non-empty but useless).
    text = _PUNCT_RE.sub(" ", text)
    tokens = [t for t in text.split(" ") if t]
    cleaned: list[str] = []
    for token in tokens:
        token = _strip_token_edges(token)
        if not token:
            continue
        if token in _HONORIFICS and not cleaned:
            # Leading honorific — discard and continue.
            continue
        cleaned.append(token)
        if token in _HONORIFICS and len(cleaned) == 1:
            # Only thing we have so far is another honorific; allow the
            # loop to keep scanning but don't keep it.
            cleaned.pop()
            continue
    # Trailing honorifics / suffixes.
    while cleaned and cleaned[-1] in _HONORIFICS:
        cleaned.pop()
    return " ".join(cleaned)


def normalize_slug_or_email(raw: object) -> str | None:
    """Return canonical slug/email suitable as a cluster key.

    Behaviour:

    - ``None`` / non-string -> ``None``.
    - Input containing ``@`` -> ``localpart.lower()``.  Domain is
      intentionally discarded; we are keying on person identity, and
      ``user@service.example`` is the same person as ``user@another``.
    - Input without ``@`` -> lowercase, separators collapsed, non-alnum
      stripped (preserves digit groups like ``"1985"``).
    - Empty after stripping -> ``None`` (never key on garbage).
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if "@" in text:
        local, _, _ = text.partition("@")
        local = local.strip().lower()
    else:
        local = text.lower()
    collapsed = _SLUG_SEPARATORS_RE.sub("", local)
    alnum = re.sub(r"[^a-z0-9]", "", collapsed)
    return alnum or None


def canonical_key(
    name: object,
    slug_or_email: object,
) -> tuple[str | None, str | None]:
    """Build the canonical cluster key for a candidate.

    Either side may be ``None``; findings that carry only a slug (no
    display name) or only a display name are legitimate.  The returned
    tuple preserves the order ``(name, slug_or_email)`` and is hashable,
    so callers can use it directly as a dict key.
    """
    norm_name = normalize_name(name) or None
    norm_slug = normalize_slug_or_email(slug_or_email)
    return (norm_name, norm_slug)


def _strip_diacritics(text: str) -> str:
    """Strip combining marks via NFD + filter — sans ``unidecode`` dep.

    ``unicodedata.normalize("NFD", ...)`` decomposes accented characters
    into a base letter + combining mark; dropping the combining category
    gives us ``"Muller"`` from ``"Müller"``.  Non-Latin scripts are
    preserved unchanged because they lack a precomposed letter-plus-mark
    sequence the same way Latin does; that is acceptable for OSINT
    clustering where mixed-script names are typically not cross-clustered
    anyway.
    """
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
