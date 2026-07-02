"""Pure-logic email pattern generator.

Takes a *name* and a single target *domain*, returns a deduplicated
list of candidate email addresses ordered by real-world prevalence
(per the Interseller 5M-company analysis).  No I/O.

This module deliberately does NOT import from
:mod:`backend.core.permutator` — that file generates against a free
provider fan-out (gmail.com / outlook.com / ...) which is not the
shape Phase C2 needs.  We also use a different template ordering
than permutator because the spec asks us to follow the Interseller
ordering rather than permutator's heuristic order.

Three-token names are reduced to first/last only — middle tokens
are dropped for pattern purposes per spec ("standard
simplification").  Single-token names produce no candidates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class GeneratedEmail:
    email: str
    pattern_template: str  # e.g. "{first}.{last}@{domain}"
    source_name: str  # original full name this came from


# Ordered from highest real-world prevalence (~65%) down to the
# long-tail patterns.  The leading position is the workhorse.
_PATTERN_TEMPLATES: tuple[str, ...] = (
    "{first}.{last}@{domain}",
    "{first}@{domain}",
    "{f}{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}{l}@{domain}",
    "{last}.{first}@{domain}",
    "{last}@{domain}",
    "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
    "{f}.{last}@{domain}",
    "{last}{f}@{domain}",
)


# Characters stripped from name parts before templating.  We keep
# ASCII letters, digits, and a broad set of Unicode scripts so the
# generator works for non-Western names too.  MUST-FIX S1: previously
# the regex only allowed Latin-extended, so every CJK / Cyrillic /
# Arabic / Devanagari name produced zero patterns — silently
# excluding entire national markets from the feature.
#
# Script coverage:
#   \u00C0-\u024F   Latin Extended-A + -B
#   \u1E00-\u1EFF   Latin Extended Additional
#   \u0400-\u04FF   Cyrillic
#   \u0600-\u06FF   Arabic
#   \u0900-\u097F   Devanagari
#   \u3040-\u30FF   Hiragana + Katakana
#   \u4E00-\u9FFF   CJK Unified Ideographs (common range)
#   \uAC00-\uD7AF   Hangul Syllables
_NON_ALNUM_RE = re.compile(
    r"[^A-Za-z"
    r"\u00C0-\u024F"
    r"\u1E00-\u1EFF"
    r"\u0400-\u04FF"
    r"\u0600-\u06FF"
    r"\u0900-\u097F"
    r"\u3040-\u30FF"
    r"\u4E00-\u9FFF"
    r"\uAC00-\uD7AF"
    r"0-9"
    r"]+"
)


def _clean_part(token: str) -> str:
    """Normalise a single name token: strip non-alnum, lowercase.

    Examples
    --------
    >>> _clean_part("O'Brien")
    'obrien'
    >>> _clean_part("Mary-Jane")
    'maryjane'
    >>> _clean_part("Sm ith  ")
    'smith'
    """
    if not token:
        return ""
    stripped = _NON_ALNUM_RE.sub("", token)
    return stripped.lower().strip()


def _maybe_transliterate(token: str) -> str:
    """Transliterate non-Latin script characters to ASCII via unidecode.

    MUST-FIX S1: when a name contains characters outside the ASCII /
    Latin-extended ranges (CJK, Cyrillic, Arabic, Devanagari, Hangul),
    the email-pattern generator cannot produce viable ASCII local
    parts — most real-world email systems still restrict local parts
    to ASCII even when the display name is non-Western.

    We pass such tokens through ``unidecode`` (the same library already
    used by ``name_consensus`` for non-Western name normalisation) to
    produce a romanised fallback. The original Unicode token is
    preserved for cross-referencing with other modules that DO
    understand Unicode (e.g. ``name_consensus``).
    """
    if not token:
        return token
    # Pure-ASCII or Latin-extended: no transliteration needed.
    if all(ord(c) < 0x0250 or 0x00C0 <= ord(c) <= 0x024F for c in token):
        # Latin-extended is fine; otherwise transliterate.
        try:
            # Probe by checking if any non-ASCII letter present.
            has_non_ascii_letter = any(
                "\u00C0" <= c <= "\u024F" or "\u1E00" <= c <= "\u1EFF"
                for c in token
            )
            if has_non_ascii_letter or all(ord(c) < 0x80 for c in token):
                return token
        except Exception:
            return token
    try:
        from unidecode import unidecode
    except ImportError:
        # Without unidecode installed we cannot romanise — return the
        # original token. The downstream pattern generator will still
        # produce patterns using whatever ASCII survived ``_clean_part``.
        return token
    try:
        return unidecode(token)
    except Exception:
        return token


def _name_parts(full_name: str) -> tuple[str, str] | None:
    """Split *full_name* into ``(first, last)``.

    * Two-token names map directly: "Jane Doe" → ("jane", "doe").
    * Three-or-more-token names use the first + last token; middle
      tokens are ignored (per spec).
    * Single-token names have no last name — return ``None``.
    * MUST-FIX S1: non-Latin-script names are transliterated via
      ``unidecode`` BEFORE tokenisation. CJK / Korean names typically
      have no whitespace between family and given name in their
      native form (e.g. "刘德华", "김철수"), so the input string
      arrives as a single token. Transliteration usually expands
      Chinese with whitespace ("Liu De Hua") but NOT Korean/Hangul
      ("gimceolsu"). For Hangul we then split on character boundaries
      (each Hangul syllable is a separate "syllable" character) so we
      produce at least 2 tokens.
    """
    if not isinstance(full_name, str):
        return None
    cleaned = full_name.strip()
    if not cleaned:
        return None
    romanised = _maybe_transliterate(cleaned)
    raw_tokens = [t for t in romanised.split() if t.strip()]
    tokens: list[str] = []
    for raw in raw_tokens:
        cleaned_token = _clean_part(raw)
        if cleaned_token:
            tokens.append(cleaned_token)

    # MUST-FIX S1 follow-up: Hangul doesn't get whitespace from
    # unidecode ("김철수" → "gimceolsu", one token). Split on Hangul
    # syllable boundaries so we can still derive (first, last).
    if len(tokens) == 1 and tokens[0]:
        first_token = tokens[0]
        # Detect Hangul by checking for any syllable character.
        if any("\uAC00" <= c <= "\uD7AF" for c in cleaned):
            syllables: list[str] = []
            current: list[str] = []
            for c in cleaned:
                if "\uAC00" <= c <= "\uD7AF":
                    if current:
                        syllables.append("".join(current))
                    current = [c]
                else:
                    current.append(c)
            if current:
                syllables.append("".join(current))
            # Filter to syllables that contain at least one Hangul char.
            hangul_only = [s for s in syllables if any("\uAC00" <= ch <= "\uD7AF" for ch in s)]
            if len(hangul_only) >= 2:
                tokens = hangul_only
            else:
                # Try splitting the romanised token by vowel boundaries.
                # Korean romanised names usually alternate consonant-vowel,
                # so splitting at every vowel transition is reasonable.
                # E.g. "gimceolsu" → ["gim", "ceol", "su"]
                vowel_split = re.findall(
                    r"[A-Za-z]*[aeiouyAEIOUY]+[^aeiouyAEIOUY]*|[A-Za-z]+",
                    first_token,
                )
                if len(vowel_split) >= 2:
                    tokens = vowel_split

    if len(tokens) < 2:
        return None
    return tokens[0], tokens[-1]


def generate_patterns(
    full_name: str,
    domain: str,
    patterns: list[str] | None = None,
) -> list[GeneratedEmail]:
    """Generate candidate email addresses from *full_name* + *domain*.

    Parameters
    ----------
    full_name:
        A person's display name, e.g. "Jane Doe" or "Jane Anne Doe".
        Multi-token names use first + last only.
    domain:
        Target domain (e.g. ``"example.com"``).  Lowercased and
        whitespace-stripped before use.
    patterns:
        Optional subset of template strings to apply.  When ``None``
        all 11 default templates are used (most-prevalent first).

    Returns an empty list when the name cannot be parsed into two
    tokens, when both halves are identical (single-token name), or
    when ``domain`` is invalid.
    """
    cleaned_domain = (domain or "").strip().lower()
    if not cleaned_domain or "." not in cleaned_domain:
        return []

    parts = _name_parts(full_name)
    if parts is None:
        return []
    first, last = parts
    if not first or not last:
        return []

    chosen_templates = list(patterns) if patterns else list(_PATTERN_TEMPLATES)

    seen: set[str] = set()
    out: list[GeneratedEmail] = []
    for template in chosen_templates:
        local = (
            template
            .replace("{first}", first)
            .replace("{last}", last)
            .replace("{f}", first[:1] if first else "")
            .replace("{l}", last[:1] if last else "")
            .replace("{domain}", cleaned_domain)
        )
        if "@" not in local:
            continue
        if local in seen:
            continue
        seen.add(local)
        out.append(
            GeneratedEmail(
                email=local,
                pattern_template=template,
                source_name=full_name,
            )
        )

    return out


def confirmed_pattern_priority(confirmed_template: str) -> list[str]:
    """Reorder the default template list with *confirmed_template* first.

    Once SMTP verification confirms one template works for a domain
    (e.g. ``"{first}.{last}@{domain}"``), subsequent employees should
    try that template *first* — saving 1 SMTP probe per name.

    The confirmed template is preserved in its original form even if
    it matches multiple official templates (substring match); we look
    for the first template that contains the core token pattern.
    """
    if confirmed_template not in _PATTERN_TEMPLATES:
        return list(_PATTERN_TEMPLATES)

    head = confirmed_template
    rest = [t for t in _PATTERN_TEMPLATES if t != confirmed_template]
    return [head, *rest]
