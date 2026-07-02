"""Pre-filter for raw extracted name strings.

Different from :mod:`backend.core.name_consensus` (which scores
candidates *for a specific email* with source weighting) — this
module scores raw extracted strings for "is this even a person name"
*before* they enter the consensus pipeline.  Cheap, deterministic,
no NLP.  Returns ``True`` only for strings that pass a basic structural
check (capitalisation, token count, no digits, not in the navigation/
footer stoplist).

The pattern validation is borrowed from ``name_consensus.PERSON_RE``
(which itself is Unicode-aware across Latin / Cyrillic / Arabic /
CJK / Devanagari scripts).  We intentionally *don't* import
``name_consensus`` here to keep this cheap module loadable from hot
paths without dragging in rapidfuzz / unidecode.
"""

from __future__ import annotations

import re

# ----------------------------------------------------------------------
# Validation patterns
# ----------------------------------------------------------------------
# Latin token: capital first, AT LEAST ONE lowercase (incl.
# diacritics in Latin-1 Supplement and Latin Extended Additional)
# trailing.  Rejects single-letter "Y" tokens and all-caps strings
# like "JOHN SMITH" while accepting "José", "François", "Łukasz",
# "O'Brien" (apostrophe in body), "Mary-Jane" (hyphen).
_LOWER_LATIN = r"[a-z\u00E0-\u024F\u1E00-\u1EFF]"
_LATIN_TOKEN = (
    rf"[A-Z\u00C0-\u024F\u1E00-\u1EFF]"
    rf"[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF''\-]*{_LOWER_LATIN}[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF''\-]*"
)
# Non-Latin alphabetic runs: Cyrillic, Arabic, CJK, Devanagari.
_NONLATIN_TOKEN = r"[Ѐ-ӿ؀-ۿ一-鿿ऀ-ॿ]+"

# Two separate top-level patterns because Latin tokens require
# whitespace between them (real names), while non-Latin runs (e.g.
# Japanese / Chinese / Korean) frequently arrive space-less.
_LATIN_PERSON_RE = re.compile(
    rf"^{_LATIN_TOKEN}(?:\s+{_LATIN_TOKEN}){{1,3}}$",
    re.UNICODE,
)
# Non-Latin allows whitespace-less runs so "王小明" / "山田太郎"
# survive.  We additionally require at least one non-Latin letter
# in :func:`is_plausible_person_name` before accepting the hit, so
# this pattern alone is necessary-but-not-sufficient.
_NONLATIN_PERSON_RE = re.compile(
    rf"^{_NONLATIN_TOKEN}(?:\s?{_NONLATIN_TOKEN}){{1,3}}$",
    re.UNICODE,
)

# Backward-compatible alias — older callers import ``_PERSON_RE``.
_PERSON_RE = _LATIN_PERSON_RE

# Common nav / footer / placeholder text.  Lower-cased comparison.
_NAV_FOOTER_STOPLIST: frozenset[str] = frozenset(
    {
        "privacy policy",
        "terms of service",
        "terms of use",
        "cookie policy",
        "contact us",
        "about us",
        "learn more",
        "read more",
        "sign up",
        "sign in",
        "log in",
        "log out",
        "all rights reserved",
        "site map",
        "follow us",
        "get started",
        "view profile",
        "view all",
        "see more",
        "load more",
        "next page",
        "previous page",
        "join us",
        "our team",
        "our company",
        "open menu",
        "close menu",
        "menu",
        "search",
        "subscribe",
        "newsletter",
        "skip to content",
        "skip to main",
    }
)

# A short list of words that, when they appear as a *token* in a candidate
# string, almost certainly indicate a job-title or nav label rather than
# a person.  Used by :func:`is_plausible_person_name` to reject strings like
# "Chief Executive Officer Jane" or "Home About Team Privacy".
_ROLE_WORDS: frozenset[str] = frozenset(
    {
        # Common job titles that show up in company about pages.
        "chief",
        "officer",
        "executive",
        "director",
        "senior",
        "junior",
        "lead",
        "head",
        "manager",
        "engineer",
        "developer",
        "designer",
        "analyst",
        "consultant",
        "marketing",
        "sales",
        "operations",
        "product",
        "project",
        "program",
        "account",
        "people",
        "human",
        "resources",
        "administrative",
        "technology",
        "technical",
        "founder",
        "co-founder",
        "cofounder",
        "ceo",
        "cto",
        "cfo",
        "coo",
        "cmo",
        "vp",
        "svp",
        "evp",
    }
)

# Same idea — when the *entire input string* matches one of these words,
# it cannot be a person name.
_NON_NAME_WORDS: frozenset[str] = frozenset(
    {
        "home",
        "about",
        "team",
        "our",
        "people",
        "leadership",
        "staff",
        "board",
        "careers",
        "jobs",
        "press",
        "contact",
        "company",
        "blog",
        "news",
        "legal",
        "privacy",
        "policy",
        "support",
        "help",
        "login",
        "signup",
        "join",
        "menu",
        "search",
        "language",
        "english",
        "french",
        "spanish",
        "german",
        "italian",
        "portuguese",
        "chinese",
        "japanese",
        "korean",
        "russian",
        "arabic",
        "hindi",
        # Footer / legalese phrases that often appear title-cased.
        "rights",
        "reserved",
        "all",
        "and",
        "or",
        "the",
        "reserved",
        "copyright",
        "policy",
        "cookies",
        "terms",
        "conditions",
        "subscribe",
        "unsubscribe",
        "follow",
        "share",
    }
)


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def is_plausible_person_name(text: str) -> bool:
    """Cheap pre-filter for raw extracted name strings.

    Returns ``True`` only for strings that look like a real person's
    display name: 2–4 capitalised tokens, no digits, total length
    4–50, not in the stoplist, not equal to a known non-name word.
    """
    if not isinstance(text, str):
        return False

    cleaned = text.strip()
    if not cleaned:
        return False
    # Length floor of 2 — single-character tokens are too noise-prone
    # but valid CJK family-name-only names (e.g. "李") and Latin
    # "Ed Lee" survive.  Latin-only names additionally need 4 chars
    # to pass the Latin path's structural check below; non-Latin
    # paths accept the shorter ground floor.
    if len(cleaned) < 2 or len(cleaned) > 50:
        return False

    # Reject digits explicitly — JS/CSS noise slips through with
    # numeric suffix, and "1.2.3 Name" patterns from build artifacts
    # are common in HTML dumps.
    if any(ch.isdigit() for ch in cleaned):
        return False

    lower = cleaned.lower()
    if lower in _NAV_FOOTER_STOPLIST:
        return False

    # Single non-name word like "Home" / "Team" / "Leadership".
    if lower in _NON_NAME_WORDS:
        return False

    # Two complementary paths — Latin (requires whitespace) and
    # non-Latin (CJK allows whitespace-less runs).  The non-Latin
    # path is the only way "王小明" without spaces can pass; mixed
    # strings ("John 王小明") correctly fall through both.
    if _LATIN_PERSON_RE.match(cleaned):
        # Reject Latin candidates whose first token is a known
        # job-title / nav word — these are typically title strings
        # ("Chief Executive Officer"), category labels ("Home About
        # Team"), or pure navigation text.  Real person names
        # overwhelmingly start with a first name.
        tokens = [t for t in cleaned.split() if t]
        if tokens:
            first = tokens[0].lower().strip(".,;:'-")
            if first in _ROLE_WORDS or first in _NON_NAME_WORDS:
                return False
        return True
    if _NONLATIN_PERSON_RE.match(cleaned):
        # Reject mixed scripts by checking there's at least one
        # alphabetic non-Latin character, and the alphabetic content
        # is *only* non-Latin (so we don't conflate "Joseph 王" with
        # a pure CJK name).
        has_latin = False
        has_non_latin_alpha = False
        for ch in cleaned:
            if ch.isspace():
                continue
            if ch.isalpha():
                if (
                    "A" <= ch <= "Z"
                    or "a" <= ch <= "z"
                    or "À" <= ch <= "ɏ"
                    or "Ḁ" <= ch <= "ỿ"
                ):
                    has_latin = True
                else:
                    has_non_latin_alpha = True
        return has_non_latin_alpha and not has_latin

    return False


def dedupe_names(names: list[str]) -> list[str]:
    """Case-insensitive dedup, prefer the longest canonical form.

    "John Smith" / "john  smith" / "JOHN SMITH" all collapse to
    "John Smith" (the longest input wins, but length is the tiebreaker
    only after exact case-insensitive equality).

    We deliberately don't do fuzzy / token-set matching here — that
    complexity belongs to :mod:`backend.core.name_consensus`.  This is a
    cheap pre-aggregation filter only.
    """
    canonical: dict[str, str] = {}
    order: list[str] = []
    for raw in names:
        if not isinstance(raw, str):
            continue
        cleaned = re.sub(r"\s+", " ", raw.strip())
        if not cleaned:
            continue
        key = cleaned.lower()
        if key not in canonical:
            canonical[key] = cleaned
            order.append(key)
        else:
            existing = canonical[key]
            # Prefer the longer / better-formed form.
            if len(cleaned) > len(existing):
                canonical[key] = cleaned

    return [canonical[key] for key in order]


def matches_domain(text: str, domain: str) -> bool:
    """Return True when *text* is identical to *domain* or its registrable part.

    Used by callers to drop names like "Acme" / "acme com" that are
    just the company/domain appearing in the title field of a
    LinkedIn result.
    """
    if not isinstance(text, str) or not isinstance(domain, str):
        return False
    cleaned = text.strip().lower()
    domain_clean = domain.strip().lower()
    if not cleaned or not domain_clean:
        return False
    if cleaned == domain_clean:
        return True
    # Strip TLD and re-check.
    parts = domain_clean.rsplit(".", 1)
    registrable = parts[0] if len(parts) == 2 else domain_clean
    return cleaned == registrable
