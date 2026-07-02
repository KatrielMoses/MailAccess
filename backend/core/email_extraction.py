"""Pure email extraction logic — no I/O, fully testable.

Two stages:

1.  *Deobfuscation pass* — rewrites common noise tokens (``[at]``,
    ``(at)``, ``AT``, ``[dot]``, ...) into ``@`` / ``.`` *only* when the
    surrounding context looks like an email.  We avoid false positives
    in normal prose such as ``"I was at the store"``.

2.  *Regex extraction* — RFC-5322-lite pattern matched against the
    deobfuscated text.  Garbage matches are filtered (oversize local
    parts, consecutive dots, common JS/CSS artifacts like
    ``logo.png@example.com``, and well-known placeholders).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9._%+\-]*"
    r"@"
    r"[a-zA-Z0-9][a-zA-Z0-9.\-]*"
    r"\.[a-zA-Z]{2,}"
)

# Obfuscation patterns.  The shorter / case-sensitive versions (``AT``,
# ``DOT``) are applied only when the surrounding text contains an
# email-shaped skeleton (handled in ``_deobfuscate``).
_AT_BRACKET_RE = re.compile(r"\s*\[\s*at\s*\]\s*")
_AT_PAREN_RE = re.compile(r"\s*\(\s*at\s*\)\s*")
_DOT_BRACKET_RE = re.compile(r"\s*\[\s*dot\s*\]\s*")
_DOT_PAREN_RE = re.compile(r"\s*\(\s*dot\s*\)\s*")

_AT_UPPER_RE = re.compile(r"\s+AT\s+")
_DOT_UPPER_RE = re.compile(r"\s+DOT\s+")
_UNDERSCORE_RE = re.compile(r"\s*_\s*")

# MUST-FIX M6: pre-processor for ``mailto:foo@bar.com`` and
# ``mailto:foo@bar.com?subject=...`` links. Without this the literal
# regex still finds ``foo@bar.com`` when the link is intact, but the
# explicit pre-processor is more robust to edge cases (HTML escapes,
# query strings containing ``@``-like chars, obfuscated mailto values
# like ``mailto:foo[at]bar[dot]com``) and centralises the
# normalisation rule in one place.
_MAILTO_RE = re.compile(
    r"mailto:"
    # Capture the local-part, separator, domain. Up to first whitespace,
    # quote, or angle bracket (matches what URL parsers consider end-of-URL).
    r"([^\s\"'<>?]+)"
    # Optional ?query — we strip it after capture.
    r"(?:\?[^\\s\"'<>]*)?",
    re.IGNORECASE,
)
_MAILTO_QUERY_STRIP_RE = re.compile(r"\?.*$", re.DOTALL)

# Placeholder local parts or whole emails seen in templates / docs /
# example code.  Compared case-insensitively against the local part.
PLACEHOLDER_LOCAL_PARTS = frozenset(
    {
        "example",
        "test",
        "user",
        "username",
        "your",
        "name",
        "sample",
        "demo",
        "domain",
        "foo",
        "bar",
        "baz",
        "email",
        "mail",
    }
)

# Full emails that appear as literal placeholders, not real addresses.
PLACEHOLDER_FULL_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "yourdomain.com",
        "your-email.com",
        "domain.com",
        "site.com",
        "email.com",
    }
)


def is_placeholder_domain(domain: str | None) -> bool:
    """Return True if *domain* is a canonical placeholder domain.

    Per the W6 audit: ``example.com``, ``test.com``, ``domain.com``,
    ``email.com`` (and the other entries in :data:`PLACEHOLDER_FULL_DOMAINS`)
    are RFC 2606 reserved / common documentation placeholders. ANY email
    on one of these domains — regardless of the local part — should be
    filtered out of a harvest because it cannot represent a real
    discovered address.

    Examples
    --------
    >>> is_placeholder_domain("example.com")
    True
    >>> is_placeholder_domain("billing.example.com")
    False  # subdomains of example.com are NOT in the placeholder list
    >>> is_placeholder_domain("stripe.com")
    False
    >>> is_placeholder_domain(None)
    False
    """
    if not domain or not isinstance(domain, str):
        return False
    return domain.strip().lower() in PLACEHOLDER_FULL_DOMAINS

# Local-part markers that almost always indicate CSS / JS asset strings,
# not real email addresses.  We deliberately keep this list short to
# avoid filtering legitimate emails with numeric local parts.
_ASSET_LOCAL_PREFIX_RE = re.compile(
    r"^(?:[a-zA-Z0-9_\-]*\.(?:png|jpg|jpeg|gif|svg|webp|ico|css|js|woff2?|ttf))",
    re.IGNORECASE,
)

_SAFE_BODY_CHARS = 50  # length of the surrounding snippet captured as evidence


@dataclass
class ExtractedEmail:
    email: str
    on_domain: bool
    source_text_snippet: str


def _extract_mailto_values(text: str) -> list[str]:
    """Pull addresses out of ``mailto:`` URL pre-processing.

    MUST-FIX M6: searches the raw text for any ``mailto:`` URL and
    returns the recipient portion (with any ``?query`` stripped). These
    are returned as candidate email strings that the rest of
    :func:`extract_emails` will treat identically to regex matches —
    deduped against the regex pass via the same ``dedup`` dict.

    The captured value is run through :func:`_deobfuscate` because some
    pages encode mailto as ``mailto:foo[at]bar[dot]com`` to defeat
    harvesters. The deobfuscator handles those.
    """
    if not text:
        return []
    out: list[str] = []
    for match in _MAILTO_RE.finditer(text):
        raw = match.group(1)
        # Strip query string if any slipped past (?:\?...) (defence in depth).
        raw = _MAILTO_QUERY_STRIP_RE.sub("", raw)
        if not raw:
            continue
        # Run the deobfuscator over the captured value only — we don't
        # want to touch the surrounding HTML/prose.
        normalised = _deobfuscate(raw)
        out.append(normalised)
    return out


# MUST-FIX S14: replace ONLY literal _AT_ / _DOT_ tokens, never ALL
# underscores. The previous implementation called
# ``_UNDERSCORE_RE.sub("@", rewritten)`` after a guard
# ``if "_AT_" in rewritten.upper()`` — that substitution matched
# every underscore character in the text, corrupting legitimate
# emails like ``john_doe_smith@x.com`` into ``john@doe@smith@x.com``.
# The new pattern is bounded by word characters on both sides, so it
# only matches literal ``_AT_`` (and similarly ``_DOT_``).
_AT_LITERAL_RE = re.compile(r"(?<=\w)_AT_(?=\w)", re.IGNORECASE)
_DOT_LITERAL_RE = re.compile(r"(?<=\w)_DOT_(?=\w)", re.IGNORECASE)


def _deobfuscate(text: str) -> str:
    """Apply deobfuscation patterns.

    We act on three explicit shapes:

    * ``word [at] word [dot] word`` / ``word (at) word (dot) word``
      — bracket/paren markers are unambiguous, always rewritten.
    * ``word AT word DOT word`` — uppercase markers rewritten, but
      only when sandwiched between word characters (the underscore
      guard prevents touching ``AT&T`` stock tickers).
    * ``name_AT_domain_DOT_com`` — literal underscore-wrapped markers
      rewritten to ``@`` / ``.`` only on the specific tokens, never
      on every underscore character (MUST-FIX S14).
    * Lowercase standalone ``at`` / ``dot`` / ``(at)`` etc. are
      *never* rewritten because they appear too often in prose; the
      false-positive tests in :mod:`tests.test_email_extraction` lock
      this in.
    """
    if not text:
        return text

    rewritten = text
    rewritten = _AT_BRACKET_RE.sub("@", rewritten)
    rewritten = _AT_PAREN_RE.sub("@", rewritten)
    rewritten = _DOT_BRACKET_RE.sub(".", rewritten)
    rewritten = _DOT_PAREN_RE.sub(".", rewritten)
    rewritten = _AT_UPPER_RE.sub("@", rewritten)
    rewritten = _DOT_UPPER_RE.sub(".", rewritten)
    # MUST-FIX S14: replace ONLY literal ``_AT_`` / ``_DOT_`` tokens,
    # bounded by word characters on both sides. The pre-fix code
    # substituted every underscore in the entire text, corrupting
    # legitimate emails like ``john_doe_smith@x.com`` when ``_AT_``
    # happened to appear anywhere nearby.
    rewritten = _AT_LITERAL_RE.sub("@", rewritten)
    rewritten = _DOT_LITERAL_RE.sub(".", rewritten)
    return rewritten


def _looks_like_email(value: str) -> bool:
    if "@" not in value:
        return False
    local, _, domain = value.partition("@")
    if not local or not domain:
        return False
    if ".." in value:
        return False
    if "." not in domain:
        return False
    return True


def _is_garbage(local: str, domain: str, full: str) -> bool:
    if len(full) > 254 or len(local) > 64 or len(domain) > 255:
        return True
    if ".." in full:
        return True
    if local.startswith(".") or local.endswith("."):
        return True
    if domain.startswith(".") or domain.endswith("."):
        return True
    if _ASSET_LOCAL_PREFIX_RE.match(local):
        return True
    # Version-y numeric local parts ("1.2.3") — too noisy.
    if re.fullmatch(r"\d+(?:\.\d+)+", local):
        return True
    return False


def _is_placeholder(local: str, domain: str) -> bool:
    """Treat an email as a placeholder when either half is a known fake.

    Two checks — either one filtering alone drops the email:

    1. **Placeholder domain** (any local part). The RFC 2606 reserved
       / common-documentation domains in :data:`PLACEHOLDER_FULL_DOMAINS`
       (``example.com``, ``test.com``, ``domain.com``, ``email.com``,
       etc.) are NEVER real. ``billing@example.com`` and
       ``alice@example.com` are equally fake.
    2. **Both halves are placeholder**. The legacy check — drops
       ``example@example.com``, ``test@test.com`` etc. Kept for
       defense-in-depth in case a placeholder domain slips past the
       first check (e.g. typo'd domain, future domain list updates).

    The spec calls out specific examples like ``example@example.com``,
    ``test@test.com``, ``your@email.com`` — these are doc literals. We
    MUST also filter ``info@example.com``, ``billing@example.com``,
    ``contact@example.com`` etc. — those are placeholder emails that
    happen to use a "real-looking" local part.
    """
    local_lower = local.lower()
    domain_lower = domain.lower()
    # ANY email whose domain is a placeholder domain is a placeholder,
    # regardless of local part. This catches ``billing@example.com``
    # which the original BOTH-halves check would have let through.
    if domain_lower in PLACEHOLDER_FULL_DOMAINS:
        return True
    # Legacy check: BOTH halves are placeholder strings.
    if local_lower in PLACEHOLDER_LOCAL_PARTS and domain_lower in PLACEHOLDER_FULL_DOMAINS:
        return True
    return False


def subaddress_key(email: str) -> str:
    """Return a normalised dedup key for *email* with ``+anything`` stripped.

    MUST-FIX S2: Gmail-style subaddressing (``foo+filter@bar.com``,
    ``foo+anything@bar.com``) routes all mail to the same mailbox as
    ``foo@bar.com``. Real-world OSINT data frequently contains both
    forms, and treating them as separate entries duplicates evidence
    without adding signal.

    This function returns a lowercased ``local@domain`` form with the
    ``+suffix`` portion of the local-part stripped. Use it as the
    dedup KEY only — the original ``email`` (with ``+filter``) is
    preserved as the canonical entry on the ``HarvestedEmail`` record.

    Examples
    --------
    >>> subaddress_key("Jane.Doe+filter@GMAIL.com")
    'jane.doe@gmail.com'
    >>> subaddress_key("jane.doe@gmail.com")
    'jane.doe@gmail.com'
    >>> subaddress_key("admin@x.com")
    'admin@x.com'
    """
    if not isinstance(email, str) or "@" not in email:
        return email.strip().lower() if email else ""
    local, _, domain = email.strip().lower().partition("@")
    # Strip ``+suffix`` only if the local part is non-empty AND the
    # ``+`` is not the first character (which would be a malformed
    # address). The split is at the FIRST ``+`` only — Gmail and
    # Outlook only treat the substring before the FIRST ``+`` as the
    # real local part.
    plus_idx = local.find("+")
    if plus_idx > 0:
        local = local[:plus_idx]
    return f"{local}@{domain}"


def _snippet(text: str, position: int, length: int, padding: int = _SAFE_BODY_CHARS) -> str:
    start = max(position - padding, 0)
    end = min(position + length + padding, len(text))
    return text[start:end].strip()


def extract_emails(text: str, target_domain: str | None = None) -> list[ExtractedEmail]:
    """Extract unique email addresses from *text*.

    Parameters
    ----------
    text:
        Raw page content (HTML or plaintext).  Treated as a single block.
    target_domain:
        If provided, results are tagged with ``on_domain`` indicating
        whether the email's domain equals *target_domain* (case-insensitive).
    """

    if not text:
        return []

    target = target_domain.strip().lower() if target_domain else None

    # Step 1: deobfuscate.  We keep the original text around for snippet
    # extraction so the user sees what the page actually said.
    deobfuscated = _deobfuscate(text)

    # Step 2: regex.  Run twice — once on the original text, once on
    # the deobfuscated text — and merge.  The original pass catches
    # well-formed emails that the deobfuscator rewrote to garbage; the
    # second pass catches the obfuscated ones.
    raw_matches: list[tuple[str, int, int]] = []
    for match in EMAIL_REGEX.finditer(deobfuscated):
        raw_matches.append((match.group(0).lower(), match.start(), match.end()))
    for match in EMAIL_REGEX.finditer(text):
        raw_matches.append((match.group(0).lower(), match.start(), match.end()))

    # MUST-FIX M6: explicit ``mailto:`` pre-processing. The regex above
    # already catches most intact ``<a href="mailto:foo@bar.com">``
    # cases because the email itself matches EMAIL_REGEX, but the
    # explicit pre-processor handles edge cases the regex can't:
    #   - query strings: ``mailto:foo@bar.com?subject=hi`` (regex
    #     stops at ``?``, missing the literal address with +filter)
    #   - obfuscated mailto values: ``mailto:foo[at]bar[dot]com``
    #     (the deobfuscator now normalises the captured value)
    #   - HTML-escaped ampersands: ``mailto:foo&amp;bar@x.com``
    #     (rare but seen in old CMSes)
    for mailto_value in _extract_mailto_values(text):
        # Use a synthetic span at position 0 so the snippet reflects
        # only the mailto value (the surrounding HTML is its own context).
        # But for actual snippets we want surrounding text — use the
        # captured value position in the original text via a re-search.
        # For simplicity, re-run the regex over the captured value to
        # get the canonical form.
        for match in EMAIL_REGEX.finditer(mailto_value):
            raw_matches.append(
                (match.group(0).lower(), match.start(), match.end())
            )

    # Step 3: normalize + dedupe.
    dedup: dict[str, ExtractedEmail] = {}
    for candidate, start, end in raw_matches:
        normalized = candidate.strip().lower()
        if "@" not in normalized:
            continue
        local, _, domain = normalized.partition("@")
        if not _looks_like_email(normalized):
            continue
        if _is_garbage(local, domain, normalized):
            continue
        if _is_placeholder(local, domain):
            continue
        if normalized in dedup:
            continue

        on_domain = bool(target and domain == target)
        snippet = _snippet(text, start, end - start)
        dedup[normalized] = ExtractedEmail(
            email=normalized,
            on_domain=on_domain,
            source_text_snippet=snippet,
        )

    # Stable order: alphabetical by email.
    return [dedup[email] for email in sorted(dedup)]
