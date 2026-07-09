"""Pure Cloudflare email-obfuscation decoder.

Cloudflare's "Email Address Obfuscation" feature protects emails by
emitting them as ``<a class="__cf_email__" data-cfemail="...">[email&#160;protected]</a>``
(or with the attribute on a parent ``<span>`` / ``<strong>``). The value
of ``data-cfemail`` is a hex string: the first two characters are a key,
each subsequent pair is a hex-encoded byte XOR'd against that key.

Decoding is therefore:

    key       = int(encoded[:2], 16)
    decoded   = "".join(
        chr(int(encoded[i:i+2], 16) ^ key)
        for i in range(2, len(encoded), 2)
    )

MailAccess calls this on every fetched HTML page so the email-extraction
pass sees the actual address instead of the obfuscated form.  The
function is intentionally *pure* — no I/O, no globals, no logger.
Tests can call it synchronously on strings.

Used by:
    * ``backend.core.cc_page_fetcher`` — applied to WARC-decoded HTML.
    * ``backend.modules.wayback.harvest_domain_emails`` — applied to
      every archived page fetched via Wayback.
    * ``backend.core.company_page_names.discover_and_extract`` — the
      Phase 2 stub is replaced with a real import by this module.

The function never raises on malformed input — it returns the original
HTML untouched when a ``data-cfemail`` value cannot be decoded.
"""

from __future__ import annotations

import re

# The literal Cloudflare placeholder text, in the several entity-encoded
# forms we've observed in the wild.  The decoded email always replaces
# this text inside the obfuscated element.
_CF_PLACEHOLDER_RE = re.compile(
    r"\[email(?:\s|&nbsp;|&#160;|&#xA0;|&#xa0;)*protected\]",
    flags=re.IGNORECASE,
)

# Canonical Cloudflare <a class="__cf_email__" data-cfemail="...">...</a>
# capture.  Group 1 carries the hex payload.
_CF_EMAIL_SPAN_RE = re.compile(
    r'<a\b[^>]*\bclass\s*=\s*["\'][^"\']*\b__cf_email__\b[^"\']*["\']'
    r'[^>]*\bdata-cfemail\s*=\s*["\']([0-9a-fA-F]+)["\']'
    r"[^>]*>"
    r".*?"
    + _CF_PLACEHOLDER_RE.pattern
    + r"</a\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)

# Any element carrying data-cfemail.  Captures:
#   group("tag")  = element tag name (span/strong/...)
#   group("hex")  = the data-cfemail hex value
#   group("attrs_pre")  = attributes preceding data-cfemail
#   group("attrs_post") = attributes following data-cfemail
# The closing-tag pattern is reconstructed by the callback function
# (referencing the named group from inside the same pattern is fragile
# in stdlib ``re`` — easier to read tag name from match.group(0)).
_CF_FULL_RE = re.compile(
    r"<(?P<tag>[a-zA-Z][a-zA-Z0-9]*)\b"
    r"(?P<attrs_pre>[^>]*?)"
    r"\bdata-cfemail\s*=\s*"
    r'(?P<quote>["\'])'
    r"(?P<hex>[0-9a-fA-F]+)"
    r"(?P=quote)"
    r"(?P<attrs_post>[^>]*)>"
    + r".*?"
    + _CF_PLACEHOLDER_RE.pattern
    + r"(?P<close></[a-zA-Z][a-zA-Z0-9]*\s*>)",
    flags=re.IGNORECASE | re.DOTALL,
)


def _decode_value(encoded: str) -> str | None:
    """Decode a single ``data-cfemail`` hex payload.

    Returns the decoded string when at least one byte XORs cleanly,
    ``None`` when the payload is too short or contains non-hex chars.
    """
    if not encoded or len(encoded) < 4:
        return None
    head = encoded[:2]
    try:
        key = int(head, 16)
    except ValueError:
        return None
    body = encoded[2:]
    if len(body) % 2 != 0:
        return None
    out_chars: list[str] = []
    try:
        for i in range(0, len(body), 2):
            byte = int(body[i : i + 2], 16)
            out_chars.append(chr(byte ^ key))
    except ValueError:
        return None
    return "".join(out_chars)


def _decode_span(match: re.Match[str]) -> str:
    """Return the decoded email, replacing a canonical ``<a __cf_email__>`` pair."""
    encoded = match.group(1) or ""
    decoded = _decode_value(encoded)
    if not decoded:
        return match.group(0)
    return decoded


def _decode_full(match: re.Match[str]) -> str:
    """Return the decoded email, replacing an arbitrary ``<tag data-cfemail>`` pair.

    The original element's tag + non-CF attributes are preserved on a
    rebuilt element.  The inner placeholder text is gone.
    """
    encoded = match.group("hex") or ""
    decoded = _decode_value(encoded)
    if not decoded:
        return match.group(0)
    tag = match.group("tag") or "span"
    attrs_pre = (match.group("attrs_pre") or "").rstrip()
    attrs_post = (match.group("attrs_post") or "").lstrip()
    suffix_attrs = (
        attrs_pre
        + (" " + attrs_post if attrs_post else "")
    ).strip()
    if suffix_attrs:
        return f"<{tag} {suffix_attrs}>{decoded}</{tag}>"
    return f"<{tag}>{decoded}</{tag}>"


def cf_decode(html: str) -> str:
    """Decode all Cloudflare ``data-cfemail`` attributes in *html*.

    Handles both styles Cloudflare emits:

    1. ``<a class="__cf_email__" data-cfemail="..." href="...">
       [email&#160;protected]</a>`` — entire ``<a>`` element is
       replaced with the decoded address.
    2. ``<span data-cfemail="...">[email&#160;protected]</span>``
       (or any other tag) — the ``data-cfemail`` attribute is stripped
       and the inner placeholder is replaced with the decoded address.
       Preserved non-CF attributes (class, id, style, etc.) stay
       intact on the rebuilt element.

    The function returns the modified HTML string.  When no
    ``data-cfemail`` attribute is present the input is returned
    unchanged (the original ``html`` object identity is NOT
    guaranteed — callers should treat the return value as a new
    string).

    The decoder is intentionally permissive:

    * ``_decode_value`` returns ``None`` on any parse error so the
      regex callbacks leave the original element untouched for
      malformed payloads.
    * The placeholder regex tolerates ``[email protected]`` plus the
      several HTML-entity / ``&nbsp;`` variants we've seen.
    """
    if not html or "data-cfemail" not in html:
        return html

    # Pass 1: canonical <a class="__cf_email__" …>…</a>.
    out = _CF_EMAIL_SPAN_RE.sub(_decode_span, html)
    # Pass 2: any element with the attribute + placeholder pair.
    out = _CF_FULL_RE.sub(_decode_full, out)
    return out


__all__ = ["cf_decode"]
