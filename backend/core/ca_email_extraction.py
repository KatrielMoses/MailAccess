"""Email extraction from Certificate Transparency log records.

Pure parsing logic — no network I/O.  Callers fetch the raw CT JSON
(we reuse the same URL shapes as
``backend.core.harvester_collectors.collect_crtsh`` /
``collect_certspotter``) and pipe each record through these helpers.

Most CT records do **not** contain an email — the CA's job is to
attest the hostname, not the contact address.  But a small percentage
of certificate subject DNs include ``emailAddress=foo@bar.com``,
and we want to catch those automatically rather than leave them
lying around in the raw JSON.

Per the spec, we deliberately avoid trying to parse OID-encoded
ASN.1 strings (``1.2.840.113549.1.9.1=#...``).  Those are real but
unreliably decoded by ad-hoc string parsing.  Plain-text
``emailAddress=`` is the safe choice.
"""

from __future__ import annotations

import logging
from typing import Any

from .email_extraction import extract_emails

_LOG = logging.getLogger(__name__)


# Field names we know crt.sh and certspotter use.  Anything that
# contains a plain text "email" anywhere in its key also gets scanned
# so future-format additions don't slip past us.
_EMAIL_FIELDS: frozenset[str] = frozenset(
    {
        "email_address",
        "emailaddress",
        "contact_email",
        "admin_email",
        "tech_email",
        "registrant_email",
        "registrar_email",
    }
)


def _stringify(value: Any) -> str:
    """Convert a JSON value (any type) to a string the email regex can scan."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, int | float | bool):
        return str(value)
    if isinstance(value, list | tuple | set):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_stringify(v) for v in value.values())
    return str(value)


def _scan_blob(blob: str, target_domain: str | None) -> list[str]:
    """Run :func:`extract_emails` and dedupe, returning lowercase strings.

    When ``target_domain`` is provided we keep **only** ``on_domain``
    matches — third-party emails that happen to appear in a CT record
    belong to other organizations and aren't useful for a domain
    harvest.
    """
    seen: dict[str, None] = {}
    for extracted in extract_emails(blob, target_domain=target_domain):
        if target_domain and not extracted.on_domain:
            continue
        seen.setdefault(extracted.email, None)
    return list(seen.keys())


def extract_emails_from_crtsh_record(
    record: Any, target_domain: str | None = None
) -> list[str]:
    """Extract emails from one crt.sh JSON record.

    Strategy: gather every textual field, concatenate, then run the
    shared :func:`extract_emails` regex against the blob.  This is
    simpler and more robust than format-specific parsers for every
    CA's quirks.
    """
    if not isinstance(record, dict):
        return []

    # Targeted field extraction first — these are the ones we know can
    # carry a contact email directly.
    focused_parts: list[str] = []
    for key in _EMAIL_FIELDS:
        if key in record:
            focused_parts.append(_stringify(record[key]))

    # Catch-all: stringify the whole record so subject_dn, OID strings,
    # mis-configured name_value fields, etc. all get scanned.
    catchall_parts = [_stringify(record)]

    blob = "\n".join(focused_parts + catchall_parts)
    return _scan_blob(blob, target_domain=target_domain)


def extract_emails_from_certspotter_record(
    record: Any, target_domain: str | None = None
) -> list[str]:
    """Extract emails from one certspotter JSON record.

    Same catch-all approach as crt.sh.  certspotter records include a
    flat dns_names list; we still scan the whole record blob so we
    don't miss unusual metadata fields.
    """
    if not isinstance(record, dict):
        return []

    focused_parts: list[str] = []
    for key in _EMAIL_FIELDS:
        if key in record:
            focused_parts.append(_stringify(record[key]))

    catchall_parts = [_stringify(record)]
    blob = "\n".join(focused_parts + catchall_parts)
    return _scan_blob(blob, target_domain=target_domain)


def extract_emails_from_records(
    records: list[Any],
    source: str = "crtsh",
    target_domain: str | None = None,
) -> list[tuple[str, int]]:
    """Bulk version: returns ``(email, record_index)`` pairs for every hit.

    ``source`` is ``"crtsh"`` or ``"certspotter"`` — selects which
    per-record parser to call.  ``record_index`` lets the caller
    correlate the email back to the original CT record if needed.
    """
    parse_one = (
        extract_emails_from_crtsh_record
        if source == "crtsh"
        else extract_emails_from_certspotter_record
    )

    out: list[tuple[str, int]] = []
    seen_in_run: dict[str, set[int]] = {}
    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        for email in parse_one(record, target_domain=target_domain):
            already = seen_in_run.setdefault(email, set())
            if idx in already:
                continue
            already.add(idx)
            out.append((email, idx))
    return out
