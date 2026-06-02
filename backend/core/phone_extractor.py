from __future__ import annotations

import re
from typing import Any

# E.164-ish: optional +, country code, subscriber digits (7–15 total digits typical)
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,6})?(?!\d)"
)
# Strong international hint (+ prefix)
_INTL_RE = re.compile(r"\+\d{7,15}")

_PHONE_KEYS = frozenset({
    "phone",
    "phone_number",
    "phonenumber",
    "phone_hint",
    "recovery_phone",
    "registrant_phone",
    "contact_phone",
})


def mask_phone(e164: str) -> str:
    """Mask middle digits; keep leading +country hint and last 4 digits."""
    digits = re.sub(r"\D", "", e164)
    if len(digits) < 6:
        return "***"
    prefix = e164 if e164.startswith("+") else f"+{digits}"
    if len(digits) <= 7:
        return f"{prefix[:3]}***{digits[-4:]}"
    visible_prefix = prefix[:5] if len(prefix) >= 5 else prefix[:3]
    return f"{visible_prefix}***{digits[-4:]}"


def normalize_e164(raw: str) -> str | None:
    """Best-effort E.164 normalization (+ and digits only)."""
    cleaned = raw.strip()
    if not cleaned:
        return None
    # Reject masked values (e.g. +1628***9574) — stripping * would produce garbage digits.
    if "*" in cleaned:
        return None

    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cleaned):
        return None

    has_plus = cleaned.startswith("+")
    digits = re.sub(r"\D", "", cleaned)
    if len(digits) < 7 or len(digits) > 15:
        return None
    if has_plus or len(digits) >= 10:
        return f"+{digits}"
    return None


def normalize_phone(raw: str, *, region: str | None = None) -> str | None:
    """
    Validate and normalize a raw phone number.

    Uses phonenumbers when installed, otherwise falls back to the existing
    E.164-ish validation so core phone discovery remains dependency-free.
    """
    value = raw.strip()
    if not value:
        return None
    try:
        import phonenumbers  # type: ignore[import-not-found]

        parsed = phonenumbers.parse(value, region)
        if not phonenumbers.is_possible_number(parsed):
            return None
        if not phonenumbers.is_valid_number(parsed):
            return None
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        return normalize_e164(value)


def _scan_value(value: Any, found: dict[str, str], current_key: str = "") -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _scan_value(v, found, k)
    elif isinstance(value, list):
        for item in value:
            _scan_value(item, found, current_key)
    elif isinstance(value, str):
        if current_key.lower() in _PHONE_KEYS:
            norm = normalize_e164(value)
            if norm:
                found[norm] = norm
            for match in _INTL_RE.finditer(value):
                norm = normalize_e164(match.group(0))
                if norm:
                    found[norm] = norm
            for match in _PHONE_RE.finditer(value):
                norm = normalize_e164(match.group(0))
                if norm:
                    found[norm] = norm


def extract_phones(findings: list[dict[str, Any]]) -> list[str]:
    """
    Scan finding payloads for phone number patterns.
    Returns deduplicated E.164-normalized numbers.
    """
    found: dict[str, str] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        _scan_value(finding, found)
        meta = finding.get("metadata")
        if isinstance(meta, dict):
            _scan_value(meta, found)
    return sorted(found.keys())
