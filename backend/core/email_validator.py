"""Native, dependency-free email candidate validation.

This layer deliberately separates mailbox evidence from address quality:
syntax/disposable/role checks are local, MX is DNS evidence, and SMTP is an
optional stronger probe owned by :mod:`smtp_verifier`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .disposable_domains import is_disposable_email
from .email_extraction import validate_email
from .mx_resolver import MXRecord, resolve_mx
from .role_classifier import classify_email


@dataclass
class EmailValidationResult:
    email: str
    syntax_valid: bool = False
    disposable: bool = False
    is_role: bool = False
    role_match_type: str | None = None
    mx_records: list[MXRecord] = field(default_factory=list)
    status: str = "invalid"
    reasons: list[str] = field(default_factory=list)

    @property
    def mx_valid(self) -> bool:
        return bool(self.mx_records)


async def validate_email_candidate(
    email: str,
    *,
    mx_records: list[MXRecord] | None = None,
) -> EmailValidationResult:
    """Validate one candidate without contacting a mailbox.

    ``mx_records`` may be supplied by a batch caller to avoid resolving the
    same domain repeatedly. ``mx_valid`` means the domain advertises mail
    exchangers; it must never be presented as proof that the mailbox exists.
    """
    value = email.strip().lower() if isinstance(email, str) else ""
    result = EmailValidationResult(email=value)
    result.syntax_valid = validate_email(value)
    if not result.syntax_valid:
        result.reasons.append("invalid_syntax")
        return result

    result.disposable = is_disposable_email(value)
    role = classify_email(value)
    result.is_role = role.is_role
    result.role_match_type = role.match_type if role.is_role else None
    if result.disposable:
        result.reasons.append("disposable_domain")
    if result.is_role:
        result.reasons.append(f"role:{role.match_type}")

    if mx_records is None:
        _, domain = value.rsplit("@", 1)
        mx_records = await resolve_mx(domain)
    result.mx_records = list(mx_records or [])
    if result.mx_records:
        result.reasons.append("mx_present")
        result.status = "mx_valid"
    else:
        result.reasons.append("mx_missing")
        result.status = "mx_missing"

    if result.disposable:
        result.status = "disposable"
    elif result.is_role:
        result.status = "role"
    return result


async def validate_email_batch(
    emails: list[str],
    *,
    mx_records: list[MXRecord] | None = None,
) -> list[EmailValidationResult]:
    """Validate candidates while resolving MX at most once for a domain."""
    return [
        await validate_email_candidate(email, mx_records=mx_records)
        for email in emails
    ]
