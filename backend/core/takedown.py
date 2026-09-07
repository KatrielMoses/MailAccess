"""Phase 2E — per-record deletion / takedown.

A takedown does more than delete: it *records* the takedown and writes a
companion suppression row, so the subject cannot silently re-enter on a later
collection. It cannot be undone silently — the takedown and suppression rows
persist, and the action is written to the tamper-evident audit log.
"""

from __future__ import annotations

import logging

from ..db.database import AsyncSessionLocal, init_db
from ..db.models import Takedown
from . import audit_log
from .suppression import (
    SuppressionScope,
    add_suppression,
    domain_of,
    match_key,
)

logger = logging.getLogger(__name__)


async def record_takedown(
    *,
    email: str | None = None,
    domain: str | None = None,
    removed_ref: str | None = None,
    reason: str | None = None,
) -> dict:
    """Record a takedown for a subject and block its re-collection.

    Writes a :class:`Takedown` row (minimum-retention hash), a companion
    suppression row (so exports/leads exclude it going forward), and an audit-log
    entry. Returns a small summary.
    """
    await init_db()
    scopes: list[tuple[SuppressionScope, str]] = []
    if email:
        scopes.append((SuppressionScope.EMAIL, email))
    if domain:
        scopes.append((SuppressionScope.DOMAIN, domain))
    # An email implies its domain is not auto-suppressed (that would over-block);
    # only the exact email is suppressed unless a domain was named explicitly.

    recorded = 0
    async with AsyncSessionLocal() as session:
        async with session.begin():
            for scope, raw in scopes:
                session.add(
                    Takedown(
                        subject_type=scope.value,
                        subject=match_key(scope, raw),
                        reason=reason,
                        removed_ref=removed_ref,
                    )
                )
                recorded += 1

    # Block re-collection via the suppression store (source = "takedown").
    suppressed = await add_suppression(
        email=email, domain=domain, reason=reason or "takedown", source="takedown"
    )

    await audit_log.append(
        audit_log.ACTION_TAKEDOWN,
        subject=(match_key(SuppressionScope.EMAIL, email) if email else None),
        details={
            "removed_ref": removed_ref,
            "email_domain": domain_of(email) if email else domain,
            "takedowns_recorded": recorded,
            "suppressions_added": suppressed,
        },
    )
    return {"takedowns_recorded": recorded, "suppressions_added": suppressed}
