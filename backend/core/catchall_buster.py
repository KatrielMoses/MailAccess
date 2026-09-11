"""Phase 3E — catch-all handling via provider existence oracles (no SMTP).

Catch-all domains defeat SMTP RCPT: every address returns 250, so an accept
proves nothing (Phase-0's "stripe catch-all" blind spot). The fix that needs no
port 25 is a **provider existence oracle** — M365 ``GetCredentialType`` /
autodiscover and the Google Workspace signal — which reports whether a *specific*
mailbox exists on the tenant, independent of the catch-all SMTP behaviour. Where
such an oracle exists, it gives a real per-mailbox signal on a catch-all domain.

**Policy gate (the hard rule).** These oracles are *active mailbox probing*. They
are permitted only in authorized modes — ``security-investigation`` and
``org-authorized-verification`` (the operator's own/authorized domain) — and are
**blocked in ``public-business-contact``**: active existence probing of arbitrary
third-party mailboxes for cold outreach is not a lawful basis (the FTC line,
Doc-1 #6). This mirrors ``product_mode.active_mailbox_probing_allowed``. The
policy suite asserts a bust never lifts a catch-all address to Valid in public
mode.

This module is the gate + a thin, guarded entrypoint over the existing verifiers;
it adds no new provider and does not raise the SMTP probe cap.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .mail_provider import MailProvider
from .product_mode import ProductMode, active_mailbox_probing_allowed, normalize_mode

logger = logging.getLogger(__name__)

# Providers for which we have a per-mailbox existence oracle that does not need
# SMTP. (Yahoo's endpoint is a consumer-account check, not a tenant oracle, so it
# is not a catch-all buster for business domains.)
_ORACLE_PROVIDERS = frozenset({MailProvider.M365, MailProvider.GOOGLE})


@dataclass(frozen=True)
class ExistenceSignal:
    """A per-mailbox existence result from a provider oracle."""

    email: str
    exists: bool | None  # True/False, or None when undeterminable
    provider: str | None
    status: str  # "confirmed" | "not_found" | "inconclusive" | "blocked_by_mode" | "no_oracle"
    detail: str = ""


def oracle_available(provider: MailProvider | str | None) -> bool:
    """Whether a non-SMTP per-mailbox oracle exists for this provider."""
    if isinstance(provider, MailProvider):
        return provider in _ORACLE_PROVIDERS
    try:
        return MailProvider(str(provider)) in _ORACLE_PROVIDERS
    except ValueError:
        return False


def is_bust_allowed(mode: str | ProductMode) -> bool:
    """Whether catch-all busting (active existence probing) is permitted in mode.

    Delegates to the single source of truth for active-probing policy so this can
    never drift from the rest of the gate: allowed in security-investigation and
    org-authorized-verification; blocked in public-business-contact.
    """
    return active_mailbox_probing_allowed(mode)


def trust_provider_confirmation_on_catchall(
    mode: str | ProductMode, provider: MailProvider | str | None
) -> bool:
    """Whether a provider "verified" verdict may lift a *catch-all* address to
    Valid under ``mode``. Requires both an oracle-capable provider and an
    authorized mode — the two conditions the grade fuser checks before trusting a
    provider confirmation as a catch-all bust."""
    return oracle_available(provider) and is_bust_allowed(mode)


async def confirm_mailbox(
    email: str,
    provider: MailProvider | str | None,
    *,
    mode: str | ProductMode,
    verifier: Any | None = None,
) -> ExistenceSignal:
    """Confirm a single mailbox via the provider oracle, policy-gated.

    Returns ``blocked_by_mode`` (without probing) in public-business-contact, and
    ``no_oracle`` when the provider has no non-SMTP oracle. Fully guarded — any
    error yields an inconclusive signal, never an exception into the harvest.

    ``verifier`` may be injected for testing; otherwise the appropriate provider
    verifier is constructed lazily.
    """
    m = normalize_mode(mode)
    prov = provider if isinstance(provider, MailProvider) else _coerce_provider(provider)

    if not is_bust_allowed(m):
        return ExistenceSignal(
            email, None, prov.value if prov else None, "blocked_by_mode",
            "active existence probing is not permitted in public-business-contact",
        )
    if not oracle_available(prov):
        return ExistenceSignal(
            email, None, prov.value if prov else None, "no_oracle",
            "no non-SMTP existence oracle for this provider",
        )

    try:
        results = await _run_oracle(email, prov, verifier)
        status = str(results.get("status") or "inconclusive").lower()
        exists = results.get("exists")
        if exists is True or status == "verified":
            return ExistenceSignal(email, True, prov.value, "confirmed", "oracle confirmed mailbox")
        if exists is False or status == "not_found":
            return ExistenceSignal(
                email, False, prov.value, "not_found", "oracle: mailbox not found"
            )
        return ExistenceSignal(
            email, None, prov.value, "inconclusive", f"oracle status={status}"
        )
    except Exception:
        logger.debug("catch-all oracle failed for %s", email, exc_info=True)
        return ExistenceSignal(
            email, None, prov.value if prov else None, "inconclusive", "oracle error"
        )


async def confirm_mailboxes(
    emails: list[str],
    provider: MailProvider | str | None,
    *,
    mode: str | ProductMode,
    verifier: Any | None = None,
) -> list[ExistenceSignal]:
    """Batched :func:`confirm_mailbox` — one policy gate, one oracle round-trip.

    Confirms many mailboxes on the SAME provider in a single ``verify_batch``
    call (the M365 oracle is batched), so a per-run pattern pass amortises latency
    and rate-limit pressure instead of paying one HTTP request per candidate. The
    policy gate and guards are identical to :func:`confirm_mailbox` — this stays
    inside the governance seam, it does not bypass it. Returns one
    :class:`ExistenceSignal` per (de-duplicated, ``@``-bearing) input email; a
    result missing from the oracle response degrades to ``inconclusive``.
    """
    m = normalize_mode(mode)
    prov = provider if isinstance(provider, MailProvider) else _coerce_provider(provider)
    cleaned = list(
        dict.fromkeys(
            e.strip().lower() for e in (emails or []) if isinstance(e, str) and "@" in e
        )
    )
    if not is_bust_allowed(m):
        return [
            ExistenceSignal(
                e, None, prov.value if prov else None, "blocked_by_mode",
                "active existence probing is not permitted in public-business-contact",
            )
            for e in cleaned
        ]
    if not oracle_available(prov):
        return [
            ExistenceSignal(
                e, None, prov.value if prov else None, "no_oracle",
                "no non-SMTP existence oracle for this provider",
            )
            for e in cleaned
        ]
    if not cleaned:
        return []

    try:
        by_email = await _run_oracle_batch(cleaned, prov, verifier)
    except Exception:
        logger.debug("catch-all oracle batch failed", exc_info=True)
        by_email = {}

    signals: list[ExistenceSignal] = []
    for e in cleaned:
        raw = by_email.get(e)
        if raw is None:
            signals.append(ExistenceSignal(e, None, prov.value, "inconclusive", "oracle error"))
            continue
        status = str(raw.get("status") or "inconclusive").lower()
        exists = raw.get("exists")
        if exists is True or status == "verified":
            signals.append(
                ExistenceSignal(e, True, prov.value, "confirmed", "oracle confirmed mailbox")
            )
        elif exists is False or status == "not_found":
            signals.append(
                ExistenceSignal(e, False, prov.value, "not_found", "oracle: mailbox not found")
            )
        else:
            # throttled / inconclusive / unmanaged / not_attempted → inconclusive.
            signals.append(
                ExistenceSignal(e, None, prov.value, "inconclusive", f"oracle status={status}")
            )
    return signals


def _coerce_provider(provider: str | None) -> MailProvider | None:
    try:
        return MailProvider(str(provider)) if provider else None
    except ValueError:
        return None


async def _run_oracle_batch(
    emails: list[str], provider: MailProvider, verifier: Any | None
) -> dict[str, dict[str, Any]]:
    """Invoke the provider verifier once for the whole batch; index by email.

    ``verify_batch`` lower-cases and de-duplicates its inputs, so the returned
    map is keyed by the same normalized email the caller passes in.
    """
    results: list[Any]
    if provider is MailProvider.M365:
        if verifier is None:
            from .m365_verifier import M365Verifier

            verifier = M365Verifier()
        results = await verifier.verify_batch(emails)
    elif provider is MailProvider.GOOGLE:
        # No working Google oracle (Phase 1) — this branch exists only for
        # symmetry; the pattern pass never routes google here. verify_batch is
        # per-domain, so group by domain first.
        if verifier is None:
            from .google_workspace_verifier import GoogleWorkspaceVerifier

            verifier = GoogleWorkspaceVerifier()
        results = []
        by_domain: dict[str, list[str]] = {}
        for e in emails:
            by_domain.setdefault(e.rsplit("@", 1)[-1], []).append(e)
        for domain, group in by_domain.items():
            results.extend(await verifier.verify_batch(group, domain))
    else:  # pragma: no cover - guarded by oracle_available
        return {}

    out: dict[str, dict[str, Any]] = {}
    for first in results or []:
        email = str(getattr(first, "email", "") or "").strip().lower()
        if not email:
            continue
        out[email] = {
            "status": getattr(first, "status", "inconclusive"),
            "exists": getattr(first, "exists", None),
        }
    return out


async def _run_oracle(
    email: str, provider: MailProvider, verifier: Any | None
) -> dict[str, Any]:
    """Invoke the appropriate provider verifier and normalise its result."""
    if provider is MailProvider.M365:
        if verifier is None:
            from .m365_verifier import M365Verifier

            verifier = M365Verifier()
        results = await verifier.verify_batch([email])
    elif provider is MailProvider.GOOGLE:
        if verifier is None:
            from .google_workspace_verifier import GoogleWorkspaceVerifier

            verifier = GoogleWorkspaceVerifier()
        domain = email.rsplit("@", 1)[-1]
        results = await verifier.verify_batch([email], domain)
    else:  # pragma: no cover - guarded by oracle_available
        return {"status": "no_oracle", "exists": None}

    first = results[0] if results else None
    if first is None:
        return {"status": "inconclusive", "exists": None}
    return {
        "status": getattr(first, "status", "inconclusive"),
        "exists": getattr(first, "exists", None),
    }
