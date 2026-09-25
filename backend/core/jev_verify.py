"""Phase JEV-2 — verification call sites (the honesty-critical path).

Thin async helpers the existing verification classifiers call ONLY in their
ambiguous / inconclusive branch. Each one:

* is a no-op without a JEV key (``jev.is_active()`` is False) — the verification
  path is then byte-identical to today;
* is reached only after the fast per-provider matcher has already handled the
  unambiguous replies (pre-filter);
* returns a conservative fallback (``None`` / ``False``) on every DEFER and never
  raises, so today's classifier stands;
* supplies only the classification INPUT the existing grading already consumes —
  no function here writes a deliverability grade, an eligibility verdict, a score,
  or a "verified" label. The existing grader turns the input into a label exactly
  as it does today.

The JEV task confidence floor (0.9) means a hesitant positive DEFERs rather than
becoming evidence, so an ambiguous reply resolves to today's behavior, never a
spurious upgrade.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from . import jev
from .jev.tasks.verify import CATCHALL_JUDGE, M365_SIGNAL_READ, REPLY_CLASSIFY

_LOG = logging.getLogger(__name__)

ReplyVerdict = Literal["exists", "no_such_user", "catch_all", "temporary", "blocked"]


async def reply_verdict(
    *,
    protocol: Literal["smtp_rcpt", "imap_login"],
    text: str | None,
    code: int | None = None,
    provider: str | None = None,
) -> ReplyVerdict | None:
    """Classify a novel/ambiguous mail-server reply, or None to keep today's verdict.

    Returns a concrete verdict only when JEV answered confidently with something
    other than ``unknown``; ``unknown`` and every DEFER map to None (fallback).
    """
    if not jev.is_active():
        return None
    reply = (text or "").strip()
    if not reply:
        return None
    try:
        verdict = await jev.judge(REPLY_CLASSIFY, {
            "protocol": protocol,
            "code": code if isinstance(code, int) and 0 <= code <= 999 else None,
            "text": reply[:600],
            "provider": (provider or None) and str(provider)[:40],
        })
    except Exception:
        _LOG.exception("JEV reply classification skipped")
        return None
    if verdict is jev.DEFER:
        return None
    result = verdict.output.verdict
    return None if result == "unknown" else result


async def catchall_yes(
    *,
    domain: str,
    provider: str | None,
    control_code: int | None,
    control_text: str | None,
    real_code: int | None = None,
    real_text: str | None = None,
) -> bool:
    """True only when JEV confidently judges the domain a catch-all.

    Conservative by design: this can only ADD a catch-all finding (which blocks a
    positive verification), never clear one. A ``no`` / ``unclear`` / DEFER returns
    False so today's heuristic decides.
    """
    if not jev.is_active():
        return False
    try:
        payload: dict[str, Any] = {
            "domain": str(domain)[:253],
            "provider": (provider or None) and str(provider)[:40],
            "control_probe": {"code": _code(control_code), "text": (control_text or "")[:400]},
        }
        if real_text or real_code is not None:
            payload["real_address"] = {"code": _code(real_code), "text": (real_text or "")[:400]}
        verdict = await jev.judge(CATCHALL_JUDGE, payload)
    except Exception:
        _LOG.exception("JEV catch-all judgment skipped")
        return False
    if verdict is jev.DEFER:
        return False
    return verdict.output.catch_all == "yes"


async def m365_verdict(
    signals: dict[str, Any],
) -> tuple[Literal["exists", "not_exists"] | None, Literal["yes", "no"] | None]:
    """Interpret partial/conflicting M365 signals.

    Returns ``(mailbox, managed_tenant)`` where each is the confident value or
    None. ``unknown`` and every DEFER map to None so the existing rules stand.
    Never fabricates existence: only ``exists`` / ``not_exists`` are returned.
    """
    if not jev.is_active():
        return None, None
    try:
        cleaned = {
            str(k)[:60]: v
            for k, v in list(signals.items())[:20]
            if isinstance(v, str | int | bool) or v is None
        }
        verdict = await jev.judge(M365_SIGNAL_READ, {"signals": cleaned})
    except Exception:
        _LOG.exception("JEV M365 signal read skipped")
        return None, None
    if verdict is jev.DEFER:
        return None, None
    mailbox = verdict.output.mailbox
    tenant = verdict.output.managed_tenant
    return (
        None if mailbox == "unknown" else mailbox,
        None if tenant == "unknown" else tenant,
    )


def _code(value: Any) -> int | None:
    return value if isinstance(value, int) and 0 <= value <= 999 else None
