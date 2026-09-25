"""Phase JEV-4 — reach and selection call sites ("same budget, better choice").

Two helpers that improve WHICH items are used within today's caps. Each one:

* is a no-op without a JEV key (``jev.is_active()`` is False) — selection and query
  generation are then byte-identical to today;
* runs AFTER the existing filters (health / protection / product-mode for platforms;
  the per-module query cap for queries) and RE-VALIDATES the model's output at the
  boundary — anything not in the eligible set, or out of scope, is dropped;
* never increases the probe count or the query budget: platform output is truncated
  to the wave cap, query output to the per-module cap;
* falls back to today's order/templates on every DEFER and never raises. JEV writes
  no score.
"""

from __future__ import annotations

import logging
from typing import Any

from . import jev
from .jev.tasks.reach import (
    _MAX_CANDIDATES,
    MAX_QUERIES,
    PLATFORM_SELECT,
    QUERY_GENERATE,
)

# Operational query-length cap (stricter than the task's schema bound): a query
# longer than this is dropped, not truncated, so a malformed blob never runs.
_OP_QUERY_LEN = 300

_LOG = logging.getLogger(__name__)


async def select_platforms(
    *,
    eligible_ids: list[str],
    candidates: list[dict[str, Any]],
    wave_cap: int,
    name: str | None = None,
    email_localpart: str | None = None,
    hints: list[str] | None = None,
) -> list[str] | None:
    """Return a re-validated ordered subset of ``eligible_ids``, or None (keep today).

    The result is always a subset of ``eligible_ids`` (defense-in-depth: any id the
    model returns that is not eligible is dropped) and never longer than ``wave_cap``.
    One call per investigation.
    """
    if not jev.is_active() or wave_cap < 1 or not eligible_ids:
        return None
    eligible = set(eligible_ids)
    try:
        verdict = await jev.judge(PLATFORM_SELECT, {
            "name": (name or None) and str(name)[:120],
            "email_localpart": (email_localpart or None) and str(email_localpart)[:64],
            "hints": [str(h)[:60] for h in (hints or [])][:12],
            "wave_cap": min(int(wave_cap), 200),
            "candidates": candidates[:_MAX_CANDIDATES],
        })
    except Exception:
        _LOG.exception("JEV platform selection skipped")
        return None
    if verdict is jev.DEFER:
        return None
    # Re-validate: keep only eligible ids, de-duplicated, order preserved, then cap.
    seen: set[str] = set()
    chosen: list[str] = []
    for pid in verdict.output.ordered_platform_ids:
        if pid in eligible and pid not in seen:
            seen.add(pid)
            chosen.append(pid)
            if len(chosen) >= wave_cap:
                break
    return chosen or None


def _scoped(query: str, anchors: list[str]) -> bool:
    """A query is in-scope only if it references a subject anchor (domain/name/handle)."""
    low = query.lower()
    return any(a and a.lower() in low for a in anchors)


async def generate_queries(
    *,
    engine: str,
    max_queries: int,
    email: str | None = None,
    name: str | None = None,
    domain: str | None = None,
    employer: str | None = None,
    handles: list[str] | None = None,
) -> list[str] | None:
    """Return validated subject-scoped queries (<= ``max_queries``), or None.

    Each returned query is length-capped and must reference a subject anchor
    (email / domain / name / handle); anything else is dropped. An empty result
    after validation returns None so today's templates run.
    """
    if not jev.is_active() or max_queries < 1:
        return None
    cap = min(int(max_queries), MAX_QUERIES)
    try:
        verdict = await jev.judge(QUERY_GENERATE, {
            "email": (email or None) and str(email)[:254],
            "name": (name or None) and str(name)[:120],
            "domain": (domain or None) and str(domain)[:253],
            "employer": (employer or None) and str(employer)[:120],
            "handles": [str(h)[:120] for h in (handles or [])][:8],
            "engine": str(engine)[:40],
            "max_queries": cap,
        })
    except Exception:
        _LOG.exception("JEV query generation skipped")
        return None
    if verdict is jev.DEFER:
        return None
    anchors = [a for a in (email, domain, name, employer, *(handles or [])) if a]
    out: list[str] = []
    seen: set[str] = set()
    for raw in verdict.output.queries:
        q = " ".join(str(raw).split())
        if not q or q in seen or len(q) < 3 or len(q) > _OP_QUERY_LEN:
            continue
        # Scope guard: only accept queries anchored to the subject/domain. When no
        # anchor is known, accept (the caller supplied nothing to scope against).
        if anchors and not _scoped(q, anchors):
            continue
        seen.add(q)
        out.append(q)
        if len(out) >= cap:
            break
    return out or None
