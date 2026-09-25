"""Phase JEV-3 — harvest roster-quality call sites.

Helpers the harvest pipeline calls to clean the ROSTER (which names / people /
titles / company). Each one:

* is a no-op without a JEV key (``jev.is_active()`` is False) — the harvest path
  is then byte-identical to today;
* pre-filters with today's fast checks and sends only ambiguous cases, capped per
  run, through the cached seam;
* biases to KEEP — a drop needs a confident ``no``, a merge a confident ``yes``;
  every DEFER falls back to today's behavior and nothing is silently lost;
* never touches an address's verification/confidence label, the Pro corpus-lead
  invariants (unverified / live-only / not persisted), scoring, or any exporter.
  It only cleans the roster and attaches ``jev_assisted`` metadata.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from . import jev
from .jev.tasks.roster import (
    COMPANY_RESOLVE,
    MAX_ORG_CANDIDATES,
    PERSON_DEDUPE,
    PERSON_FILTER,
    TITLE_NORMALIZE,
)

_LOG = logging.getLogger(__name__)

MAX_PERSON_FILTER_PER_RUN = 25
MAX_DEDUPE_PAIRS_PER_RUN = 20
MAX_TITLES_PER_RUN = 40

_SENIORITY_BUCKETS = frozenset({"c-level", "vp", "director", "manager", "ic", "unknown"})
# Fuzzy band that makes a name pair a dedupe *candidate*: similar but not identical.
_DEDUPE_LOW = 82
_DEDUPE_HIGH = 99


# ---------------------------------------------------------------------------
# Task 1 — roster.person_filter
# ---------------------------------------------------------------------------
async def drop_junk_names(
    candidates: list[dict[str, Any]],
) -> tuple[set[int], dict[int, str]]:
    """Given borderline name candidates, return indices to DROP + normalized names.

    Each candidate: ``{"candidate": str, "context": str|None, "source": str|None}``.
    Only a confident ``no`` drops; ``yes`` / ``unclear`` / DEFER keep (today's
    behavior). Returns ``(drop_indices, {index: normalized_name})``.
    """
    drop: set[int] = set()
    normalized: dict[int, str] = {}
    if not jev.is_active() or not candidates:
        return drop, normalized
    try:
        bounded = candidates[:MAX_PERSON_FILTER_PER_RUN]
        verdicts = await asyncio.gather(*(
            jev.judge(PERSON_FILTER, {
                "candidate": str(c.get("candidate") or "")[:120],
                "context": (c.get("context") or None) and str(c["context"])[:600],
                "source": (c.get("source") or None) and str(c["source"])[:60],
            })
            for c in bounded
        ))
        for i, verdict in enumerate(verdicts):
            if verdict is jev.DEFER:
                continue
            out = verdict.output
            if out.is_person_name == "no":
                drop.add(i)
            elif out.is_person_name == "yes" and out.normalized_name:
                normalized[i] = out.normalized_name.strip()
    except Exception:
        _LOG.exception("JEV person-name filter skipped")
        return set(), {}
    return drop, normalized


# ---------------------------------------------------------------------------
# Task 3 — roster.person_dedupe
# ---------------------------------------------------------------------------
def candidate_dedupe_pairs(names: list[str]) -> list[tuple[int, int]]:
    """Near-duplicate (similar-but-not-identical) name pairs, bounded. Fuzzy only."""
    try:
        from rapidfuzz import fuzz
    except Exception:
        return []
    pairs: list[tuple[int, int]] = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i].strip().lower(), names[j].strip().lower()
            if not a or not b or a == b:
                continue
            if _DEDUPE_LOW <= fuzz.token_sort_ratio(a, b) <= _DEDUPE_HIGH:
                pairs.append((i, j))
                if len(pairs) >= MAX_DEDUPE_PAIRS_PER_RUN:
                    return pairs
    return pairs


async def same_person_pairs(
    entries: list[dict[str, Any]], pairs: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Return the subset of candidate pairs JEV confidently judges the same person.

    ``no`` / ``unclear`` / DEFER keep the pair separate (today's behavior).
    """
    if not jev.is_active() or not pairs:
        return []
    try:
        verdicts = await asyncio.gather(*(
            jev.judge(PERSON_DEDUPE, {"a": entries[i], "b": entries[j]})
            for i, j in pairs
        ))
        return [
            pair for pair, verdict in zip(pairs, verdicts)
            if verdict is not jev.DEFER and verdict.output.same_person == "yes"
        ]
    except Exception:
        _LOG.exception("JEV person dedupe skipped")
        return []


# ---------------------------------------------------------------------------
# Task 2 — roster.title_normalize
# ---------------------------------------------------------------------------
async def normalize_title(
    title: str, *, company: str | None = None, industry: str | None = None
) -> tuple[str | None, str | None]:
    """Return ``(seniority_bucket, normalized_title)`` for a title, or (None, None).

    Only used for titles the fast classifier left ``unknown``. DEFER / low
    confidence / an out-of-vocab bucket all return (None, None) → today's result.
    """
    if not jev.is_active() or not (title or "").strip():
        return None, None
    try:
        verdict = await jev.judge(TITLE_NORMALIZE, {
            "title": title.strip()[:200],
            "company": (company or None) and str(company)[:120],
            "industry": (industry or None) and str(industry)[:80],
        })
    except Exception:
        _LOG.exception("JEV title normalize skipped")
        return None, None
    if verdict is jev.DEFER:
        return None, None
    bucket = verdict.output.seniority_bucket
    if bucket not in _SENIORITY_BUCKETS:
        return None, None
    return bucket, (verdict.output.normalized_title or None)


# ---------------------------------------------------------------------------
# Task 4 — roster.company_resolve
# ---------------------------------------------------------------------------
async def choose_company(query: str, candidates: list[dict[str, Any]]) -> int | None:
    """Pick the index of the right org among real candidates, or None.

    ``candidates`` are the ACTUAL org records the engine returned. A returned index
    always points into that list, so JEV can never fabricate a name or domain.
    null / out-of-range / DEFER → None (existing disambiguation stands).
    """
    if not jev.is_active() or len(candidates) < 2:
        return None
    try:
        bounded = candidates[:MAX_ORG_CANDIDATES]
        verdict = await jev.judge(COMPANY_RESOLVE, {
            "query": str(query)[:200],
            "candidates": [
                {
                    "name": str(c.get("name") or "")[:200],
                    "domain": (c.get("domain") or None) and str(c["domain"])[:253],
                    "employees": c.get("employees") if isinstance(
                        c.get("employees"), int
                    ) and c.get("employees") >= 0 else None,
                }
                for c in bounded
            ],
        })
    except Exception:
        _LOG.exception("JEV company resolve skipped")
        return None
    if verdict is jev.DEFER:
        return None
    idx = verdict.output.chosen_index
    if idx is None or not (0 <= idx < len(bounded)):
        return None
    return idx
