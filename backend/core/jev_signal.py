"""Phase JEV-5 — signal-hygiene call sites (investigate cleanups).

Helpers the investigation engine calls to feed cleaner signals into the existing
engines. Each one:

* is a no-op without a JEV key (``jev.is_active()`` is False) — the role gate,
  common-name control and breach dedup are then byte-identical to today;
* runs only on the AMBIGUOUS cases the fast path could not settle, capped per run,
  cached, and biased against over-correction (act only on a confident verdict);
* never writes a band or a score, and makes no JEV call inside scoring. It only
  improves the inputs the existing formulas already consume.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from . import jev
from .jev.tasks.signal import (
    BREACH_CANONICALIZE,
    COMMON_NAME_CONTEXT,
    ROLE_SYSTEM_CLASSIFY,
)

_LOG = logging.getLogger(__name__)

MAX_BREACH_PAIRS_PER_RUN = 15
_BREACH_LOW = 78
_BREACH_HIGH = 99


# ---------------------------------------------------------------------------
# Task 1 — signal.role_system_classify
# ---------------------------------------------------------------------------
async def is_role_or_shared(
    email: str, *, display_name: str | None = None, seen_role: str | None = None
) -> bool:
    """True only when JEV is confident a NON-OBVIOUS address is a shared/role mailbox.

    Callers use this only after the fast role check said "not a role"; a confident
    ``role_or_shared`` then gates personal enumeration exactly as a known role does.
    ``person`` / ``unclear`` / DEFER return False so today's default (enumerate) stands.
    """
    if not jev.is_active() or "@" not in (email or ""):
        return False
    local, _, domain = email.strip().lower().partition("@")
    if not local:
        return False
    try:
        verdict = await jev.judge(ROLE_SYSTEM_CLASSIFY, {
            "localpart": local[:64],
            "domain": domain[:253],
            "display_name": (display_name or None) and str(display_name)[:120],
            "seen_role": (seen_role or None) and str(seen_role)[:80],
        })
    except Exception:
        _LOG.exception("JEV role classification skipped")
        return False
    if verdict is jev.DEFER:
        return False
    return verdict.output.kind == "role_or_shared"


# ---------------------------------------------------------------------------
# Task 2 — signal.common_name_context
# ---------------------------------------------------------------------------
async def common_name_hint(email: str, collected: dict[str, Any], base_hint: Any) -> Any:
    """Augment a NameHint: lift the common-name cap or drop a same-name stranger.

    Only fires when the heuristic's winning name is a common name (the case where the
    static cap would apply). A confident ``is_subject`` adds the name to
    ``lift_common_name_cap``; a confident ``coincidental`` adds it to ``drop``;
    everything else leaves the hint unchanged (today's cap stands).
    """
    if not jev.is_active():
        return base_hint
    try:
        import dataclasses

        from .common_names import is_common_name
        from .name_consensus import (
            NameConsensusEngine,
            NameHint,
            canonical_name,
            extract_name_candidates,
        )

        result = NameConsensusEngine(email, jev_hint=base_hint).resolve(
            extract_name_candidates(collected, email)
        )
        name = (result.confirmed_name or "").strip()
        if not name:
            return base_hint
        tokens = [t.strip(".,'-") for t in name.lower().split() if t.strip(".,'-")]
        if not tokens or not all(is_common_name(t) for t in tokens):
            return base_hint  # not a common-name hit → the cap never applies
        canon = canonical_name(name)
        evidence = sorted({
            str(c.source) for c in result.all_candidates
            if canonical_name(c.normalized_name) == canon
        })[:20]
        verdict = await jev.judge(COMMON_NAME_CONTEXT, {
            "name": name[:120],
            "subject_email": str(email)[:254],
            "evidence": evidence,
        })
        if verdict is jev.DEFER:
            return base_hint
        base = base_hint if isinstance(base_hint, NameHint) else NameHint()
        relation = verdict.output.relation
        if relation == "is_subject":
            return dataclasses.replace(
                base, lift_common_name_cap=base.lift_common_name_cap | {canon}
            )
        if relation == "coincidental":
            return dataclasses.replace(base, drop=base.drop | {canon})
        return base_hint
    except Exception:
        _LOG.exception("JEV common-name context skipped")
        return base_hint


# ---------------------------------------------------------------------------
# Task 3 — signal.breach_canonicalize
# ---------------------------------------------------------------------------
async def canonicalize_breaches(findings: list[dict[str, Any]]) -> int:
    """Stamp ``metadata.jev_canonical_breach`` on confident same-breach variants.

    Groups breach findings by today's canonical id, fuzzy-pairs the DISTINCT source
    names across different ids, and asks JEV; a confident ``yes`` stamps both groups
    with one shared canonical id so the deterministic collapse merges them. Nothing is
    ever dropped or invented; runs outside scoring. Returns the number of merges.
    """
    if not jev.is_active() or not findings:
        return 0
    try:
        from .breach_normalizer import _normalize_key, resolve_breach_identity

        # One representative finding-list per current canonical id.
        groups: dict[str, dict[str, Any]] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            payload = finding.get("data") if isinstance(finding.get("data"), dict) else finding
            module = str(finding.get("module_name") or (payload or {}).get("source") or "")
            identity = resolve_breach_identity(payload if isinstance(payload, dict) else {}, module)
            if identity is None:
                continue
            g = groups.setdefault(
                identity.canonical_id,
                {"name": _raw_breach_name(payload) or identity.canonical_name,
                 "date": _date_of(payload), "domain": _domain_of(payload), "metas": []},
            )
            meta = payload.get("metadata") if isinstance(payload, dict) else None
            if isinstance(meta, dict):
                g["metas"].append(meta)
        if len(groups) < 2:
            return 0

        ids = list(groups)
        pairs = _fuzzy_pairs([groups[i]["name"] for i in ids])
        if not pairs:
            return 0
        verdicts = await asyncio.gather(*(
            jev.judge(BREACH_CANONICALIZE, {
                "name_a": groups[ids[i]]["name"][:120],
                "name_b": groups[ids[j]]["name"][:120],
                "domain_a": groups[ids[i]]["domain"], "domain_b": groups[ids[j]]["domain"],
                "date_a": groups[ids[i]]["date"], "date_b": groups[ids[j]]["date"],
            })
            for i, j in pairs
        ))
        merges = 0
        for (i, j), verdict in zip(pairs, verdicts):
            if verdict is jev.DEFER or verdict.output.same_breach != "yes":
                continue
            canonical_name = (verdict.output.canonical_name or groups[ids[i]]["name"]).strip()
            canonical_id = _normalize_key(canonical_name) or ids[i]
            stamp = {"canonical_id": canonical_id, "canonical_name": canonical_name,
                     "jev_assisted": True, "jev_task": BREACH_CANONICALIZE}
            for gid in (ids[i], ids[j]):
                for meta in groups[gid]["metas"]:
                    meta["jev_canonical_breach"] = dict(stamp)
            merges += 1
        return merges
    except Exception:
        _LOG.exception("JEV breach canonicalization skipped")
        return 0


def _fuzzy_pairs(names: list[str]) -> list[tuple[int, int]]:
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
            if _BREACH_LOW <= fuzz.token_sort_ratio(a, b) <= _BREACH_HIGH:
                pairs.append((i, j))
                if len(pairs) >= MAX_BREACH_PAIRS_PER_RUN:
                    return pairs
    return pairs


def _raw_breach_name(payload: Any) -> str | None:
    """The raw breach source-name string (for the fuzzy pre-filter + JEV payload)."""
    if not isinstance(payload, dict):
        return None
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    for src in (payload, meta):
        for key in ("breach_name", "breach_source", "name"):
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:120]
    return None


def _date_of(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    for src in (payload, meta):
        for key in ("breach_date", "breached_date", "xposed_date", "year", "added_date"):
            val = src.get(key)
            if val:
                return str(val)[:40]
    return None


def _domain_of(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    for src in (payload, meta):
        val = src.get("domain") or src.get("breach_domain")
        if val:
            return str(val)[:253]
    return None
