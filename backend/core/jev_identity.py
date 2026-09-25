"""Phase JEV-1 — identity-resolution call sites (investigate).

Three helpers the investigation engine calls between the module phases and the
persist step. Each one:

* is a no-op on a keyless install (``jev.is_active()`` is False) — no payloads are
  built, nothing is mutated, output is byte-identical to the heuristic-only tool;
* pre-filters with today's heuristics and sends only borderline cases, with a
  hard per-investigation cap, through the cached JEV seam;
* falls back to today's behavior on every DEFER, and never raises;
* only improves INPUTS (graph edges, the name candidate set, bio metadata). No
  function here computes, reads or writes an exposure / credential score or a
  name-confidence band — those stay with the existing deterministic engines.

JEV-influenced outputs carry ``jev_assisted: true`` + ``jev_task`` so the
side-by-side eval can attribute a delta. Nothing is ever labelled "verified".
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from . import jev
from .jev.tasks.identity import (
    BIO_EXTRACT,
    MAX_NAME_CANDIDATES,
    NAME_RECONCILE,
    SAME_PERSON,
    Profile,
)

_LOG = logging.getLogger(__name__)

# Per-investigation ceilings (each investigation makes at most this many calls
# per task; repeats inside and across runs are served from the JEV cache).
MAX_BIOS_PER_RUN = 8
MAX_PAIRS_PER_RUN = 12

BIO_STRUCTURED_KEY = "bio_structured"
_BIO_KEYS = ("bio", "about", "about_me", "aboutMe", "biography", "description")
_BIO_SIGNAL_TYPES = frozenset({"phone_in_bio", "email_in_bio"})
_MIN_BIO_CHARS = 25
_MIN_BIO_WORDS = 4

# Graph signal classes for the same-person pre-filter.
_WEAK_PAIR_SIGNALS = frozenset({"same_bio", "same_signup_window", "shared_display_name"})
_STRONG_PAIR_SIGNALS = frozenset({"same_avatar", "shared_photo"})
_SUPPRESSIBLE = _WEAK_PAIR_SIGNALS | {"shared_username"}
_ATTR_EDGE_TYPES = {
    "shared_username": "username",
    "shared_display_name": "display_name",
    "shared_photo": "photo_url",
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def _clip(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _findings_of(result: Any) -> list[Any]:
    findings = result.get("findings") if isinstance(result, dict) else getattr(
        result, "findings", None
    )
    return findings if isinstance(findings, list) else []


# ---------------------------------------------------------------------------
# Task 3 — identity.bio_extract
# ---------------------------------------------------------------------------
def _bio_text(finding: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    meta = finding.get("metadata")
    if not isinstance(meta, dict) or BIO_STRUCTURED_KEY in meta:
        return None
    if finding.get("signal_type") in _BIO_SIGNAL_TYPES:
        return None
    if meta.get("verification") == "unverified" or meta.get("is_infrastructure"):
        return None
    for key in _BIO_KEYS:
        value = meta.get(key)
        if isinstance(value, str):
            text = value.strip()
            if len(text) >= _MIN_BIO_CHARS and len(text.split()) >= _MIN_BIO_WORDS:
                return meta, text
    return None


def ground_bio_fields(output: Any, bio: str) -> dict[str, Any] | None:
    """Keep only fields that occur verbatim in the bio (a span, never model text)."""
    haystack = _norm(bio)
    fields: dict[str, Any] = {}
    for name in ("employer", "role_title", "location"):
        value = getattr(output, name, None)
        if isinstance(value, str) and len(value.strip()) >= 2 and _norm(value) in haystack:
            fields[name] = value.strip()
    entity_type = getattr(output, "entity_type", "unclear")
    if entity_type != "unclear":
        fields["entity_type"] = entity_type
    if not fields:
        return None
    return {**fields, "jev_assisted": True, "jev_task": BIO_EXTRACT}


async def enrich_bios(collected: dict[str, Any], exclude_domain: str | None = None) -> int:
    """Attach ``metadata.bio_structured`` to profile findings with a substantive bio.

    Adds metadata only — the regex extraction in :func:`bio_analyzer.analyze_bio`
    (phones / emails / urls) is untouched. Returns the number of findings enriched.
    """
    if not jev.is_active():
        return 0
    try:
        by_bio: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for module_name in sorted(collected):
            for finding in _findings_of(collected[module_name]):
                if not isinstance(finding, dict):
                    continue
                hit = _bio_text(finding)
                if hit is None:
                    continue
                meta, text = hit
                key = _norm(text)
                if key not in by_bio:
                    order.append(key)
                    by_bio[key] = []
                by_bio[key].append(meta)
        selected = order[:MAX_BIOS_PER_RUN]
        if not selected:
            return 0
        texts = {key: _bio_source(by_bio[key][0]) for key in selected}
        verdicts = await asyncio.gather(*(
            jev.judge(BIO_EXTRACT, {"bio": texts[key][:1000], "exclude_domain": exclude_domain})
            for key in selected
        ))
        enriched = 0
        for key, verdict in zip(selected, verdicts):
            if verdict is jev.DEFER:
                continue
            fields = ground_bio_fields(verdict.output, texts[key])
            if fields is None:
                continue
            for meta in by_bio[key]:
                meta[BIO_STRUCTURED_KEY] = dict(fields)
                enriched += 1
        return enriched
    except Exception:
        _LOG.exception("JEV bio enrichment skipped")
        return 0


def _bio_source(meta: dict[str, Any]) -> str:
    for key in _BIO_KEYS:
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


# ---------------------------------------------------------------------------
# Task 2 — identity.name_reconcile
# ---------------------------------------------------------------------------
async def reconcile_names(email: str, collected: dict[str, Any]) -> Any:
    """Return a :class:`NameHint` for a borderline name picture, else None.

    Borderline = at least two distinct candidate names AND the heuristic result
    is conflicting or only possible/unknown. A confirmed/probable, unconflicted
    heuristic answer is never sent.
    """
    if not jev.is_active():
        return None
    try:
        from .name_consensus import (
            NameConsensusEngine,
            NameHint,
            canonical_name,
            extract_name_candidates,
        )

        heuristic = NameConsensusEngine(email).resolve(extract_name_candidates(collected, email))
        by_canon: dict[str, list[Any]] = {}
        for cand in heuristic.all_candidates:
            by_canon.setdefault(canonical_name(cand.normalized_name), []).append(cand)
        if len(by_canon) < 2:
            return None
        if not heuristic.conflicting_names and heuristic.name_confidence not in (
            "possible", "unknown",
        ):
            return None

        ranked = sorted(
            by_canon.items(),
            key=lambda kv: (-sum(c.final_score for c in kv[1]), kv[0]),
        )[:MAX_NAME_CANDIDATES]
        keys = [key for key, _ in ranked]
        payload = {
            "email_localpart": (email.split("@", 1)[0] if "@" in email else email)[:64],
            "candidates": [
                {
                    "name": max(group, key=lambda c: c.final_score).normalized_name[:60],
                    "sources": sorted({c.source for c in group})[:12],
                    "weight": round(min(sum(c.final_score for c in group), 10.0), 3),
                }
                for _, group in ranked
            ],
        }
        verdict = await jev.judge(NAME_RECONCILE, payload)
        if verdict is jev.DEFER:
            return None
        return _hint_from(verdict.output, keys, NameHint)
    except Exception:
        _LOG.exception("JEV name reconciliation skipped")
        return None


def _hint_from(output: Any, keys: list[str], hint_cls: Any) -> Any:
    n = len(keys)
    drop = {keys[i] for i in output.drop if 0 <= i < n}
    if len(drop) >= n:  # dropping everything is not a cleanup — ignore the drops
        drop = set()
    groups = []
    for group in output.equivalence_groups:
        members = frozenset(keys[i] for i in group if 0 <= i < n and keys[i] not in drop)
        if len(members) >= 2:
            groups.append(members)
    canonical = None
    idx = output.canonical_index
    if idx is not None and 0 <= idx < n and keys[idx] not in drop:
        canonical = keys[idx]
    if not (drop or groups or canonical):
        return None
    return hint_cls(drop=frozenset(drop), groups=tuple(groups), canonical=canonical)


# ---------------------------------------------------------------------------
# Task 1 — identity.same_person
# ---------------------------------------------------------------------------
def _fill(prof: dict[str, Any], key: str, value: Any) -> None:
    if value is not None and not prof.get(key):
        prof[key] = value


def _profiles(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per platform node id → comparable public fields (mirrors the graph build)."""
    from .enrichment.temporal_cluster import extract_creation_date
    from .identity_graph import _DISPLAY_KEYS, _USERNAME_KEYS, _node_id

    out: dict[str, dict[str, Any]] = {}
    for item in findings:
        module_name = item.get("module_name", "") if isinstance(item, dict) else ""
        finding = item.get("data", item) if isinstance(item, dict) else None
        if not isinstance(finding, dict):
            continue
        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        if meta.get("verification") == "unverified" or meta.get("is_infrastructure"):
            continue
        platform = str(finding.get("platform") or module_name or "unknown")
        prof = out.setdefault(
            _node_id("platform", platform.lower()), {"platform": platform[:80]}
        )
        for payload in (finding, meta):
            for key in sorted(_USERNAME_KEYS):
                _fill(prof, "username", _clip(payload.get(key), 120))
            for key in sorted(_DISPLAY_KEYS):
                _fill(prof, "display_name", _clip(payload.get(key), 120))
        _fill(prof, "bio", _clip(_bio_source(meta), 600))
        created = extract_creation_date(finding)
        if created is not None:
            _fill(prof, "created", created.date().isoformat())
        structured = meta.get(BIO_STRUCTURED_KEY)
        if isinstance(structured, dict):
            _fill(prof, "employer", _clip(structured.get("employer"), 120))
            _fill(prof, "location", _clip(structured.get("location"), 120))
        handles = prof.setdefault("handles", [])
        for key in ("email", "linked_urls", "verified_accounts"):
            value = meta.get(key)
            values = value if isinstance(value, list) else [value]
            for v in values:
                if isinstance(v, str) and v.strip() and len(handles) < 8:
                    clipped = v.strip()[:120]
                    if clipped not in handles:
                        handles.append(clipped)
    return {
        nid: {k: v for k, v in prof.items() if v not in (None, [])}
        for nid, prof in out.items()
    }


def ambiguous_pairs(graph: Any, profiles: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Propose borderline platform pairs from today's cheap graph signals.

    A pair qualifies when its only merge signals are weak (similar bio, close
    signup dates, a display name shared by exactly these two profiles) or when a
    shared username conflicts with differing display names and no avatar match.
    Attribute nodes shared by more than two profiles are never expanded, so the
    candidate set is O(edges), never O(n²). Capped at :data:`MAX_PAIRS_PER_RUN`.
    """
    from .name_consensus import canonical_name

    platform_ids = {nid for nid, node in graph.nodes.items() if node.type == "platform"}
    signals: dict[tuple[str, str], set[str]] = {}
    suppress: dict[tuple[str, str], list[tuple[str, str, str]]] = {}

    def note(a: str, b: str, sig: str, edges: list[tuple[str, str, str]]) -> None:
        key = (a, b) if a < b else (b, a)
        signals.setdefault(key, set()).add(sig)
        suppress.setdefault(key, []).extend(edges)

    attr_links: dict[str, list[tuple[str, str]]] = {}
    for e in graph.edges:
        if e.source in platform_ids and e.target in platform_ids and e.source != e.target:
            note(e.source, e.target, e.type, [(e.source, e.target, e.type)])
        elif e.type in _ATTR_EDGE_TYPES and e.source in platform_ids:
            attr_links.setdefault(e.target, []).append((e.source, e.type))
    for attr_nid, links in attr_links.items():
        members = {src for src, _ in links}
        if len(members) != 2:
            continue
        (a, a_type), (b, _b_type) = sorted(links)[:2]
        edges = [(src, attr_nid, et) for src, et in links]
        note(a, b, a_type, edges)

    out: list[dict[str, Any]] = []
    for (a, b), sigs in signals.items():
        if a not in profiles or b not in profiles:
            continue
        if sigs & _STRONG_PAIR_SIGNALS:
            continue
        identity_sigs = sigs - {"shared_infrastructure"}
        weak_only = bool(identity_sigs) and identity_sigs <= _WEAK_PAIR_SIGNALS
        da, db = profiles[a].get("display_name"), profiles[b].get("display_name")
        conflict = (
            "shared_username" in sigs
            and bool(da and db)
            and canonical_name(str(da)) != canonical_name(str(db))
        )
        if not (weak_only or conflict):
            continue
        out.append({
            "a": a,
            "b": b,
            "signals": sorted(sigs),
            "conflict": conflict,
            # Only identity edges are suppressible; infrastructure edges are not
            # a same-person claim and are left alone.
            "suppress": sorted({e for e in suppress[(a, b)] if e[2] in _SUPPRESSIBLE}),
        })
    out.sort(key=lambda p: (not p["conflict"], -len(p["signals"]), p["a"], p["b"]))
    return out[:MAX_PAIRS_PER_RUN]


async def refine_graph(graph: Any, findings: list[dict[str, Any]]) -> None:
    """Ask JEV about borderline pairs and apply yes/no to the built graph.

    ``yes`` keeps/creates a ``same_person`` edge; ``no`` stops the pair's
    heuristic edges from merging clusters; ``unclear``/DEFER leaves today's
    heuristic decision in place. Correlation/display layer only.
    """
    if not jev.is_active():
        return
    try:
        profiles = _profiles(findings)
        pairs = ambiguous_pairs(graph, profiles)
        if not pairs:
            return
        results = await asyncio.gather(*(
            jev.judge(SAME_PERSON, {
                "a": Profile(**profiles[p["a"]]).model_dump(),
                "b": Profile(**profiles[p["b"]]).model_dump(),
                "avatar_match": False,  # a pair with an avatar/photo match is never sent
                "heuristic_signals": p["signals"][:8],
            })
            for p in pairs
        ))
        applied: list[dict[str, Any]] = []
        review: list[dict[str, Any]] = []
        for pair, verdict in zip(pairs, results):
            decision = "defer" if verdict is jev.DEFER else verdict.output.same_person
            review.append({
                "a": graph.nodes[pair["a"]].value,
                "b": graph.nodes[pair["b"]].value,
                "signals": pair["signals"],
                "heuristic_merge": True,
                "jev": decision,
            })
            if decision in ("yes", "no"):
                applied.append({
                    "a": pair["a"], "b": pair["b"], "verdict": decision,
                    "suppress": pair["suppress"], "task": SAME_PERSON,
                })
        graph.jev_review = review
        graph.apply_same_person_verdicts(applied)
    except Exception:
        _LOG.exception("JEV identity-graph refinement skipped")
