"""Phase 1E — field-level provenance & conflict resolution over the 1C ledger.

When several observations assert different values for the same ``(subject,
field)`` — e.g. "VP Engineering" vs "Engineer" for one person's title — this
layer keeps them all as coexisting dated claims and selects the *current best*
with an explainable rule. It never overwrites: losing claims stay in the
append-only ledger and are returned alongside the winner, with the selection
reasoning recorded (machine-readable + human-readable).

Design decisions (exploration latitude in the brief):

* **Scoring reuses the existing source weighting** (``SOURCE_WEIGHTS``) and the
  existing recency curve (``freshness_factor``) from ``email_confidence`` — no
  second weighting is invented. A claim's score is ``source_weight x freshness``.
  Source types absent from ``SOURCE_WEIGHTS`` fall back to a small neutral
  weight, so recency/support still decide (investigate name sources are often
  not in the email-oriented ``SOURCE_WEIGHTS``).
* **Deterministic total order** (so resolution is reproducible): higher score →
  more recent → higher raw source weight → more supporting observations →
  lexical value. Ties never resolve randomly.
* **Computed on read**, not materialized: the ledger is append-only and a
  subject has few observations, so resolution is a cheap read-time projection
  that is always current — no refresh triggers.

Applied first to the fields that exist today (``name`` signals, and the email
``source_type``/``confidence``), proving it on real data before Phase 3 adds
titles/seniority.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from typing import Any

from .email_confidence import SOURCE_WEIGHTS, freshness_factor

logger = logging.getLogger(__name__)

# Source types not present in the email-oriented SOURCE_WEIGHTS fall back to this
# small neutral weight, so a positive score remains and recency/support decide.
_DEFAULT_SOURCE_WEIGHT = 0.30

# Field accessors — where a field's value lives inside a heterogeneous claim.
# Names are scattered across platform-specific metadata keys (see
# name_consensus.extract_name_candidates); titles land in a few keys (Phase 3
# will populate them richly — modelled here now so it's proven first).
_FIELD_KEYS: dict[str, tuple[str, ...]] = {
    "name": (
        "name", "display_name", "full_name", "person_name", "uid_name",
        "author", "author_name", "credit_name", "extracted_name",
        "real_name_from_git", "source_name",
    ),
    "title": ("title", "title_or_role", "role", "job_title", "position", "seniority"),
    "company": ("company", "organization", "employer", "org"),
    # Phase 3A — person fields wired from existing harvest signals (Hunter,
    # company-page structured data, LinkedIn SERP). Additive: unknown fields fall
    # back to their own key, so these only ever *add* resolvable fields.
    "first": ("first", "first_name", "given_name", "givenName"),
    "last": ("last", "last_name", "family_name", "surname", "familyName"),
    "department": ("department", "dept", "division"),
    "linkedin_url": ("linkedin_url", "linkedin", "linkedin_profile", "linkedinUrl"),
    "phone": ("phone", "phone_number", "telephone", "tel", "mobile"),
    "location": ("location", "city", "locality", "region", "geo", "address"),
}
# Fields read from the observation's own columns rather than the claim payload.
_COLUMN_FIELDS = {"source_type", "source_url", "extraction_method"}


@dataclass
class ClaimObservation:
    """A single observation flattened for resolution."""

    observation_id: str
    value: Any
    source_type: str | None
    source_weight: float
    capture_time: datetime
    freshness: float
    score: float
    extraction_method: str
    source_url: str | None = None


@dataclass
class CandidateValue:
    """All observations asserting one distinct value for the field."""

    value: Any
    score: float
    best_source_type: str | None
    best_source_weight: float
    most_recent: datetime
    support_count: int
    observation_ids: list[str] = dataclass_field(default_factory=list)
    best_source_url: str | None = None
    is_winner: bool = False


@dataclass
class FieldResolution:
    subject: str
    field: str
    resolved_value: Any
    winner: CandidateValue
    candidates: list[CandidateValue]
    reasoning: str
    reasoning_data: dict[str, Any]


def _get_from_claim(claim: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(claim, dict):
        return None
    for key in keys:
        value = claim.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    meta = claim.get("metadata")
    if isinstance(meta, dict):
        for key in keys:
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _extract_value(obs: dict[str, Any], field: str) -> Any:
    if field in _COLUMN_FIELDS:
        value = obs.get(field)
        return value.strip() if isinstance(value, str) and value.strip() else value or None
    keys = _FIELD_KEYS.get(field, (field,))
    return _get_from_claim(obs.get("claim"), keys)


def _normalize_value(value: Any) -> str:
    """Grouping key: case/space-insensitive so 'Katriel Moses' == 'katriel  moses'."""
    return " ".join(str(value).split()).casefold()


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _score_observation(obs: dict[str, Any], value: Any) -> ClaimObservation:
    source_type = obs.get("source_type")
    weight = SOURCE_WEIGHTS.get(str(source_type), _DEFAULT_SOURCE_WEIGHT) if source_type \
        else _DEFAULT_SOURCE_WEIGHT
    capture_time = _as_utc(obs.get("capture_time"))
    fresh = freshness_factor(capture_time.isoformat(), str(source_type) if source_type else None)
    return ClaimObservation(
        observation_id=str(obs.get("id") or ""),
        value=value,
        source_type=source_type,
        source_weight=weight,
        capture_time=capture_time,
        freshness=fresh,
        score=round(weight * fresh, 6),
        extraction_method=str(obs.get("extraction_method") or ""),
        source_url=obs.get("source_url"),
    )


def resolve_field(
    observations: list[dict[str, Any]], field: str, subject: str = ""
) -> FieldResolution | None:
    """Resolve one ``(subject, field)`` across observations. None if no claim.

    ``observations`` are dicts with keys: id, claim, source_type, capture_time,
    extraction_method (the shape produced by :func:`gather_observations`).
    """
    scored: list[ClaimObservation] = []
    for obs in observations:
        value = _extract_value(obs, field)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        scored.append(_score_observation(obs, value))
    if not scored:
        return None

    # Group by normalized value.
    groups: dict[str, list[ClaimObservation]] = {}
    for claim in scored:
        groups.setdefault(_normalize_value(claim.value), []).append(claim)

    candidates: list[CandidateValue] = []
    for members in groups.values():
        best = max(
            members,
            key=lambda c: (c.score, c.capture_time, c.source_weight),
        )
        candidates.append(
            CandidateValue(
                value=best.value,  # display form from the strongest observation
                score=max(c.score for c in members),
                best_source_type=best.source_type,
                best_source_weight=best.source_weight,
                most_recent=max(c.capture_time for c in members),
                support_count=len(members),
                observation_ids=[c.observation_id for c in members],
                best_source_url=best.source_url,
            )
        )

    # Deterministic winner ordering (best first).
    candidates.sort(
        key=lambda c: (
            c.score,
            c.most_recent,
            c.best_source_weight,
            c.support_count,
            _normalize_value(c.value),
        ),
        reverse=True,
    )
    winner = candidates[0]
    winner.is_winner = True

    reasoning_data = _build_reasoning(subject, field, winner, candidates[1:])
    reasoning = _build_reasoning_text(field, winner, candidates[1:])
    return FieldResolution(
        subject=subject,
        field=field,
        resolved_value=winner.value,
        winner=winner,
        candidates=candidates,
        reasoning=reasoning,
        reasoning_data=reasoning_data,
    )


def _candidate_dict(candidate: CandidateValue) -> dict[str, Any]:
    return {
        "value": candidate.value,
        "score": candidate.score,
        "source_type": candidate.best_source_type,
        "source_url": candidate.best_source_url,
        "source_weight": candidate.best_source_weight,
        "most_recent": candidate.most_recent.isoformat(),
        "support_count": candidate.support_count,
        "observation_ids": candidate.observation_ids,
    }


def _build_reasoning(
    subject: str, field: str, winner: CandidateValue, losers: list[CandidateValue]
) -> dict[str, Any]:
    return {
        "subject": subject,
        "field": field,
        "resolved_value": winner.value,
        "rule": (
            "max(source_weight x freshness); ties -> recency, source_weight, "
            "support_count, value"
        ),
        "selected_because": _candidate_dict(winner),
        "beat": [_candidate_dict(c) for c in losers],
    }


def _build_reasoning_text(
    field: str, winner: CandidateValue, losers: list[CandidateValue]
) -> str:
    head = (
        f"Selected {field}={winner.value!r} (score {winner.score:.3f} from "
        f"{winner.best_source_type or 'unknown'} x {winner.support_count} source(s))"
    )
    if not losers:
        return head + "; no competing values."
    beaten = ", ".join(f"{c.value!r} ({c.score:.3f})" for c in losers)
    return f"{head}; beat {beaten}."


async def gather_observations(
    subject: str,
    session: Any | None = None,
    *,
    mode: str | None = None,
    as_of: Any | None = None,
) -> list[dict[str, Any]]:
    """Fetch ledger observations for a subject as resolution-ready dicts.

    R12 (S1): scope the observations to a *run* rather than "everything ever
    recorded for this subject", so a later (e.g. security-mode) run cannot leak a
    name/title into an older/public report:

    * ``mode`` — restrict to observations collected under that product mode
      (cross-mode evidence isolation);
    * ``as_of`` — restrict to observations that already existed at the report's
      run time (a later run's facts can't retroactively appear);
    * always drop observations whose retention has expired.
    """
    from datetime import datetime, timezone

    from sqlalchemy import or_, select

    from ..db.models import Observation

    async def _query(s: Any) -> list[dict[str, Any]]:
        conditions = [Observation.subject == subject]
        if mode is not None:
            conditions.append(Observation.mode == str(mode))
        if as_of is not None:
            conditions.append(Observation.created_at <= as_of)
        now = datetime.now(timezone.utc)
        conditions.append(
            or_(Observation.expires_at.is_(None), Observation.expires_at > now)
        )
        rows = (
            await s.execute(select(Observation).where(*conditions))
        ).scalars().all()
        return [
            {
                "id": r.id,
                "claim": r.claim,
                "source_type": r.source_type,
                "source_url": r.source_url,
                "capture_time": r.capture_time,
                "extraction_method": r.extraction_method,
                "mode": r.mode,
            }
            for r in rows
        ]

    if session is not None:
        return await _query(session)
    from ..db.database import AsyncSessionLocal

    async with AsyncSessionLocal() as owned:
        return await _query(owned)


async def resolve_subject_field(
    subject: str, field: str, session: Any | None = None
) -> FieldResolution | None:
    """Resolve a field for a subject directly from the ledger. Guarded → None."""
    try:
        observations = await gather_observations(subject, session=session)
        return resolve_field(observations, field, subject=subject)
    except Exception:
        logger.exception("Field resolution failed for %s.%s", subject, field)
        return None


# Fields resolved for a report today (proven on real data before Phase 3 adds
# titles/seniority — those keys already resolve, they are just usually absent).
_REPORT_FIELDS = ("name", "source_type", "title", "company")


async def resolve_report_fields(
    subject: str,
    session: Any | None = None,
    *,
    mode: str | None = None,
    as_of: Any | None = None,
) -> dict[str, dict[str, Any]]:
    """Resolve the standard report fields for a subject from the ledger.

    Returns ``{field: field_provenance}`` for each field that has at least one
    claim, where each entry carries the resolved value, the machine-readable
    "why this won / what it beat", and the full candidate list (losers included,
    with their observation ids — nothing is discarded). Fully guarded → {}.

    R12 (S1): ``mode`` and ``as_of`` scope the provenance to the report's own run
    (see :func:`gather_observations`) so it can't be polluted by a later or
    different-mode run's observations.
    """
    result: dict[str, dict[str, Any]] = {}
    try:
        observations = await gather_observations(
            subject, session=session, mode=mode, as_of=as_of
        )
    except Exception:
        logger.exception("Field-provenance gather failed for %s", subject)
        return result
    for field in _REPORT_FIELDS:
        resolution = resolve_field(observations, field, subject=subject)
        if resolution is None:
            continue
        result[field] = {
            "resolved_value": resolution.resolved_value,
            "reasoning": resolution.reasoning,
            "reasoning_data": resolution.reasoning_data,
            "candidates": [_candidate_dict(c) | {"is_winner": c.is_winner}
                           for c in resolution.candidates],
        }
    return result
