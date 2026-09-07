"""Phase 6A — confidence decay in the corpus.

B2B contact data rots ~25–30%/yr (Doc-2 A4): a person changes jobs, an address
starts bouncing, a role is backfilled. The corpus is read-first and compounding,
so without decay a *growing* corpus quietly becomes a *rotting* one — the
50–123× read-first speedup would be paid for by serving stale-but-fast data at
full confidence.

This module down-weights an aging corpus row's confidence as a function of how
long ago we last verified/observed it (``contacts.last_verified``, modelled in
1D), and flags a row that has aged past a threshold for re-verification rather
than serving it blind. It is a pure, explainable transform applied at *serve*
time over the ``contacts`` projection:

* it never mutates the stored confidence — a re-verification simply refreshes
  ``last_verified`` and the served score returns to full strength;
* it never touches the parity-preserving crawl reconstruction (``read_fresh_crawl``
  stays byte-identical) — only the compounding lead projection is decayed;
* a **fresh** row is unchanged (factor 1.0), so fresh-data results never regress.

Model. The retained fraction after ``age_days`` is a geometric decay keyed
directly to the annual rot rate::

    factor = (1 - annual_rot) ** (age_days / 365)

so a brand-new row keeps factor ``1.0`` and a one-year-old row is down-weighted
to ``1 - annual_rot`` (≈0.72 at the 28% default), two years to ≈0.52, and so on.
A configurable floor keeps a very old row from decaying to a misleading zero. A
row older than ``stale_after_days`` is additionally flagged
``needs_reverification`` so a stale-but-served row is never presented as fresh.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..config import settings

_DAYS_PER_YEAR = 365.0


def _enabled() -> bool:
    return bool(getattr(settings, "enable_corpus_decay", True))


def _annual_rot() -> float:
    # Fraction of confidence lost after one year without re-verification.
    return max(0.0, min(0.99, float(getattr(settings, "corpus_decay_annual_rot", 0.28))))


def _min_factor() -> float:
    return max(0.0, min(1.0, float(getattr(settings, "corpus_decay_min_factor", 0.3))))


def _stale_after_days() -> int:
    return int(getattr(settings, "corpus_decay_stale_after_days", 180))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    # SQLite returns naive datetimes even for tz-aware columns; treat naive as UTC
    # so an aware "now" and a naive stored value compare correctly.
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def age_days(last_verified: datetime | None, now: datetime | None = None) -> float | None:
    """Age of our knowledge in days, or ``None`` when ``last_verified`` is unknown."""
    if not isinstance(last_verified, datetime):
        return None
    reference = now or _now()
    return max(0.0, (reference - _aware(last_verified)).total_seconds() / 86400.0)


def decay_factor(last_verified: datetime | None, now: datetime | None = None) -> float:
    """Confidence multiplier in ``[min_factor, 1.0]`` for a row's age.

    ``1.0`` for a fresh row (or when decay is disabled, or when the age is
    unknown — we never *invent* rot). Geometric in the annual rot rate, floored.
    """
    if not _enabled():
        return 1.0
    days = age_days(last_verified, now)
    if days is None:
        return 1.0
    factor = (1.0 - _annual_rot()) ** (days / _DAYS_PER_YEAR)
    return max(_min_factor(), factor)


def is_stale(last_verified: datetime | None, now: datetime | None = None) -> bool:
    """Whether a row has aged past ``stale_after_days`` and needs re-verification.

    Unknown age is *not* treated as stale here (we cannot judge it); such a row
    still carries a distinct reason in :func:`decay` for surfacing.
    """
    if not _enabled():
        return False
    threshold = _stale_after_days()
    if threshold <= 0:
        return False
    days = age_days(last_verified, now)
    if days is None:
        return False
    return days >= threshold


@dataclass(frozen=True)
class DecayResult:
    """Explainable outcome of decaying one served confidence score."""

    served_score: float | None
    factor: float
    age_days: float | None
    stale: bool
    reason: str


def decay(
    confidence_score: float | None,
    last_verified: datetime | None,
    now: datetime | None = None,
) -> DecayResult:
    """Apply age decay to one served confidence, explainably.

    Returns the down-weighted ``served_score`` (``confidence_score * factor``),
    the ``factor`` and ``age_days`` that produced it, and a ``stale`` flag. The
    raw ``confidence_score`` is never mutated by this function; the caller keeps
    it alongside the served value.
    """
    reference = now or _now()
    days = age_days(last_verified, reference)
    factor = decay_factor(last_verified, reference)
    stale = is_stale(last_verified, reference)

    if not _enabled():
        reason = "decay disabled"
    elif days is None:
        reason = "no last_verified (age unknown; served at full confidence)"
    elif stale:
        reason = f"aged {days:.0f}d ≥ {_stale_after_days()}d stale threshold"
    elif factor >= 0.999:
        reason = "fresh"
    else:
        reason = f"aged {days:.0f}d; down-weighted ×{factor:.3f}"

    served: float | None
    if confidence_score is None:
        served = None
    else:
        served = round(float(confidence_score) * factor, 6)

    return DecayResult(
        served_score=served,
        factor=round(factor, 6),
        age_days=None if days is None else round(days, 3),
        stale=stale,
        reason=reason,
    )


def decay_view(
    confidence_score: float | None,
    last_verified: datetime | None,
    now: datetime | None = None,
) -> dict[str, object]:
    """A serialisable decay descriptor for embedding in a served lead row."""
    result = decay(confidence_score, last_verified, now)
    return {
        "served_confidence_score": result.served_score,
        "decay_factor": result.factor,
        "age_days": result.age_days,
        "needs_reverification": result.stale,
        "reason": result.reason,
        "annual_rot": _annual_rot() if _enabled() else 0.0,
    }
