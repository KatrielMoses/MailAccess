"""
Dataset curator — health-DB driven prune recommendations.

Phase 3G. Reads probe outcomes from `PlatformHealthDB` and flags platforms whose
hit rate / consecutive-miss pattern indicates they're dead or FP-heavy. The
output is a `CuratorReport` with one `PruneRecommendation` per flagged platform.

This module is intentionally **read-only with respect to source data** —
it never edits `data/sherlock_sites.json`, `data/wmn_sites.json`,
`data/nexfil_sites.json`, or any per-platform probe log. Curators are
**advisory**: a `CuratorReport` can be logged, returned from an API, or
hand-applied by an operator. The actual loader-side auto-skipping is gated
behind a future `dataset_curator_auto_prune` flag and lives in the loaders,
not here.

Why advisory-only by default?
    - Hit-rate is a lagging signal: a new platform needs ≥ N probes before the
      rate stabilizes, and a sudden burst of legitimate hits on a previously
      dead-looking platform is plausible (e.g. service revival, cache flush).
    - Per-investigation noise: a 0% hit rate over 8 probes might just mean the
      last 8 usernames happened to be uncommon — not that the platform is dead.
    - Module owners (sherlock vs blackbird vs nexfil) need to interpret the
      signal differently; one global auto-pruner would over-fit.

Public surface:
    Curator                        — orchestrator class
    CuratorReport                  — top-level container
    PruneRecommendation            — single-platform recommendation
    curate()                       — module-level convenience wrapper
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

from .platform_health import PlatformHealthDB

_LOG = logging.getLogger(__name__)


# Curator thresholds. Conservative by design — false positives (recommending
# pruning a healthy platform) are worse than false negatives (failing to prune
# a dead one), because pruning silently removes signal from results.
DEFAULT_HIT_RATE_FLOOR = 0.02          # < 2% hits over the window → suspicious
DEFAULT_MAX_CONSECUTIVE_MISSES = 15   # ≥ 15 misses in a row → almost certainly dead
DEFAULT_MIN_WINDOW_PROBES = 20        # need at least this many probes to be flagged
DEFAULT_WINDOW_DAYS = 30              # health-DB rolling window


@dataclass
class PruneRecommendation:
    """A single platform flagged for pruning."""

    platform: str
    reason: str
    hit_rate: float
    consecutive_misses: int
    total_probes: int
    inconclusive_rate: float
    fragility: float
    window_days: int

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "reason": self.reason,
            "hit_rate": self.hit_rate,
            "consecutive_misses": self.consecutive_misses,
            "total_probes": self.total_probes,
            "inconclusive_rate": self.inconclusive_rate,
            "fragility": self.fragility,
            "window_days": self.window_days,
        }


@dataclass
class CuratorReport:
    """Aggregate curator output."""

    recommendations: list[PruneRecommendation] = field(default_factory=list)
    scanned_platforms: int = 0
    window_days: int = DEFAULT_WINDOW_DAYS
    thresholds: dict[str, float | int] = field(default_factory=dict)
    generated_at: str = ""

    @property
    def platform_count(self) -> int:
        return len(self.recommendations)

    def platforms(self) -> list[str]:
        return [r.platform for r in self.recommendations]

    def to_dict(self) -> dict:
        return {
            "recommendations": [r.to_dict() for r in self.recommendations],
            "scanned_platforms": self.scanned_platforms,
            "platform_count": self.platform_count,
            "window_days": self.window_days,
            "thresholds": dict(self.thresholds),
            "generated_at": self.generated_at,
        }


class Curator:
    """Health-DB driven prune recommender.

    Usage::

        curator = Curator()
        report = curator.generate_report()
        for rec in report.recommendations:
            print(rec.platform, rec.reason)
    """

    def __init__(
        self,
        db: PlatformHealthDB | None = None,
        *,
        hit_rate_floor: float = DEFAULT_HIT_RATE_FLOOR,
        max_consecutive_misses: int = DEFAULT_MAX_CONSECUTIVE_MISSES,
        min_window_probes: int = DEFAULT_MIN_WINDOW_PROBES,
        window_days: int = DEFAULT_WINDOW_DAYS,
    ) -> None:
        self._db = db if db is not None else PlatformHealthDB()
        self._hit_rate_floor = hit_rate_floor
        self._max_consecutive_misses = max_consecutive_misses
        self._min_window_probes = min_window_probes
        self._window_days = window_days

    def generate_report(
        self,
        *,
        platforms: Iterable[str] | None = None,
    ) -> CuratorReport:
        """Scan the health DB and emit prune recommendations.

        Args:
            platforms: If provided, only inspect these platform names.
                Default: scan every platform with at least one probe record.
        """
        from datetime import datetime, timezone

        names = list(platforms) if platforms is not None else self._db.all_platform_names()

        recommendations: list[PruneRecommendation] = []
        for name in names:
            stats = self._db.get_stats(name, window_days=self._window_days)
            rec = self._evaluate(name, stats)
            if rec is not None:
                recommendations.append(rec)

        # Stable sort: worst hit-rate first, then by consecutive misses.
        recommendations.sort(
            key=lambda r: (r.hit_rate, -r.consecutive_misses, r.platform),
        )

        return CuratorReport(
            recommendations=recommendations,
            scanned_platforms=len(names),
            window_days=self._window_days,
            thresholds={
                "hit_rate_floor": self._hit_rate_floor,
                "max_consecutive_misses": self._max_consecutive_misses,
                "min_window_probes": self._min_window_probes,
            },
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _evaluate(
        self,
        platform: str,
        stats: dict,
    ) -> PruneRecommendation | None:
        """Apply thresholds to one platform's stats. Return a recommendation or None."""
        total = int(stats.get("total_probes") or 0)
        if total < self._min_window_probes:
            return None

        hit_rate = float(stats.get("hit_rate") or 0.0)
        consecutive_misses = int(stats.get("consecutive_misses") or 0)
        inconclusive = int(stats.get("inconclusive") or 0)
        inconclusive_rate = inconclusive / total if total else 0.0
        fragility = float(stats.get("fragility") or 0.0)

        # Reason selection — first matching rule wins.
        reason: str | None = None
        if consecutive_misses >= self._max_consecutive_misses:
            reason = (
                f"{consecutive_misses} consecutive misses "
                f"(>= {self._max_consecutive_misses})"
            )
        elif hit_rate < self._hit_rate_floor:
            reason = (
                f"hit_rate {hit_rate:.3f} below floor "
                f"{self._hit_rate_floor:.3f} over {self._window_days}d"
            )

        if reason is None:
            return None

        return PruneRecommendation(
            platform=platform,
            reason=reason,
            hit_rate=hit_rate,
            consecutive_misses=consecutive_misses,
            total_probes=total,
            inconclusive_rate=round(inconclusive_rate, 3),
            fragility=fragility,
            window_days=self._window_days,
        )


# ── module-level convenience ─────────────────────────────────────────────────


def curate(
    db: PlatformHealthDB | None = None,
    *,
    hit_rate_floor: float = DEFAULT_HIT_RATE_FLOOR,
    max_consecutive_misses: int = DEFAULT_MAX_CONSECUTIVE_MISSES,
    min_window_probes: int = DEFAULT_MIN_WINDOW_PROBES,
    window_days: int = DEFAULT_WINDOW_DAYS,
    platforms: Iterable[str] | None = None,
) -> CuratorReport:
    """Convenience wrapper around `Curator(...).generate_report(...)`.

    Provided so callers can `from backend.core.dataset_curator import curate`.
    """
    return Curator(
        db=db,
        hit_rate_floor=hit_rate_floor,
        max_consecutive_misses=max_consecutive_misses,
        min_window_probes=min_window_probes,
        window_days=window_days,
    ).generate_report(platforms=platforms)


def log_report(report: CuratorReport, *, logger: logging.Logger | None = None) -> None:
    """Emit one INFO log line per recommendation. Safe to call repeatedly.

    The first call after process start prints a header summarizing thresholds;
    subsequent calls only log individual recommendations so logs stay readable.
    """
    log = logger or _LOG
    if not report.recommendations:
        log.info(
            "dataset_curator: no prune recommendations "
            "(scanned %d platforms over %dd, hit_rate_floor=%.3f)",
            report.scanned_platforms,
            report.window_days,
            float(report.thresholds.get("hit_rate_floor", DEFAULT_HIT_RATE_FLOOR)),
        )
        return

    log.info(
        "dataset_curator: %d prune recommendation(s) over %dd "
        "(hit_rate_floor=%.3f, max_consec_miss=%d, min_probes=%d)",
        report.platform_count,
        report.window_days,
        float(report.thresholds.get("hit_rate_floor", DEFAULT_HIT_RATE_FLOOR)),
        int(report.thresholds.get("max_consecutive_misses", DEFAULT_MAX_CONSECUTIVE_MISSES)),
        int(report.thresholds.get("min_window_probes", DEFAULT_MIN_WINDOW_PROBES)),
    )
    for rec in report.recommendations:
        log.info(
            "dataset_curator: prune %s — %s "
            "(hit_rate=%.3f, consec_miss=%d, n=%d)",
            rec.platform,
            rec.reason,
            rec.hit_rate,
            rec.consecutive_misses,
            rec.total_probes,
        )
