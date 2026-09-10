"""
Persistent platform health tracker backed by SQLite.

Schema (probe_log):
    id               INTEGER PRIMARY KEY AUTOINCREMENT
    platform         TEXT NOT NULL
    domain           TEXT
    outcome          TEXT NOT NULL  -- 'hit' | 'miss' | 'inconclusive'
    latency_ms       INTEGER
    content_length   INTEGER
    probed_at        TEXT NOT NULL  -- ISO 8601 UTC

Index:
    idx_probe_log_platform_time ON probe_log(platform, probed_at)
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import logging
import math
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

# One lock guards both the module-level singleton and all DB operations.
# Public methods acquire it; __init__/_migrate run during construction before
# any other thread has a reference, so they skip the lock safely.
_LOCK = threading.Lock()
_INSTANCE: PlatformHealthDB | None = None

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS probe_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    platform        TEXT NOT NULL,
    domain          TEXT,
    outcome         TEXT NOT NULL,
    latency_ms      INTEGER,
    content_length  INTEGER,
    probed_at       TEXT NOT NULL
)"""

_CREATE_INDEX = """\
CREATE INDEX IF NOT EXISTS idx_probe_log_platform_time
    ON probe_log(platform, probed_at)"""

# 0.12.7 — Per-source health from harvest module runs.
# One row per (module_name, started_at) — ``status`` is one of
# ``success``/``partial``/``failed``/``skipped`` (mirrors ModuleStatus
# values).  ``duration_seconds`` is the wall-clock time the module
# spent running; ``probed_at`` is the moment the row was inserted.
_CREATE_MODULE_RUNS_TABLE = """\
CREATE TABLE IF NOT EXISTS module_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name      TEXT NOT NULL,
    domain           TEXT,
    status           TEXT NOT NULL,
    duration_seconds REAL,
    started_at       TEXT,
    probed_at        TEXT NOT NULL
)"""

_CREATE_MODULE_RUNS_INDEX = """\
CREATE INDEX IF NOT EXISTS idx_module_runs_module_time
    ON module_runs(module_name, probed_at)"""


def _cutoff_ts(window_days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()


def _parse_ts(value: Any) -> datetime | None:
    """Parse an ISO-8601 ``probed_at`` string into an aware UTC datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── Availability-based health gating ───────────────────────────────────────────
# Health measures whether the PLATFORM/detector is working, NOT whether the probed
# target happens to have an account there. A ``hit`` or a ``miss`` both prove the
# probe reached the site and the detector produced a verdict, so both count as
# "available"; only ``inconclusive`` (timeout / WAF / transport / broken detector)
# counts against availability. This is the root-cause fix for the old
# consecutive-miss / low-hit-rate gates, which conflated ordinary target negatives
# (most people have no account on most sites) with platform death and slowly
# disabled healthy popular platforms.
_UNAVAILABLE_OUTCOME = "inconclusive"
_HEALTH_WINDOW_DAYS = 30
# Need a meaningful sample before we're willing to disable anything.
_HEALTH_MIN_PROBES = 20
# Disable only when the platform is almost entirely inconclusive (genuinely broken),
# not merely low-yield.
_HEALTH_MAX_UNAVAIL_RATE = 0.90
# Even when disabled, re-probe after this backoff so a transient outage self-heals
# (expiring backoff — no permanent death).
_HEALTH_BACKOFF_MINUTES = 60.0


class PlatformHealthDB:
    """SQLite-backed per-platform probe outcome tracker."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            home = os.environ.get("HOME")
            base = Path(home) if home else Path.home()
            db_path = base / ".mailaccess" / "platform_health.db"
        db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(db_path.parent, 0o700)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.execute(_CREATE_INDEX)
        self._conn.execute(_CREATE_MODULE_RUNS_TABLE)
        self._conn.execute(_CREATE_MODULE_RUNS_INDEX)
        self._conn.commit()
        atexit.register(self.close)

    # ── writes ────────────────────────────────────────────────────────────────

    def record_probe(
        self,
        platform: str,
        domain: str | None,
        outcome: str,
        latency_ms: int,
        content_length: int,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        try:
            with _LOCK:
                self._conn.execute(
                    "INSERT INTO probe_log"
                    " (platform, domain, outcome, latency_ms, content_length, probed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (platform, domain, outcome, latency_ms, content_length, ts),
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            _LOG.warning("platform_health: record_probe failed: %s", exc)

    def clear(self, platform: str) -> None:
        with _LOCK:
            self._conn.execute("DELETE FROM probe_log WHERE platform = ?", (platform,))
            self._conn.commit()

    # ── 0.12.7 module-level health tracking ───────────────────────────────────

    def record_module_run(
        self,
        module_name: str,
        domain: str | None,
        status: str,
        duration_seconds: float | None,
        started_at: str | None = None,
    ) -> None:
        """Record one harvest-module execution for the per-source health view.

        ``status`` should be a ModuleStatus value (or any lowercase
        token — the column has no CHECK constraint).  ``duration_seconds``
        is the wall-clock time the module spent running; ``None`` is
        permitted for runtimes that don't know how long they took
        (e.g. crashes before the timer started).  ``started_at`` is
        the ISO 8601 string the caller used to start the timer (stored
        for cross-referencing with the JSON export); ``probed_at`` is
        the moment the row was actually inserted.
        """
        ts = datetime.now(timezone.utc).isoformat()
        try:
            with _LOCK:
                self._conn.execute(
                    "INSERT INTO module_runs"
                    " (module_name, domain, status, duration_seconds, started_at, probed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        str(module_name),
                        str(domain) if domain is not None else None,
                        str(status),
                        float(duration_seconds) if duration_seconds is not None else None,
                        str(started_at) if started_at is not None else None,
                        ts,
                    ),
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            _LOG.warning("platform_health: record_module_run failed: %s", exc)

    def get_module_health(
        self,
        module_name: str,
        *,
        window_hours: int = 24,
    ) -> dict[str, Any]:
        """Return the rolling-window health snapshot for one module.

        Returns a dict with ``module_name``, ``total_runs``,
        ``avg_duration_seconds`` (``None`` when no data), ``success_rate``
        (a float in ``[0.0, 1.0]``), ``last_status``, and ``last_run_at``.
        A module is considered "successful" when ``status`` is in
        ``{"success", "complete"}`` (the canonical ModuleStatus values
        for a clean run); partial / failed / skipped are all "not
        successful" for this metric.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours)
        ).isoformat()
        with _LOCK:
            rows = self._conn.execute(
                "SELECT status, duration_seconds, probed_at FROM module_runs"
                " WHERE module_name = ? AND probed_at >= ?"
                " ORDER BY probed_at DESC, id DESC",
                (module_name, cutoff),
            ).fetchall()
        total = len(rows)
        successes = sum(1 for r in rows if str(r["status"]).lower() in {"success", "complete"})
        durations = [
            float(r["duration_seconds"])
            for r in rows
            if r["duration_seconds"] is not None
        ]
        avg_duration = round(sum(durations) / len(durations), 2) if durations else None
        success_rate = round(successes / total, 3) if total else 0.0
        last_status = str(rows[0]["status"]) if rows else None
        last_run_at = str(rows[0]["probed_at"]) if rows else None
        return {
            "module_name": module_name,
            "total_runs": total,
            "avg_duration_seconds": avg_duration,
            "success_rate": success_rate,
            "last_status": last_status,
            "last_run_at": last_run_at,
        }

    def get_all_module_names(self) -> list[str]:
        """Distinct module names that have at least one record."""
        with _LOCK:
            rows = self._conn.execute(
                "SELECT DISTINCT module_name FROM module_runs ORDER BY module_name"
            ).fetchall()
        return [str(r["module_name"]) for r in rows]

    # ── reads ─────────────────────────────────────────────────────────────────

    def get_hit_rate(self, platform: str, window_days: int = 30) -> float:
        """Rolling hit rate in [0.0, 1.0] over the given window."""
        cutoff = _cutoff_ts(window_days)
        with _LOCK:
            rows = self._conn.execute(
                "SELECT outcome FROM probe_log WHERE platform = ? AND probed_at >= ?",
                (platform, cutoff),
            ).fetchall()
        if not rows:
            return 0.0
        hits = sum(1 for r in rows if r["outcome"] == "hit")
        return round(hits / len(rows), 3)

    def get_consecutive_misses(self, platform: str) -> int:
        """Count uninterrupted misses from the most recent probe backwards."""
        with _LOCK:
            rows = self._conn.execute(
                "SELECT outcome FROM probe_log WHERE platform = ?"
                " ORDER BY probed_at DESC, id DESC",
                (platform,),
            ).fetchall()
        count = 0
        for row in rows:
            if row["outcome"] == "miss":
                count += 1
            else:
                break
        return count

    def should_probe(self, platform: str, force: bool = False) -> bool:
        """Return False only when the PLATFORM itself looks unavailable.

        Availability is read from *conclusive* verdicts: a ``hit`` or a ``miss`` both
        prove the probe reached the site and the detector produced an answer, so
        neither disables the platform. Many valid targets simply have no account on a
        given site, and those legitimate negatives must never look like platform
        death. Only ``inconclusive`` outcomes (timeout / WAF / transport / broken
        detector) count against availability, and a disabled platform is re-probed
        after ``_HEALTH_BACKOFF_MINUTES`` so a transient outage self-heals.

        ``force`` (mirroring the ``MAILACCESS_DISABLE_HEALTH`` env override and the
        per-platform ``USERNAME_FORCE_*`` flags) bypasses the gate entirely, applied
        consistently across every caller.
        """
        if force or os.environ.get("MAILACCESS_DISABLE_HEALTH") == "1":
            return True
        with _LOCK:
            rows = self._conn.execute(
                "SELECT outcome, probed_at FROM probe_log"
                " WHERE platform = ? AND probed_at >= ?"
                " ORDER BY probed_at DESC, id DESC",
                (platform, _cutoff_ts(_HEALTH_WINDOW_DAYS)),
            ).fetchall()
        if len(rows) < _HEALTH_MIN_PROBES:
            # Not enough evidence to declare a platform dead — a run of legitimate
            # target-misses can never trip this.
            return True
        unavailable = sum(1 for r in rows if r["outcome"] == _UNAVAILABLE_OUTCOME)
        if unavailable / len(rows) < _HEALTH_MAX_UNAVAIL_RATE:
            # The platform is producing conclusive verdicts → it is responsive.
            return True
        # Platform looks unavailable. Allow a periodic recovery probe so a transient
        # outage doesn't disable it forever.
        last_at = _parse_ts(rows[0]["probed_at"])
        if last_at is None:
            return True
        age_minutes = (datetime.now(timezone.utc) - last_at).total_seconds() / 60.0
        return age_minutes >= _HEALTH_BACKOFF_MINUTES

    # ── async wrappers for use in async contexts ───────────────────────────────

    async def should_probe_async(self, platform: str, force: bool = False) -> bool:
        """Async version of should_probe — runs the blocking sqlite3 call in a thread."""
        return await asyncio.to_thread(self.should_probe, platform, force)

    def recovery_due(self, platform: str, backoff_minutes: float | None = None) -> bool:
        """R10 (S4): whether a platform is due a bounded-time RECOVERY probe.

        A platform demoted/skipped by a *later* health gate (Phase-6D skip set)
        would otherwise never be probed again until its stats age out of the
        window — stranding a site that has since recovered for weeks. This lets
        such a platform through occasionally (last probe older than the health
        backoff, or never probed) so a recovery self-heals within a bounded time.
        """
        backoff = _HEALTH_BACKOFF_MINUTES if backoff_minutes is None else backoff_minutes
        with _LOCK:
            row = self._conn.execute(
                "SELECT MAX(probed_at) AS last FROM probe_log WHERE platform = ?",
                (platform,),
            ).fetchone()
        last = row["last"] if row else None
        last_at = _parse_ts(last) if last else None
        if last_at is None:
            return True
        age_minutes = (datetime.now(timezone.utc) - last_at).total_seconds() / 60.0
        return age_minutes >= backoff

    async def recovery_due_async(
        self, platform: str, backoff_minutes: float | None = None
    ) -> bool:
        return await asyncio.to_thread(self.recovery_due, platform, backoff_minutes)

    async def record_probe_async(
        self,
        platform: str,
        domain: str | None,
        outcome: str,
        latency_ms: int,
        content_length: int,
    ) -> None:
        """Async version of record_probe — runs the blocking sqlite3 call in a thread."""
        return await asyncio.to_thread(
            self.record_probe, platform, domain, outcome, latency_ms, content_length
        )

    def get_fragility_score(self, platform: str, window_days: int = 30) -> float:
        """Fragility in [0.0, 1.0]: 0.6 × inconclusive_rate + 0.4 × latency_variance_normalized."""
        cutoff = _cutoff_ts(window_days)
        with _LOCK:
            rows = self._conn.execute(
                "SELECT outcome, latency_ms FROM probe_log"
                " WHERE platform = ? AND probed_at >= ?",
                (platform, cutoff),
            ).fetchall()
        if len(rows) < 5:
            return 0.0
        total = len(rows)
        inconclusive = sum(1 for r in rows if r["outcome"] == "inconclusive")
        inconclusive_rate = inconclusive / total

        latencies = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
        if len(latencies) >= 2:
            mean = sum(latencies) / len(latencies)
            variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
            stddev = math.sqrt(variance)
            latency_variance_normalized = min(stddev / 1000.0, 1.0)
        else:
            latency_variance_normalized = 0.0

        score = 0.6 * inconclusive_rate + 0.4 * latency_variance_normalized
        return round(min(score, 1.0), 3)

    def get_stats(self, platform: str, window_days: int = 30) -> dict[str, Any]:
        cutoff = _cutoff_ts(window_days)
        with _LOCK:
            window_rows = self._conn.execute(
                "SELECT outcome FROM probe_log WHERE platform = ? AND probed_at >= ?",
                (platform, cutoff),
            ).fetchall()
            span = self._conn.execute(
                "SELECT MIN(probed_at) AS first_seen, MAX(probed_at) AS last_seen"
                " FROM probe_log WHERE platform = ?",
                (platform,),
            ).fetchone()
            latency_row = self._conn.execute(
                "SELECT AVG(latency_ms) AS avg_lat"
                " FROM probe_log"
                " WHERE platform = ? AND probed_at >= ? AND latency_ms IS NOT NULL",
                (platform, cutoff),
            ).fetchone()
        total = len(window_rows)
        hits = sum(1 for r in window_rows if r["outcome"] == "hit")
        misses = sum(1 for r in window_rows if r["outcome"] == "miss")
        inconclusive = total - hits - misses
        avg_latency_ms = (
            int(round(float(latency_row["avg_lat"])))
            if latency_row and latency_row["avg_lat"] is not None
            else 0
        )
        return {
            "platform": platform,
            "total_probes": total,
            "hits": hits,
            "misses": misses,
            "inconclusive": inconclusive,
            "hit_rate": self.get_hit_rate(platform, window_days),
            "fragility": self.get_fragility_score(platform, window_days),
            "consecutive_misses": self.get_consecutive_misses(platform),
            "window_days": window_days,
            "first_seen": span["first_seen"] if span else None,
            "last_seen": span["last_seen"] if span else None,
            "avg_latency_ms": avg_latency_ms,
        }

    def get_noisiest_platforms(
        self, limit: int = 20, window_days: int = 30
    ) -> list[dict[str, Any]]:
        """Platforms with ≥ 10 probes in the window, ranked by inconclusive rate DESC."""
        cutoff = _cutoff_ts(window_days)
        with _LOCK:
            rows = self._conn.execute(
                "SELECT platform,"
                " COUNT(*) AS total,"
                " SUM(CASE WHEN outcome = 'inconclusive' THEN 1 ELSE 0 END) AS inc"
                " FROM probe_log WHERE probed_at >= ?"
                " GROUP BY platform HAVING total >= 10"
                " ORDER BY CAST(inc AS REAL) / total DESC"
                " LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        return [self.get_stats(row["platform"], window_days) for row in rows]

    # ── phase 6D auto-demotion / auto-upgrade ──────────────────────────────────

    def get_skip_set(
        self,
        min_probes: int = 50,
        *,
        window_days: int = 30,
        freshness_days: int = 14,
    ) -> set[str]:
        """Platforms meeting Phase 6D SKIP criteria.

        A platform is in the skip set when, over the rolling ``window_days`` window:
          * ``total_probes > min_probes`` (default 50)
          * ``inconclusive_rate > 0.70``
          * ``MAX(probed_at)`` is within ``freshness_days`` (default 14 days)

        The freshness check ensures we never re-skip a platform that hasn't been
        probed recently — stale stats must not trigger demotion. The wave
        classification is intentionally not consulted here; SKIP is wave-agnostic.
        """
        cutoff_window = _cutoff_ts(window_days)
        cutoff_fresh = _cutoff_ts(freshness_days)
        with _LOCK:
            rows = self._conn.execute(
                "SELECT platform,"
                " COUNT(*) AS total,"
                " SUM(CASE WHEN outcome = 'inconclusive' THEN 1 ELSE 0 END) AS inc,"
                " MAX(probed_at) AS last_probed"
                " FROM probe_log WHERE probed_at >= ?"
                " GROUP BY platform HAVING total > ?",
                (cutoff_window, min_probes),
            ).fetchall()
        skip: set[str] = set()
        for row in rows:
            total = int(row["total"] or 0)
            inc = int(row["inc"] or 0)
            if total <= 0:
                continue
            inconclusive_rate = inc / total
            if inconclusive_rate <= 0.70:
                continue
            last_probed = str(row["last_probed"] or "")
            if not last_probed or last_probed < cutoff_fresh:
                continue
            skip.add(str(row["platform"]))
        return skip

    def get_demote_set(
        self,
        min_probes: int = 30,
        wave1_names: set[str] | None = None,
        *,
        window_days: int = 30,
    ) -> set[str]:
        """Platforms meeting Phase 6D DEMOTE criteria.

        A platform is in the demote set when, over the rolling window:
          * ``total_probes > min_probes`` (default 30)
          * ``inconclusive_rate > 0.40``
          * ``platform_health`` knows about it AND
            * if ``wave1_names`` is provided, the platform is currently Wave 1
            * if ``wave1_names`` is ``None``, wave filtering is skipped and
              every platform meeting the inconclusive/probes thresholds is
              returned (caller can post-filter as needed)

        The freshness constraint is intentionally looser than SKIP/UPGRADE —
        a noisy Wave-1 platform is still worth demoting even on slightly stale
        data, because the consequence is scheduling, not skipping.
        """
        cutoff_window = _cutoff_ts(window_days)
        with _LOCK:
            rows = self._conn.execute(
                "SELECT platform,"
                " COUNT(*) AS total,"
                " SUM(CASE WHEN outcome = 'inconclusive' THEN 1 ELSE 0 END) AS inc"
                " FROM probe_log WHERE probed_at >= ?"
                " GROUP BY platform HAVING total > ?",
                (cutoff_window, min_probes),
            ).fetchall()
        demote: set[str] = set()
        for row in rows:
            total = int(row["total"] or 0)
            inc = int(row["inc"] or 0)
            if total <= 0:
                continue
            inconclusive_rate = inc / total
            if inconclusive_rate <= 0.40:
                continue
            name = str(row["platform"])
            if wave1_names is not None and name not in wave1_names:
                continue
            demote.add(name)
        return demote

    def get_upgrade_set(
        self,
        min_probes: int = 30,
        wave2_names: set[str] | None = None,
        *,
        window_days: int = 30,
        freshness_days: int = 30,
    ) -> set[str]:
        """Platforms meeting Phase 6D UPGRADE criteria (Wave 2 → Wave 1).

        A platform is in the upgrade set when, over the rolling window:
          * ``total_probes > min_probes`` (default 30)
          * ``inconclusive_rate < 0.10``
          * ``MAX(probed_at)`` is within ``freshness_days`` (default 30 days)
            — never promote on stale stats.
          * if ``wave2_names`` is provided, the platform is currently Wave 2.

        ``wave2_names=None`` disables wave filtering — caller is responsible
        for ensuring only Wave-2 candidates reach the upgrade logic.
        """
        cutoff_window = _cutoff_ts(window_days)
        cutoff_fresh = _cutoff_ts(freshness_days)
        with _LOCK:
            rows = self._conn.execute(
                "SELECT platform,"
                " COUNT(*) AS total,"
                " SUM(CASE WHEN outcome = 'inconclusive' THEN 1 ELSE 0 END) AS inc,"
                " MAX(probed_at) AS last_probed"
                " FROM probe_log WHERE probed_at >= ?"
                " GROUP BY platform HAVING total > ?",
                (cutoff_window, min_probes),
            ).fetchall()
        upgrade: set[str] = set()
        for row in rows:
            total = int(row["total"] or 0)
            inc = int(row["inc"] or 0)
            if total <= 0:
                continue
            inconclusive_rate = inc / total
            if inconclusive_rate >= 0.10:
                continue
            last_probed = str(row["last_probed"] or "")
            if not last_probed or last_probed < cutoff_fresh:
                continue
            name = str(row["platform"])
            if wave2_names is not None and name not in wave2_names:
                continue
            upgrade.add(name)
        return upgrade

    def get_all_platforms_stats(
        self,
        min_probes: int = 1,
        window_days: int = 30,
    ) -> list[dict[str, Any]]:
        """One-shot stats for every platform in the window with at least ``min_probes`` probes.

        Efficient: aggregates hits / misses / avg_latency / span in three queries per platform
        via ``get_stats``, but the platform-name enumeration is a single DISTINCT query.
        """
        names = self.all_platform_names()
        results: list[dict[str, Any]] = []
        for name in names:
            stats = self.get_stats(name, window_days)
            if int(stats.get("total_probes") or 0) >= min_probes:
                results.append(stats)
        return results

    def all_platform_names(self) -> list[str]:
        """Return every distinct platform name that has at least one record."""
        with _LOCK:
            rows = self._conn.execute(
                "SELECT DISTINCT platform FROM probe_log ORDER BY platform"
            ).fetchall()
        return [row["platform"] for row in rows]

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        with _LOCK:
            try:
                self._conn.commit()
                self._conn.close()
            except Exception:
                pass


# ── module-level singleton ────────────────────────────────────────────────────


def get_health_db() -> PlatformHealthDB:
    """Return the process-wide PlatformHealthDB singleton (created on first call)."""
    global _INSTANCE
    if _INSTANCE is not None:
        return _INSTANCE
    with _LOCK:
        if _INSTANCE is None:
            _INSTANCE = PlatformHealthDB()
        return _INSTANCE
