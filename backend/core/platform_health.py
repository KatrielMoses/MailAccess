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


def _cutoff_ts(window_days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()


class PlatformHealthDB:
    """SQLite-backed per-platform probe outcome tracker."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            home = os.environ.get("HOME")
            base = Path(home) if home else Path.home()
            db_path = base / ".mailaccess" / "platform_health.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.execute(_CREATE_INDEX)
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

    def should_probe(self, platform: str) -> bool:
        """Return False when health data indicates the platform is consistently dead."""
        if os.environ.get("MAILACCESS_DISABLE_HEALTH") == "1":
            return True
        if self.get_consecutive_misses(platform) >= 10:
            return False
        cutoff = _cutoff_ts(30)
        with _LOCK:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM probe_log WHERE platform = ? AND probed_at >= ?",
                (platform, cutoff),
            ).fetchone()[0]
        if total >= 30 and self.get_hit_rate(platform, 30) < 0.05:
            return False
        return True

    # ── async wrappers for use in async contexts ───────────────────────────────

    async def should_probe_async(self, platform: str) -> bool:
        """Async version of should_probe — runs the blocking sqlite3 call in a thread."""
        return await asyncio.to_thread(self.should_probe, platform)

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
