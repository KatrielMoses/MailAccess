"""Seven-day probe cache for the username sweep and pivot (UC4).

One row per (site_key, handle): the outcome (found / missing / inconclusive), the
parsed profile fields when found, a SHA-256 of the response body and when it was
checked. A repeat search inside the TTL reads SQLite instead of the network.

* ``found`` / ``missing`` rows serve for ``probe_cache_ttl_days`` (7).
* ``inconclusive`` rows (a 429, a timeout, a challenge) serve only for
  ``probe_cache_inconclusive_ttl_seconds`` (1 h): long enough that a repeat search
  makes no requests, short enough that a site's bad minute isn't remembered for a week.
* Rows older than twice the TTL are deleted once per process (on first use).
* ``set_no_cache_read(True)`` (CLI ``--no-cache``) skips reads for this run; results
  are still written. ``probe_cache_enabled = false`` turns the cache off entirely.

Never raises: any SQLite problem degrades to "no cache".
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)
_NO_READ: ContextVar[bool] = ContextVar("mailaccess_probe_cache_no_read", default=False)
_LOCK = threading.Lock()
_CONN: sqlite3.Connection | None = None
_CONN_PATH: Path | None = None
_OUTCOME = {"hit": "found", "miss": "missing"}
_BACK = {"found": "hit", "missing": "miss", "inconclusive": "inconclusive"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_cache (
    site_key   TEXT NOT NULL,
    handle     TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    fields     TEXT,
    resp_hash  TEXT,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (site_key, handle)
);
CREATE INDEX IF NOT EXISTS idx_cache_age ON probe_cache (checked_at);
"""


def set_no_cache_read(value: bool):
    return _NO_READ.set(bool(value))


def _settings():
    from ..config import settings

    return settings


def enabled() -> bool:
    return bool(getattr(_settings(), "probe_cache_enabled", True))


def reads_enabled() -> bool:
    return enabled() and not _NO_READ.get()


def cache_path() -> Path:
    raw = Path(str(getattr(_settings(), "probe_cache_path", "data/probe_cache.db")))
    if raw.is_absolute():
        return raw
    root = Path(__file__).resolve().parents[2]  # the project root, where data/ lives
    candidate = root / raw
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        probe = candidate.parent / ".probe_cache_write_test"
        probe.touch()
        probe.unlink()
        return candidate
    except OSError:  # an installed, read-only package: keep it under the user's home
        return Path.home() / ".mailaccess" / raw.name


def _connection() -> sqlite3.Connection | None:
    global _CONN, _CONN_PATH
    path = cache_path()
    if _CONN is not None and _CONN_PATH == path:
        return _CONN
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=5.0)
        # WAL + NORMAL: a sweep writes ~1,500 rows; per-row fsync would stall the loop.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)
        ttl_days = int(getattr(_settings(), "probe_cache_ttl_days", 7) or 7)
        conn.execute(  # cleanup: older than twice the TTL
            "DELETE FROM probe_cache WHERE checked_at < ?",
            (_iso_days_ago(2 * ttl_days),),
        )
        conn.commit()
    except sqlite3.Error as exc:
        _LOG.debug("probe cache unavailable: %s", exc)
        return None
    _CONN, _CONN_PATH = conn, path
    return conn


def _iso_days_ago(days: float) -> str:
    from datetime import timedelta

    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def site_key(defn: dict[str, Any], name: str) -> str:
    return str(defn.get("id") or name)


def get(defn: dict[str, Any], name: str, handle: str) -> dict[str, Any] | None:
    """``{"outcome": hit|miss|inconclusive, "fields": {...}, "age_days": n,
    "checked_at": iso}`` when a fresh row exists and reads are on; else None."""
    if not reads_enabled():
        return None
    with _LOCK:
        conn = _connection()
        if conn is None:
            return None
        try:
            row = conn.execute(
                "SELECT outcome, fields, checked_at FROM probe_cache WHERE site_key=? AND handle=?",
                (site_key(defn, name), handle),
            ).fetchone()
        except sqlite3.Error:
            return None
    if not row:
        return None
    outcome, fields, checked_at = row
    try:
        checked = datetime.fromisoformat(checked_at)
    except ValueError:
        return None
    age_s = (datetime.now(timezone.utc) - checked).total_seconds()
    s = _settings()
    ttl_s = (float(getattr(s, "probe_cache_inconclusive_ttl_seconds", 3600))
             if outcome == "inconclusive"
             else float(getattr(s, "probe_cache_ttl_days", 7)) * 86400)
    if age_s < 0 or age_s > ttl_s:
        return None
    try:
        parsed = json.loads(fields) if fields else {}
    except ValueError:
        parsed = {}
    return {"outcome": _BACK.get(outcome, "inconclusive"), "fields": parsed,
            "age_days": int(age_s // 86400), "checked_at": checked_at}


def put(defn: dict[str, Any], name: str, handle: str, outcome: str,
        fields: dict[str, Any] | None = None, resp_hash: str | None = None) -> None:
    if not enabled():
        return
    stored = _OUTCOME.get(outcome, "inconclusive")
    with _LOCK:
        conn = _connection()
        if conn is None:
            return
        try:
            conn.execute(
                "INSERT OR REPLACE INTO probe_cache VALUES (?, ?, ?, ?, ?, ?)",
                (site_key(defn, name), handle, stored,
                 json.dumps(fields, ensure_ascii=False) if fields else None, resp_hash,
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        except sqlite3.Error as exc:
            _LOG.debug("probe cache write failed: %s", exc)


def checked_ago(age_days: int) -> str:
    return "checked today" if age_days <= 0 else (
        "checked 1 day ago" if age_days == 1 else f"checked {age_days} days ago")
