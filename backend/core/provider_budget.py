"""Phase 7B — reusable per-provider monthly free-tier budget.

Generalizes the Hunter.io monthly circuit-breaker (``hunter_client``) into a
provider-agnostic counter so every BYO enrichment key (Apollo, People Data
Labs, ...) gets the same guarantees:

* **Per-provider persistent monthly counter.** State lives in
  ``~/.mailaccess/<provider>_usage.json`` (``{month, calls, last_reset}``) so a
  cap survives process restarts within the same calendar month and resets
  automatically on a month boundary.
* **Reserve-before-call.** :func:`reserve` increments *and persists* before the
  API request returns, so a crash never frees a counted slot and a free tier is
  never silently overrun. Returns ``False`` once the monthly limit is hit.
* **Atomic, guarded writes.** ``tempfile.mkstemp`` + ``os.replace``; a read or
  write failure degrades to a fresh in-memory counter and never raises.

Hunter keeps its own dedicated tracker (two independent capability counters);
new single-capability enrichment connectors use this module. The waterfall
(``enrichment_waterfall``) calls :func:`reserve` per provider so it can spread
lookups across BYO keys and stop touching a provider the moment its free tier
is exhausted.

These are the *operator's own* keys and quotas — never ours. When a provider's
limit is configured as ``0`` (or negative) the provider is treated as unbudgeted
disabled and :func:`reserve` returns ``False``.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

#: Base directory for per-provider usage files (mirrors Hunter's location).
_DEFAULT_USAGE_DIR = "~/.mailaccess"

# Test-only override for the whole usage directory. When set, every provider's
# counter is redirected under this directory, isolating tests from a real
# ``~/.mailaccess`` and from each other.
_USAGE_DIR_OVERRIDE: str | None = None

# One lock per provider, created on demand under this guard.
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.Lock] = {}


def set_usage_dir_for_tests(path: str | None) -> None:
    """Test-only: redirect all provider usage files under *path*.

    Pass ``None`` to clear the override and revert to env-var / default
    resolution.
    """
    global _USAGE_DIR_OVERRIDE
    _USAGE_DIR_OVERRIDE = path


def _lock_for(provider: str) -> threading.Lock:
    with _LOCKS_GUARD:
        lock = _LOCKS.get(provider)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[provider] = lock
        return lock


def _resolve_usage_path(provider: str) -> Path:
    """Return the active path for *provider*'s usage JSON file.

    Precedence: per-provider env var (``MAILACCESS_<PROVIDER>_USAGE_PATH``) →
    test dir override → default ``~/.mailaccess/<provider>_usage.json``.
    """
    env_key = f"MAILACCESS_{provider.upper()}_USAGE_PATH"
    raw = os.environ.get(env_key)
    if raw:
        return Path(os.path.expanduser(raw))
    base = _USAGE_DIR_OVERRIDE or _DEFAULT_USAGE_DIR
    return Path(os.path.expanduser(base)) / f"{provider}_usage.json"


def _current_month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


@dataclass
class _Usage:
    month: str
    calls: int = 0
    last_reset: str = ""

    def reset_for(self, month: str) -> None:
        self.month = month
        self.calls = 0
        self.last_reset = f"{month}-01T00:00:00Z"


def _read_usage(provider: str) -> _Usage:
    """Read *provider*'s persistent counter; never raises.

    Resets in-memory when the persisted month differs from the current calendar
    month (the on-disk file is left untouched until the next write reserves a
    slot).
    """
    path = _resolve_usage_path(provider)
    current = _current_month()
    fresh = _Usage(month=current, last_reset=f"{current}-01T00:00:00Z")
    if not path.exists():
        return fresh
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _LOG.warning("%s usage file unreadable (%s); resetting to %s", provider, exc, current)
        return fresh
    if not isinstance(payload, dict):
        return fresh
    month = str(payload.get("month") or "")
    if month != current:
        return fresh
    try:
        calls = max(0, int(payload.get("calls")))
    except (TypeError, ValueError):
        calls = 0
    return _Usage(
        month=month,
        calls=calls,
        last_reset=str(payload.get("last_reset") or f"{month}-01T00:00:00Z"),
    )


def _write_usage(provider: str, usage: _Usage) -> None:
    """Persist *usage* atomically; never raises."""
    path = _resolve_usage_path(provider)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _LOG.warning("%s usage dir creation failed: %s", provider, exc)
        return
    try:
        fd, tmp = tempfile.mkstemp(prefix=f"{provider}-usage-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {"month": usage.month, "calls": usage.calls, "last_reset": usage.last_reset},
                    fh,
                )
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        _LOG.warning("%s usage file write failed: %s", provider, exc)


def reserve(provider: str, limit: int) -> bool:
    """Reserve one call slot for *provider*; return False when the cap is hit.

    Durable: the increment is written to disk before returning. Warns when two
    or fewer calls remain. A ``limit`` of ``0`` or less means the provider is
    disabled/unbudgeted and no slot is ever granted.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return False
    with _lock_for(provider):
        current = _current_month()
        usage = _read_usage(provider)
        if usage.month != current:
            usage.reset_for(current)
        if usage.calls >= limit:
            _LOG.warning("%s: monthly free-tier quota exhausted (%d).", provider, limit)
            return False
        usage.calls += 1
        _write_usage(provider, usage)
        remaining = limit - usage.calls
    if 0 <= remaining <= 2:
        _LOG.warning(
            "%s: %d free-tier call%s remaining this month.",
            provider,
            remaining,
            "" if remaining == 1 else "s",
        )
    return True


def usage_count(provider: str) -> int:
    """This month's persisted call count for *provider*."""
    with _lock_for(provider):
        return _read_usage(provider).calls


def remaining(provider: str, limit: int) -> int:
    """Calls left this month for *provider* against *limit* (never negative)."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 0
    return max(0, limit - usage_count(provider))


def circuit_open(provider: str, limit: int) -> bool:
    """True when *provider* has reached *limit* this month (no slots left)."""
    return remaining(provider, limit) <= 0


def snapshot(provider: str) -> dict[str, Any]:
    """Read-only view of *provider*'s current-month usage."""
    with _lock_for(provider):
        usage = _read_usage(provider)
    return {
        "provider": provider,
        "month": usage.month,
        "calls": usage.calls,
        "last_reset": usage.last_reset,
    }
