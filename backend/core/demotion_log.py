"""Append-only JSONL audit log for Phase 6D auto-demotion / auto-upgrade events.

Every auto-action — skip, demote, upgrade — writes one line to
``~/.mailaccess/platform_demotion.log``. This is the user-facing audit trail
that backs ``mailaccess platform-audit --show-demotions``.

Design rules:

* Append-only. We never rewrite history. If the file is missing, create it
  with the parent directory. If it's malformed at the tail, we still append —
  we never refuse to record an event because of a corrupted line.
* One JSON object per line. Each line is independently parseable.
* ``stats`` captures the snapshot that triggered the action so analysts can
  reconstruct why a platform was skipped/demoted/upgraded.
* ``reversible_via`` names the env var that disables this auto-action, e.g.
  ``MAIGRET_FORCE_NOISYSITECOM=true`` for ``NoisySite.com``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

_VALID_ACTIONS = frozenset({"skip", "demote", "upgrade"})

_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")


def demotion_log_path() -> Path:
    """Return the canonical location of the platform_demotion.log file."""
    home = os.environ.get("HOME")
    base = Path(home) if home else Path.home()
    return base / ".mailaccess" / "platform_demotion.log"


def env_var_key_for(platform: str) -> str:
    """Map a platform name to its env-var override key.

    Rules:
      * uppercase
      * strip non-alphanumeric characters (so ``NoisySite.com`` -> ``NOISYSITECOM``)

    Examples:
      >>> env_var_key_for("NoisySite.com")
      'MAIGRET_FORCE_NOISYSITECOM'
      >>> env_var_key_for("github")
      'MAIGRET_FORCE_GITHUB'
    """
    stripped = _NON_ALNUM_RE.sub("", platform or "").upper()
    if not stripped:
        # Degenerate platform names still need *some* key. Use a placeholder so
        # the audit trail never silently drops the override hint.
        stripped = "UNKNOWN"
    return f"MAIGRET_FORCE_{stripped}"


def log_event(
    platform: str,
    action: str,
    stats: dict[str, Any],
    reason: str,
    reversible_via: str | None = None,
    *,
    path: Path | None = None,
) -> Path:
    """Append a single demotion/upgrade event to the JSONL log.

    Args:
        platform: the platform name (e.g. ``"NoisySite.com"``).
        action: one of ``"skip"``, ``"demote"``, ``"upgrade"``.
        stats: snapshot of probe stats that triggered the action. Must be
            JSON-serializable. At minimum: ``inconclusive_rate``, ``hit_rate``,
            ``total_probes``. Other keys are preserved verbatim.
        reason: short human-readable string explaining why this action fired.
        reversible_via: env var name that disables this auto-action. Defaults
            to the standard ``MAIGRET_FORCE_{KEY}`` derived from ``platform``.
        path: override the log file path (mostly for tests). Defaults to
            ``~/.mailaccess/platform_demotion.log``.

    Returns:
        The path the event was appended to.

    Raises:
        ValueError: if ``action`` is not a known action.
    """
    if action not in _VALID_ACTIONS:
        raise ValueError(
            f"Unknown demotion log action: {action!r}. "
            f"Expected one of: {sorted(_VALID_ACTIONS)}"
        )

    target = path or demotion_log_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platform": str(platform),
        "action": action,
        "reason": str(reason),
        "stats": dict(stats) if isinstance(stats, dict) else {},
        "reversible_via": reversible_via or env_var_key_for(platform),
    }

    line = json.dumps(record, ensure_ascii=False, sort_keys=False)
    try:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        # We refuse to crash an investigation because the audit log failed
        # to write — but the user needs to know.
        _LOG.warning("platform_demotion_log: failed to append: %s", exc)

    return target


def read_recent_events(
    *,
    since: datetime | None = None,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    """Read events from the log, optionally filtered by timestamp.

    Malformed lines are skipped silently — the file is append-only and a
    partially-written line at the tail is recoverable.

    Args:
        since: only return events with ``timestamp`` at or after this UTC
            datetime. ``None`` returns every event.
        path: override the log file path. Defaults to the canonical location.

    Returns:
        A list of event dicts, oldest first.
    """
    target = path or demotion_log_path()
    if not target.exists():
        return []

    cutoff_iso: str | None = None
    if since is not None:
        cutoff_iso = since.isoformat()

    out: list[dict[str, Any]] = []
    try:
        with open(target, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                if cutoff_iso is not None:
                    ts = str(record.get("timestamp") or "")
                    if ts and ts < cutoff_iso:
                        continue
                out.append(record)
    except OSError:
        return out
    return out


def count_recent_by_action(
    *,
    since: datetime | None = None,
    path: Path | None = None,
) -> dict[str, int]:
    """Tally event counts grouped by action.

    Useful for the platform-audit summary line.
    """
    events = read_recent_events(since=since, path=path)
    counts: dict[str, int] = {"skip": 0, "demote": 0, "upgrade": 0}
    for ev in events:
        action = str(ev.get("action") or "")
        if action in counts:
            counts[action] += 1
    return counts