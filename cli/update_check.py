"""Self-contained PyPI update notifier + soft-enforcement for the CLI.

All network, cache, comparison and enforcement logic lives here; ``cli.main``
only wires it in. PyPI is the single source of truth.

Design guarantees:
  * Zero added latency — the current run never waits on the network. A daemon
    thread refreshes the cache when it is older than the TTL; the notice and
    the escalation guard read ONLY the cache (i.e. the *previous* run's
    result). Standard "check now, notify next run" pattern.
  * Best-effort — every network / cache path swallows its own exceptions and
    degrades to a no-op. Uncertainty (missing / stale / failed lookup) never
    escalates, never notifies, never crashes a command.
  * stderr only — nothing here ever writes to stdout, so piped JSON/CSV stays
    clean. The notice is additionally gated on ``stderr.isatty()``.

Historical note: this notifier can only act on the release that ships it and
later releases. It cannot reach back and notify or enforce anything on versions
published before it — there is no retroactive mechanism.
"""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────────
_PYPI_URL = "https://pypi.org/pypi/mailaccess/json"
_CHANGELOG_URL = "https://pypi.org/project/mailaccess/#history"
_CACHE_FILE = Path.home() / ".mailaccess" / "update_check.json"
_HTTP_TIMEOUT = 1.5  # seconds, total
_TTL_SECONDS = 24 * 60 * 60  # 24h

# Escalation applies ONLY to these network / stateful commands. Every other
# (read-only / util) command never blocks, even when badly outdated.
_NETWORK_COMMANDS = frozenset(
    {"investigate", "harvest-emails", "find-email", "discover", "serve"}
)

# Commands whose end-of-run notice is suppressed to avoid noise.
_NOTICE_SUPPRESSED_COMMANDS = frozenset({"version", "upgrade"})

# Set once from the app callback (mirrors the global --allow-outdated flag).
_allow_outdated_flag = False
# atexit is process-global; guard against double registration / double print.
_notice_registered = False


# ── Small helpers ────────────────────────────────────────────────────────────
def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _installed_version() -> str:
    from backend.config import APP_VERSION

    return str(APP_VERSION)


def set_allow_outdated(value: bool) -> None:
    """Record the global ``--allow-outdated`` flag from the app callback."""
    global _allow_outdated_flag
    _allow_outdated_flag = bool(value)


def _allow_outdated() -> bool:
    return _allow_outdated_flag or _env_true("MAILACCESS_ALLOW_OUTDATED")


# ── PyPI lookup (best-effort) ─────────────────────────────────────────────────
def _fetch_latest() -> str | None:
    """Return the latest version string from PyPI, or ``None`` on any failure."""
    try:
        import httpx

        resp = httpx.get(_PYPI_URL, timeout=_HTTP_TIMEOUT)
        if resp.status_code != 200:
            return None
        version = resp.json().get("info", {}).get("version")
        return str(version) if version else None
    except Exception:
        return None


# ── Cache (atomic writes) ─────────────────────────────────────────────────────
def _read_cache() -> dict[str, Any] | None:
    try:
        with open(_CACHE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "latest" in data and "checked_at" in data:
            return data
    except Exception:
        return None
    return None


def _write_cache(latest: str) -> None:
    tmp_path: str | None = None
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "latest": str(latest),
        }
        fd, tmp_path = tempfile.mkstemp(
            dir=str(_CACHE_FILE.parent), prefix=".update_check.", suffix=".tmp"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp_path, _CACHE_FILE)  # atomic
        tmp_path = None
    except Exception:
        pass
    finally:
        if tmp_path is not None:
            with contextlib.suppress(Exception):
                os.unlink(tmp_path)


def _cache_is_stale(cache: dict[str, Any]) -> bool:
    try:
        checked = datetime.fromisoformat(str(cache["checked_at"]))
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        return age > _TTL_SECONDS
    except Exception:
        return True


def _confident_latest() -> str | None:
    """The latest version we are confident about: a present, non-stale cache.

    Both the notice and the escalation guard rely on this — a missing or stale
    cache yields ``None`` (uncertainty), so neither fires.
    """
    cache = _read_cache()
    if cache is None or _cache_is_stale(cache):
        return None
    latest = cache.get("latest")
    return str(latest) if latest else None


# ── Version comparison (packaging, never hand-rolled) ─────────────────────────
def _is_older(installed: str, latest: str) -> bool:
    try:
        from packaging.version import parse

        return parse(installed) < parse(latest)
    except Exception:
        return False


def _is_minor_or_more_behind(installed: str, latest: str) -> bool:
    """True iff ``latest`` is a full MINOR (or major) ahead of ``installed``.

    Patch-only gaps never qualify. Any parse failure yields ``False`` (allow).
    """
    try:
        from packaging.version import parse

        i_rel = parse(installed).release
        l_rel = parse(latest).release
        i_major = i_rel[0] if len(i_rel) > 0 else 0
        i_minor = i_rel[1] if len(i_rel) > 1 else 0
        l_major = l_rel[0] if len(l_rel) > 0 else 0
        l_minor = l_rel[1] if len(l_rel) > 1 else 0
        if l_major > i_major:
            return True
        return l_major == i_major and l_minor > i_minor
    except Exception:
        return False


# ── Background refresh (never blocks the current run) ─────────────────────────
def start_background_refresh() -> None:
    """Spawn a daemon thread that refreshes the cache if older than the TTL.

    Independent of ``MAILACCESS_NO_UPDATE_CHECK`` (which silences only the
    *notice*): the escalation guard needs a fresh cache to work, so the refresh
    keeps running. The current process never waits on this thread.
    """

    def _worker() -> None:
        try:
            cache = _read_cache()
            if cache is not None and not _cache_is_stale(cache):
                return  # fresh enough — no network, zero cost
            latest = _fetch_latest()
            if latest:
                _write_cache(latest)
        except Exception:
            pass

    try:
        threading.Thread(
            target=_worker, name="mailaccess-update-check", daemon=True
        ).start()
    except Exception:
        pass


# ── End-of-command notice (stderr only, from cache) ───────────────────────────
def _notice_enabled(command: str | None, no_banner: bool) -> bool:
    if not sys.stderr.isatty():
        return False
    if _env_true("MAILACCESS_NO_UPDATE_CHECK"):
        return False
    if no_banner:
        return False
    if command in _NOTICE_SUPPRESSED_COMMANDS:
        return False
    return True


def _render_notice(err_console: Any, installed: str, latest: str) -> None:
    err_console.print("[yellow]── Update available ─────────────────────────────[/yellow]")
    err_console.print(f"  MailAccess [bold]{latest}[/bold] is out — you're on {installed}.")
    err_console.print(f"  Changelog: {_CHANGELOG_URL}")
    err_console.print("  Upgrade:   [bold cyan]mailaccess upgrade[/bold cyan]")
    err_console.print("[yellow]─────────────────────────────────────────────────[/yellow]")


def _print_notice(err_console: Any, command: str | None, no_banner: bool) -> None:
    try:
        if not _notice_enabled(command, no_banner):
            return
        latest = _confident_latest()
        if latest is None:
            return
        installed = _installed_version()
        if not _is_older(installed, latest):
            return
        _render_notice(err_console, installed, latest)
    except Exception:
        pass


def register_exit_notice(err_console: Any, command: str | None, no_banner: bool) -> None:
    """Register the end-of-command notice via ``atexit``.

    Runs after the command completes — including on error / non-zero exit —
    and renders purely from cache (no inline network).
    """
    global _notice_registered
    if _notice_registered:
        return
    _notice_registered = True
    atexit.register(_print_notice, err_console, command, no_banner)


# ── Soft-enforcement escalation (cache-only, before the command body) ─────────
def enforce_or_exit(command: str, err_console: Any) -> None:
    """Block a network command when the client is a full minor+ behind.

    No-op unless ``command`` is a network command, we have a confident (fresh)
    latest, and ``installed`` is a full minor (or major) behind. Bypassed by the
    ``--allow-outdated`` flag or ``MAILACCESS_ALLOW_OUTDATED=1``. Uses ONLY
    cached data — never performs an inline network call.
    """
    if command not in _NETWORK_COMMANDS:
        return
    try:
        if _allow_outdated():
            return
        latest = _confident_latest()
        if latest is None:
            return
        installed = _installed_version()
        should_block = _is_minor_or_more_behind(installed, latest)
    except Exception:
        return  # uncertainty => allow
    if not should_block:
        return

    import typer

    err_console.print(
        f"[bold red]Your MailAccess {installed} is multiple releases behind "
        f"{latest} and may be unsupported. Run: mailaccess upgrade[/bold red]"
    )
    err_console.print(
        "[dim]Bypass for this run with --allow-outdated or "
        "MAILACCESS_ALLOW_OUTDATED=1.[/dim]"
    )
    raise typer.Exit(code=2)


# ── `mailaccess upgrade` ──────────────────────────────────────────────────────
def _detect_pipx() -> bool:
    if os.environ.get("PIPX_HOME"):
        return True
    probe = f"{sys.prefix} {sys.argv[0] if sys.argv else ''}".lower()
    return "pipx" in probe


def _upgrade_command() -> list[str]:
    if _detect_pipx():
        return ["pipx", "upgrade", "mailaccess"]
    return [sys.executable, "-m", "pip", "install", "-U", "mailaccess"]


def _installed_after_upgrade() -> str | None:
    """Best-effort detection of the version now on disk after an upgrade."""
    try:
        import importlib
        import importlib.metadata as im

        importlib.invalidate_caches()
        return im.version("mailaccess")
    except Exception:
        pass
    try:
        out = subprocess.run(
            [sys.executable, "-m", "pip", "show", "mailaccess"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in out.stdout.splitlines():
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def run_upgrade(assume_yes: bool, console: Any, err_console: Any) -> int:
    """Upgrade MailAccess in place (pip or pipx). Never uses sudo."""
    cmd = _upgrade_command()
    shown = " ".join(shlex.quote(part) for part in cmd)

    console.print("This will upgrade MailAccess by running:")
    console.print(f"  [bold]{shown}[/bold]")
    if not assume_yes:
        import typer

        if not typer.confirm("Proceed?", default=True):
            console.print("Upgrade aborted.")
            return 1

    try:
        completed = subprocess.run(cmd)  # streams output to the inherited fds
        return_code = completed.returncode
    except (PermissionError, FileNotFoundError, OSError) as exc:
        err_console.print(f"[red]Upgrade could not run:[/red] {exc}")
        err_console.print("Run this yourself:")
        err_console.print(f"  {shown}")
        err_console.print(
            "[dim]If this is a permissions error, use your environment manager "
            "(venv / pipx / pip --user). Never use sudo.[/dim]"
        )
        return 1

    if return_code != 0:
        err_console.print(f"[red]Upgrade command exited with status {return_code}.[/red]")
        err_console.print("Run this yourself:")
        err_console.print(f"  {shown}")
        err_console.print(
            "[dim]If this is a permissions error, use your environment manager "
            "(venv / pipx / pip --user). Never use sudo.[/dim]"
        )
        return return_code

    # Success — refresh the cache so the next run's state is accurate.
    with contextlib.suppress(Exception):
        latest = _fetch_latest()
        if latest:
            _write_cache(latest)

    new_version = _installed_after_upgrade()
    if new_version:
        console.print(
            f"[green]MailAccess upgraded to {new_version}. Re-run your command.[/green]"
        )
    else:
        console.print("[green]MailAccess upgraded. Re-run your command.[/green]")
    return 0
