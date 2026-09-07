"""Run manifest capture for the Phase 0 baseline harness.

A manifest is recorded with every baseline run so any result is reproducible
and comparable across phases. It records *what configuration produced a
scorecard* — tool version, git commit, resolved opt-in module set, which API
keys are present, host/python, timestamp, and a config-hash.

SECURITY INVARIANT: this module records API key **names and presence only**.
It never reads, stores, prints, or serializes a key value. The dotenv parser
below deliberately discards everything after the ``=``.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

# Canonical key-name lists, imported from the tool so this never drifts.
try:
    from cli.main import _API_KEYS, _SCRAPINGANT_KEYS

    _KEY_NAMES: list[str] = [n for n, _, _ in _API_KEYS] + [n for n, _, _ in _SCRAPINGANT_KEYS]
except Exception:  # pragma: no cover - defensive: tool import should not block a manifest
    _KEY_NAMES = [
        "HIBP_API_KEY",
        "SERPAPI_KEY",
        "GITHUB_TOKEN",
        "SHODAN_API_KEY",
        "EMAILREP_API_KEY",
        "HUNTER_IO_API_KEY",
        "GOOGLE_CSE_API_KEY",
        "GOOGLE_CSE_CX",
        "COMPANIES_HOUSE_API_KEY",
        "SLACK_WEBHOOK_URL",
        "DISCORD_WEBHOOK_URL",
        "SCRAPINGANT_API_KEY",
    ]

# Opt-in module settings that are OFF by default (the brief's four + maigret).
_OPT_IN_SETTINGS = [
    "enable_breach_deep",
    "enable_ghunt",
    "enable_email_discovery",
    "enable_press_intel",
    "enable_maigret_platforms",
]


def _dotenv_key_names(path: Path) -> set[str]:
    """Return the NAMES of keys defined in a dotenv file. Values are discarded."""
    names: set[str] = set()
    if not path.exists():
        return names
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name = line.split("=", 1)[0].strip()
            # Only record the name; the value half is never touched again.
            if name and name.isupper():
                names.add(name)
    except OSError:
        pass
    return names


def _keys_present() -> dict[str, bool]:
    """Map each known key name -> whether it is set (env or either dotenv).

    Names only. A key is 'present' if it appears in os.environ with a non-empty
    value, or is defined in ~/.mailaccess/.env or ./.env.
    """
    dotenv_names = _dotenv_key_names(Path.home() / ".mailaccess" / ".env")
    dotenv_names |= _dotenv_key_names(REPO_ROOT / ".env")
    present: dict[str, bool] = {}
    for name in _KEY_NAMES:
        env_val = os.environ.get(name)
        present[name] = bool(env_val) or (name in dotenv_names)
    return present


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        return None
    return None


def _git_dirty() -> bool | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return bool(out.stdout.strip())
    except Exception:
        return None
    return None


def _tool_version() -> str | None:
    try:
        out = subprocess.run(
            [sys.executable, "-m", "cli.main", "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(REPO_ROOT),
        )
        if out.returncode == 0:
            # e.g. "mailaccess 0.14.4"
            return out.stdout.strip().split()[-1]
    except Exception:
        return None
    return None


def _sanitized_db_url() -> str | None:
    """Return the DB url with any password component stripped."""
    try:
        from backend.config import settings

        url = str(settings.database_url)
    except Exception:
        return None
    # Strip user:pass@ if present (postgres). SQLite urls have no creds.
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        if "@" in rest:
            _creds, host = rest.split("@", 1)
            return f"{scheme}://<redacted>@{host}"
    return url


def _resolved_config() -> dict[str, Any]:
    """Whitelisted, non-secret slice of resolved settings."""
    cfg: dict[str, Any] = {}
    try:
        from backend.config import settings
    except Exception:
        return {"error": "backend.config import failed"}

    for name in _OPT_IN_SETTINGS:
        cfg[name] = bool(getattr(settings, name, False))
    for name in (
        "harvest_auto_export",
        "harvest_results_max_per_domain",
        "harvest_results_max_age_days",
    ):
        cfg[name] = getattr(settings, name, None)
    cfg["harvest_results_dir"] = str(getattr(settings, "harvest_results_dir", ""))
    cfg["database_url"] = _sanitized_db_url()
    return cfg


def build_manifest(
    *,
    config_label: str = "keyless-default",
    seed: int | None = None,
    extra: dict[str, Any] | None = None,
    keys_stripped: bool = False,
) -> dict[str, Any]:
    """Build the full run manifest dict.

    ``keys_stripped`` must be True for runs where the harness removed all keys
    from the tool's environment (keyless config). In that case keys_present is
    reported as all-false, because that is what the TOOL actually saw — not what
    the harness's own parent environment happens to hold.
    """
    keys = {n: False for n in _KEY_NAMES} if keys_stripped else _keys_present()
    config = _resolved_config()
    if keys_stripped:
        # Keyless runs strip every dotenv-defined name, so the tool falls back to
        # code defaults. Report those, not the harness parent's dotenv values.
        config["enable_breach_deep"] = False
        config["enable_ghunt"] = False
        config["enable_email_discovery"] = False
        config["enable_press_intel"] = False
        config["_note"] = "keyless: dotenv/keys stripped; opt-in toggles shown as code defaults"
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "config_label": config_label,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": _tool_version(),
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "python_executable": sys.executable,
        },
        "seed": seed,
        "resolved_config": config,
        "keys_present": keys,  # names -> bool, NEVER values
        "keys_present_names": sorted(n for n, v in keys.items() if v),
        "opt_in_modules_enabled": sorted(
            n for n in _OPT_IN_SETTINGS if config.get(n) is True
        ),
    }
    if extra:
        manifest["extra"] = extra
    # A stable hash of the config-defining fields, for quick cross-run equality.
    hash_src = json.dumps(
        {
            "tool_version": manifest["tool_version"],
            "resolved_config": config,
            "keys_present": keys,
            "config_label": config_label,
        },
        sort_keys=True,
    )
    manifest["config_hash"] = hashlib.sha256(hash_src.encode()).hexdigest()[:16]
    return manifest


if __name__ == "__main__":
    print(json.dumps(build_manifest(), indent=2))
