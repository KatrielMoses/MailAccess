"""Fail-soft persistence for the latest harvest export per domain."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_SAFE = re.compile(r"[^a-z0-9.-]+", re.IGNORECASE)
_ROOT = Path.home() / ".mailaccess" / "cache" / "harvest_history"


def _path(domain: str, root: Path = _ROOT) -> Path:
    safe = _SAFE.sub("_", (domain or "").strip().lower()).strip("._") or "unknown"
    return root / f"{safe}.json"


def load_latest(domain: str, *, root: Path = _ROOT) -> dict[str, Any] | None:
    try:
        payload = json.loads(_path(domain, root).read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def save_latest(domain: str, payload: dict[str, Any], *, root: Path = _ROOT) -> bool:
    """Atomically save a JSON export; return False for any persistence error."""
    try:
        root.mkdir(parents=True, exist_ok=True)
        destination = _path(domain, root)
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
        return True
    except (OSError, TypeError, ValueError):
        return False
