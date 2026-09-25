"""Content-addressed, TTL-bounded verdict cache for the JEV seam.

Key = sha256(task name + normalized payload + model id + prompt version), so the
same input to the same model under the same prompt replays the same verdict —
for speed and for reproducible side-by-side eval runs. Stored as one small JSON
file per key under ``data/cache/jev/`` (git-ignored) with atomic replace, so
concurrent writers never leave a torn entry.

Only schema-valid model output is cached (never a DEFER); the confidence floor
is applied at read time, so tuning the floor never needs a cache purge. Every
I/O failure is swallowed — the cache is an accelerator, never a dependency.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

_DEFAULT_DIR = Path(__file__).resolve().parents[3] / "data" / "cache" / "jev"
_SCHEMA = 1


def cache_dir(configured: str) -> Path:
    return Path(configured).expanduser() if configured else _DEFAULT_DIR


def normalize_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def cache_key(task: str, normalized_payload: str, model: str, prompt_version: str) -> str:
    material = "\x1f".join((task, normalized_payload, model, prompt_version))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _path(root: Path, task: str, key: str) -> Path:
    return root / task / key[:2] / f"{key}.json"


def read(root: Path, task: str, key: str, ttl_seconds: int) -> dict[str, Any] | None:
    """Return ``{"output": {...}, "confidence": float}`` or None (miss/expired/bad)."""
    if ttl_seconds <= 0:
        return None
    path = _path(root, task, key)
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # missing, unreadable or torn → miss
        return None
    if not isinstance(entry, dict) or entry.get("schema") != _SCHEMA:
        return None
    created = entry.get("created_at")
    if not isinstance(created, int | float) or time.time() - created > ttl_seconds:
        return None
    output, confidence = entry.get("output"), entry.get("confidence")
    if not isinstance(output, dict) or not isinstance(confidence, int | float):
        return None
    return {"output": output, "confidence": float(confidence)}


def write(
    root: Path,
    task: str,
    key: str,
    *,
    output: dict[str, Any],
    confidence: float,
    model: str,
    prompt_version: str,
) -> None:
    path = _path(root, task, key)
    entry = {
        "schema": _SCHEMA,
        "task": task,
        "model": model,
        "prompt_version": prompt_version,
        "created_at": time.time(),
        "output": output,
        "confidence": confidence,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(entry, fh, sort_keys=True)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        _LOG.debug("JEV cache write failed (task=%s): %s", task, type(exc).__name__)
