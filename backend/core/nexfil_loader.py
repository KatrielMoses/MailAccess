from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)
_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "nexfil_sites.json"

_SITES_CACHE: dict[str, dict[str, Any]] | None = None
_META_CACHE: dict[str, Any] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_from_file() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if not _DATA_PATH.exists():
        _LOG.warning("Nexfil data file not found: %s", _DATA_PATH)
        return {}, {"source": "nexfil", "site_count": 0, "partial": True, "loaded_at": _now()}

    try:
        payload = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("Failed to load Nexfil data file: %s", exc)
        return {}, {"source": "nexfil", "site_count": 0, "partial": True, "loaded_at": _now()}

    raw_sites: dict[str, Any] = payload.get("sites", {}) if isinstance(payload, dict) else {}
    sites: dict[str, dict[str, Any]] = {}
    skipped = 0
    valid_types = {"status_code", "message", "response_url", "api"}
    for name, defn in raw_sites.items():
        if not isinstance(defn, dict):
            skipped += 1
            continue
        if not defn.get("url") or not defn.get("error_type"):
            _LOG.warning("Nexfil site %r missing url or error_type, skipping", name)
            skipped += 1
            continue
        if defn.get("error_type") not in valid_types:
            _LOG.warning(
                "Nexfil site %r has unsupported error_type %r, skipping",
                name,
                defn.get("error_type"),
            )
            skipped += 1
            continue
        sites[str(name)] = defn

    if skipped:
        _LOG.info("Nexfil loader: skipped %d invalid site definitions", skipped)

    upstream_meta = payload.get("_meta", {}) if isinstance(payload, dict) else {}
    meta: dict[str, Any] = {
        "source": "nexfil",
        "upstream": upstream_meta.get("upstream", "thewhiteh4t/nexfil"),
        "site_count": len(sites),
        "partial": skipped > 0,
        "loaded_at": _now(),
    }
    return sites, meta


async def load_nexfil_sites() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return validated, cached Nexfil sites in Sherlock-compatible form."""
    global _SITES_CACHE, _META_CACHE
    if _SITES_CACHE is not None:
        return _SITES_CACHE, _META_CACHE  # type: ignore[return-value]
    sites, meta = _load_from_file()
    _SITES_CACHE = sites
    _META_CACHE = meta
    return sites, meta
