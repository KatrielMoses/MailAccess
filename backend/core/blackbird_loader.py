from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "wmn_sites.json"

_SITES_CACHE: dict[str, dict[str, Any]] | None = None
_META_CACHE: dict[str, Any] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_from_file() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if not _DATA_PATH.exists():
        _LOG.warning("WMN data file not found: %s", _DATA_PATH)
        return {}, {"source": "blackbird", "site_count": 0, "partial": True, "loaded_at": _now()}

    try:
        payload = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("Failed to load WMN data file: %s", exc)
        return {}, {"source": "blackbird", "site_count": 0, "partial": True, "loaded_at": _now()}

    raw_sites: dict[str, Any] = payload.get("sites", {}) if isinstance(payload, dict) else {}
    if not isinstance(raw_sites, dict):
        _LOG.warning("WMN data file has a non-object sites field")
        raw_sites = {}

    sites: dict[str, dict[str, Any]] = {}
    skipped = 0
    for name, defn in raw_sites.items():
        if not isinstance(defn, dict):
            skipped += 1
            continue
        if not defn.get("uri_check"):
            _LOG.warning("WMN site %r missing uri_check, skipping", name)
            skipped += 1
            continue
        if not isinstance(defn.get("e_code"), int) or not isinstance(defn.get("m_code"), int):
            _LOG.warning("WMN site %r missing e_code or m_code, skipping", name)
            skipped += 1
            continue
        if not isinstance(defn.get("e_string"), str) or not isinstance(defn.get("m_string"), str):
            _LOG.warning("WMN site %r missing e_string or m_string, skipping", name)
            skipped += 1
            continue
        if not isinstance(defn.get("cat"), str):
            _LOG.warning("WMN site %r missing cat, skipping", name)
            skipped += 1
            continue
        sites[str(name)] = defn

    if skipped:
        _LOG.info("WMN loader: skipped %d invalid site definitions", skipped)

    meta: dict[str, Any] = {
        "source": "blackbird",
        "upstream": (
            payload.get("_meta", {}).get("upstream", "WebBreacher/WhatsMyName")
            if isinstance(payload, dict)
            else "WebBreacher/WhatsMyName"
        ),
        "site_count": len(sites),
        "partial": skipped > 0,
        "loaded_at": _now(),
    }
    return sites, meta


async def load_blackbird_sites() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return the cached WMN site mapping and its load metadata."""
    global _SITES_CACHE, _META_CACHE
    if _SITES_CACHE is not None:
        return _SITES_CACHE, _META_CACHE  # type: ignore[return-value]
    sites, meta = _load_from_file()
    _SITES_CACHE = sites
    _META_CACHE = meta
    return sites, meta
