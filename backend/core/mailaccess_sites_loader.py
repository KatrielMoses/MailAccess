"""Loader for the unified ``data/mailaccess_sites.json`` site definitions.

This is the single, forward-compatible site corpus introduced in 0.15.0.
It holds both ``email-existence`` and ``username-url`` check
paradigms; see ``docs/mailaccess-sites-schema.md``. The loader validates the
minimal required fields, module-level caches the parsed result, and returns
``(sites_dict, load_meta)`` — the ``(sites, meta)`` loader contract the retired
per-tool loaders used.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "mailaccess_sites.json"

_SITES_CACHE: dict[str, dict[str, Any]] | None = None
_META_CACHE: dict[str, Any] | None = None

_VALID_CHECK_TYPES = {"email-existence", "username-url"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_site(name: str, defn: Any) -> bool:
    if not isinstance(defn, dict):
        return False
    if defn.get("check_type") not in _VALID_CHECK_TYPES:
        _LOG.warning("mailaccess_sites: %r has invalid/missing check_type, skipping", name)
        return False
    # Disabled entries are retained: they document coverage of a dead/broken
    # upstream site (they are simply never probed — the module filters them out).
    if defn.get("disabled"):
        return True
    # A probeable site must declare either a native handler or a probe URL.
    if not defn.get("handler") and not (defn.get("uri_check") or defn.get("url")):
        _LOG.warning("mailaccess_sites: %r has no handler and no uri_check/url, skipping", name)
        return False
    return True


def _load_from_file() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    empty_meta = {
        "source": "mailaccess_sites",
        "site_count": 0,
        "partial": True,
        "loaded_at": _now(),
    }
    if not _DATA_PATH.exists():
        _LOG.warning("mailaccess_sites data file not found: %s", _DATA_PATH)
        return {}, empty_meta

    try:
        payload = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("Failed to load mailaccess_sites data file: %s", exc)
        return {}, empty_meta

    raw_sites: dict[str, Any] = payload.get("sites", {}) if isinstance(payload, dict) else {}
    file_meta: dict[str, Any] = payload.get("_meta", {}) if isinstance(payload, dict) else {}

    sites: dict[str, dict[str, Any]] = {}
    skipped = 0
    for name, defn in raw_sites.items():
        if not _valid_site(name, defn):
            skipped += 1
            continue
        entry = dict(defn)
        entry.setdefault("id", str(name))
        sites[str(name)] = entry

    meta: dict[str, Any] = {
        "source": "mailaccess_sites",
        "schema_version": file_meta.get("schema_version"),
        "site_count": len(sites),
        "partial": skipped > 0,
        "loaded_at": _now(),
        "provenance": file_meta.get("provenance"),
    }
    if skipped:
        _LOG.info("mailaccess_sites loader: skipped %d invalid site definitions", skipped)
    return sites, meta


def load_mailaccess_sites() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return ``(sites_dict, load_meta)`` from ``data/mailaccess_sites.json``.

    Module-level cached: the file is read at most once per process. The returned
    dict is shared by reference — do not mutate it.
    """
    global _SITES_CACHE, _META_CACHE
    if _SITES_CACHE is not None:
        return _SITES_CACHE, _META_CACHE  # type: ignore[return-value]
    sites, meta = _load_from_file()
    _SITES_CACHE = sites
    _META_CACHE = meta
    return sites, meta


def sites_for_paradigm(check_type: str) -> dict[str, dict[str, Any]]:
    """Return only the sites matching a given ``check_type`` discriminator."""
    sites, _ = load_mailaccess_sites()
    return {name: defn for name, defn in sites.items() if defn.get("check_type") == check_type}
