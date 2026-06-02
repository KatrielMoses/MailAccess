from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .http_client import build_client

_LOG = logging.getLogger(__name__)

MAIGRET_DATA_URL = (
    "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json"
)
CACHE_PATH = Path.home() / ".mailaccess" / "cache" / "maigret-data.json"
CACHE_TTL = 86_400
EXTRA_SITES_PATH = Path(__file__).resolve().parents[2] / "data" / "mailaccess-extra-sites.json"

_WAVE1_BLOCKED_PROTECTIONS = {
    "cf_js_challenge",
    "tls_fingerprint",
    "ip_reputation",
    "custom_bot_protection",
}


def _site_mapping(data: Any) -> dict[str, dict[str, Any]]:
    if isinstance(data, dict):
        sites = data.get("sites", data)
        if isinstance(sites, dict):
            return {
                str(name): dict(defn)
                for name, defn in sites.items()
                if isinstance(defn, dict)
            }
        if isinstance(sites, list):
            return {
                str(item.get("name") or item.get("site") or index): dict(item)
                for index, item in enumerate(sites)
                if isinstance(item, dict)
            }
    return {}


def _protections(defn: dict[str, Any]) -> set[str]:
    value = defn.get("protection")
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return {str(key) for key in value.keys()}
    return set()


def _requires_activation(defn: dict[str, Any]) -> bool:
    activation = defn.get("activation") or defn.get("activationRequired")
    if isinstance(activation, bool):
        return activation
    if isinstance(activation, str) and activation.strip():
        return activation.strip().lower() not in {"false", "no", "0"}
    tags = defn.get("tags")
    return isinstance(tags, list) and any("activation" in str(tag).lower() for tag in tags)


def _is_supported_site(defn: dict[str, Any], include_wave2: bool) -> bool:
    if defn.get("disabled") is True:
        return False
    if str(defn.get("type") or "username") != "username":
        return False
    if _requires_activation(defn):
        return False
    if _protections(defn) & _WAVE1_BLOCKED_PROTECTIONS and not include_wave2:
        return False
    if not (defn.get("url") or defn.get("urlProbe") or defn.get("engine") == "Discourse"):
        return False
    return True


def _filter_sites(sites: dict[str, dict[str, Any]], include_wave2: bool) -> dict[str, dict[str, Any]]:
    return {
        name: defn
        for name, defn in sites.items()
        if _is_supported_site(defn, include_wave2=include_wave2)
    }


def _load_cache() -> dict[str, Any] | None:
    if not CACHE_PATH.exists():
        return None
    return json.loads(CACHE_PATH.read_text(encoding="utf-8"))


async def _fetch_fresh() -> dict[str, Any]:
    async with build_client(timeout=30.0) as client:
        response = await client.get(MAIGRET_DATA_URL)
        response.raise_for_status()
        data = response.json()
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(data), encoding="utf-8")
    return data


def _load_extra_sites() -> dict[str, dict[str, Any]]:
    if not EXTRA_SITES_PATH.exists():
        return {}
    try:
        return _site_mapping(json.loads(EXTRA_SITES_PATH.read_text(encoding="utf-8")))
    except Exception as exc:
        _LOG.warning("Failed to load MailAccess extra Maigret sites: %s", exc)
        return {}


async def load_maigret_sites(include_wave2: bool = False) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Load filtered Maigret sites, refreshing the cache when stale."""
    source = "cache"
    partial = False
    data: dict[str, Any] | None = None

    if CACHE_PATH.exists():
        age = time.time() - CACHE_PATH.stat().st_mtime
        if age < CACHE_TTL:
            data = _load_cache()
        else:
            source = "network"
    else:
        source = "network"

    if data is None:
        try:
            data = await _fetch_fresh()
        except Exception as exc:
            cached = _load_cache()
            if cached is None:
                raise RuntimeError(f"Failed to fetch Maigret data and no cache is available: {exc}") from exc
            data = cached
            source = "stale_cache"
            partial = True

    maigret_sites = _filter_sites(_site_mapping(data), include_wave2=include_wave2)
    extra_sites = _filter_sites(_load_extra_sites(), include_wave2=include_wave2)
    merged = {**maigret_sites, **extra_sites}
    return merged, {
        "source": source,
        "partial": partial,
        "maigret_sites": len(maigret_sites),
        "extra_sites": len(extra_sites),
        "sites_loaded": len(merged),
    }
