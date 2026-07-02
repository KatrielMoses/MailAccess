from __future__ import annotations

import functools
import json
import logging
from pathlib import Path

_LOG = logging.getLogger(__name__)

_SOURCES_PATH = Path(__file__).resolve().parents[2] / "data" / "harvester_sources.json"
_WORDLIST_PATH = Path(__file__).resolve().parents[2] / "data" / "subdomain_wordlist.txt"

_FALLBACK_PREFIXES = (
    "www", "mail", "ftp", "smtp", "api", "dev", "staging", "test",
    "admin", "portal", "vpn", "cdn", "static", "assets", "docs",
    "blog", "support", "login", "auth", "app", "web", "ns1", "ns2",
    "mx", "mx1", "mx2", "secure", "ssl", "remote", "intranet", "git",
    "beta", "alpha", "old", "new", "backup", "db", "database", "cache",
    "media", "img", "files", "dashboard", "status", "help", "faq",
)


@functools.lru_cache(maxsize=1)
def load_sources() -> tuple[dict, ...]:
    if not _SOURCES_PATH.exists():
        _LOG.warning("harvester_sources.json not found: %s", _SOURCES_PATH)
        return ()
    try:
        payload = json.loads(_SOURCES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("Failed to load harvester_sources.json: %s", exc)
        return ()
    sources = payload.get("sources") if isinstance(payload, dict) else []
    if not isinstance(sources, list):
        _LOG.warning("harvester_sources.json: 'sources' is not a list")
        return ()
    return tuple(s for s in sources if isinstance(s, dict) and s.get("name"))


@functools.lru_cache(maxsize=1)
def load_wordlist() -> tuple[str, ...]:
    if not _WORDLIST_PATH.exists():
        _LOG.warning("subdomain_wordlist.txt not found: %s", _WORDLIST_PATH)
        return _FALLBACK_PREFIXES
    try:
        lines = _WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _LOG.warning("Failed to load subdomain_wordlist.txt: %s", exc)
        return _FALLBACK_PREFIXES
    prefixes = tuple(
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    )
    return prefixes if prefixes else _FALLBACK_PREFIXES
