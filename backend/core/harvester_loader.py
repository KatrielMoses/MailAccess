from __future__ import annotations

import asyncio
import functools
import json
import logging
from pathlib import Path

import httpx

from .harvester_collectors import (
    collect_bufferoverun,
    collect_certspotter,
    collect_crtsh,
    collect_rapiddns,
    collect_threatminer,
    dns_brute_force,
    resolve_ips,
)

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


_COLLECTOR_MAP = {
    "crtsh": collect_crtsh,
    "rapiddns": collect_rapiddns,
    "certspotter": collect_certspotter,
    "bufferoverun": collect_bufferoverun,
    "threatminer": collect_threatminer,
}


async def collect_all(
    client: httpx.AsyncClient,
    domain: str,
    enabled_sources: set[str] | None = None,
) -> tuple[set[str], dict[str, set[str]], list[str]]:
    sources = load_sources()
    wordlist = load_wordlist()

    active = [
        s for s in sources
        if s.get("name") in _COLLECTOR_MAP
        and (enabled_sources is None or s.get("name") in enabled_sources)
    ]

    sem = asyncio.Semaphore(10)
    all_subdomains: set[str] = set()
    per_source: dict[str, set[str]] = {}
    errors: list[str] = []

    async def _run_one(source: dict) -> None:
        name = source.get("name", "")
        fn = _COLLECTOR_MAP.get(name)
        if fn is None:
            return
        try:
            found = await fn(client, domain, sem)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            per_source[name] = set()
            return
        per_source[name] = found
        all_subdomains.update(found)

    await asyncio.gather(*[_run_one(s) for s in active])

    brute_sem = asyncio.Semaphore(20)
    try:
        brute_hits = await dns_brute_force(client, domain, list(wordlist), brute_sem)
        per_source["dns_brute"] = brute_hits
        all_subdomains.update(brute_hits)
    except Exception as exc:
        errors.append(f"dns_brute: {exc}")

    ip_sem = asyncio.Semaphore(20)
    try:
        ip_map = await resolve_ips(client, all_subdomains, ip_sem)
        per_source["_ip_map"] = set(ip_map.keys())  # just tracking resolved hosts
    except Exception as exc:
        errors.append(f"resolve_ips: {exc}")

    return all_subdomains, per_source, errors
