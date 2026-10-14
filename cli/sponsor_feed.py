"""Remote sponsor feed for CLI placements.

Sponsors are not shipped in the package. The CLI reads a JSON feed (default
``https://mailaccess.pro/api/cli/sponsors``), caches it in
``~/.mailaccess/sponsor_feed.json`` and re-fetches once the cache is older than
the feed's ``ttl_seconds`` in a background thread, so a run never waits on the
network once a cache exists; only the very first run waits (up to 3 s). Every
network and cache path is best-effort: a slow, missing or malformed feed means
no sponsor lines, never a failed run.

The feed is untrusted input rendered into a terminal: strings lose control
characters and are length-capped, links must be https, colours are validated,
and unknown fields are ignored. The "Partner ·" disclosure is added by the
renderer, so the feed cannot remove it.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import httpx

DEFAULT_URL = "https://mailaccess.pro/api/cli/sponsors"
SCHEMA = 1
MAX_SPONSORS = 25
MAX_BYTES = 64 * 1024
_DEFAULT_TTL = 24 * 60 * 60
_MIN_TTL, _MAX_TTL = 300, 7 * 24 * 60 * 60
# First run (no cache) waits up to this once; later runs never wait.
_FIRST_FETCH_TIMEOUT = 3.0
_BACKGROUND_TIMEOUT = 10.0
_CACHE_FILE = Path.home() / ".mailaccess" / "sponsor_feed.json"
_HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ANSI16 = {
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
    "bright_black", "bright_red", "bright_green", "bright_yellow",
    "bright_blue", "bright_magenta", "bright_cyan", "bright_white",
}


@dataclass(frozen=True)
class Sponsor:
    id: str
    name: str
    label: str
    tagline: str
    domain: str
    url: str
    color: str
    low_color: str
    surfaces: tuple[str, ...]
    priority: int


def _env_true(name: str) -> bool:
    value = os.environ.get(name)
    return value is not None and value.strip().lower() not in ("", "0", "false", "no")


def feed_url() -> str:
    return (os.environ.get("MAILACCESS_SPONSORS_URL") or DEFAULT_URL).strip()


def _text(value: Any, limit: int) -> str:
    return _CTRL.sub("", str(value or "")).strip()[:limit]


def _https(value: Any) -> str:
    url = str(value or "").strip()
    if url.startswith("https://") and len(url) <= 500 and not _CTRL.search(url) and " " not in url:
        return url
    return ""


def _day(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def parse(payload: Any, *, today: date | None = None) -> list[Sponsor]:
    """Validated, currently-running sponsors from a feed payload, in display order."""
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        return []
    today = today or datetime.now(timezone.utc).date()
    sponsors: list[Sponsor] = []
    for raw in (payload.get("sponsors") or [])[:MAX_SPONSORS]:
        if not isinstance(raw, dict):
            continue
        starts, ends = _day(raw.get("starts")), _day(raw.get("ends"))
        if (starts and today < starts) or (ends and today > ends):
            continue
        links = raw.get("links") if isinstance(raw.get("links"), dict) else {}
        colors = raw.get("colors") if isinstance(raw.get("colors"), dict) else {}
        name, tagline = _text(raw.get("name"), 40), _text(raw.get("tagline"), 90)
        domain, url = _text(raw.get("domain"), 60), _https(links.get("cli") or links.get("default"))
        if not (name and tagline and domain and url):
            continue
        hex_color = str(colors.get("hex") or "")
        low = str(colors.get("ansi16") or "")
        priority = raw.get("priority")
        sponsors.append(
            Sponsor(
                id=_text(raw.get("id"), 40) or name.lower(),
                name=name,
                label=_text(raw.get("label"), 30),
                tagline=tagline,
                domain=domain,
                url=url,
                color=hex_color if _HEX.match(hex_color) else "#AAAAAA",
                low_color=low if low in _ANSI16 else "white",
                surfaces=tuple(s for s in raw.get("surfaces") or [] if isinstance(s, str)),
                priority=priority if isinstance(priority, int) else 100,
            )
        )
    return sorted(sponsors, key=lambda s: (s.priority, s.name.lower()))


def _ttl(payload: Any) -> int:
    override = os.environ.get("MAILACCESS_SPONSORS_TTL")
    if override is not None:
        try:
            return max(0, int(override))
        except ValueError:
            pass
    ttl = payload.get("ttl_seconds") if isinstance(payload, dict) else None
    return min(max(ttl, _MIN_TTL), _MAX_TTL) if isinstance(ttl, int) else _DEFAULT_TTL


def _read_cache() -> dict | None:
    try:
        with open(_CACHE_FILE, encoding="utf-8") as fh:
            cache = json.load(fh)
        return cache if isinstance(cache, dict) and cache.get("url") == feed_url() else None
    except (OSError, ValueError):
        return None


def _write_cache(payload: dict) -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(_CACHE_FILE.parent), prefix=".sponsor_feed.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"url": feed_url(), "fetched_at": time.time(), "payload": payload}, fh)
        os.replace(tmp, _CACHE_FILE)
    except OSError:
        pass


def _fetch(timeout: float = _FIRST_FETCH_TIMEOUT) -> dict | None:
    try:
        from backend.config import APP_VERSION
    except Exception:  # noqa: BLE001
        APP_VERSION = "unknown"
    try:
        resp = httpx.get(
            feed_url(),
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": f"mailaccess-cli/{APP_VERSION}"},
            follow_redirects=False,
        )
        if resp.status_code != 200 or len(resp.content) > MAX_BYTES:
            return None
        payload = resp.json()
        return payload if isinstance(payload, dict) and payload.get("schema") == SCHEMA else None
    except (httpx.HTTPError, ValueError):
        return None


def _refresh_in_background() -> None:
    def worker() -> None:
        fresh = _fetch(_BACKGROUND_TIMEOUT)
        if fresh is not None:
            _write_cache(fresh)

    try:
        threading.Thread(target=worker, name="mailaccess-sponsor-feed", daemon=True).start()
    except Exception:  # noqa: BLE001
        pass


def load_payload() -> dict | None:
    """Cached feed (refreshed in the background once stale); first run fetches once."""
    if _env_true("MAILACCESS_NO_SPONSORS"):
        return None
    cache = _read_cache()
    if os.environ.get("MAILACCESS_SPONSORS_TTL", "").strip() == "0":
        # Testing switch: fetch on every run, so feed edits show immediately.
        fresh = _fetch()
        if fresh is not None:
            _write_cache(fresh)
            return fresh
        return cache.get("payload") if cache else None
    if cache:
        if time.time() - float(cache.get("fetched_at") or 0) >= _ttl(cache.get("payload")):
            _refresh_in_background()
        return cache.get("payload")
    fresh = _fetch()
    if fresh is not None:
        _write_cache(fresh)
    return fresh


def for_surface(surface: str, *, today: date | None = None) -> list[Sponsor]:
    """Sponsors booked on *surface*, capped by the feed's limit and rotated daily."""
    payload = load_payload()
    if not payload:
        return []
    booked = [s for s in parse(payload, today=today) if surface in s.surfaces]
    limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
    cap = limits.get(surface)
    if not isinstance(cap, int) or cap < 0 or len(booked) <= cap:
        return booked
    # More bookings than slots: rotate one step per day so everyone gets air time.
    start = (today or datetime.now(timezone.utc).date()).toordinal() % len(booked)
    return (booked[start:] + booked[:start])[:cap]
