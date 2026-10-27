"""Operator Google session — keep the people-pa cookie alive with near-zero upkeep.

The people-pa profile lookup authenticates with the operator's logged-in Google
session (SAPISIDHASH + cookie jar). Empirically (2026-10-22) the ONE short-lived
cookie that endpoint requires is ``__Secure-1PSIDTS``; every other required cookie
is a durable login/SAPISID cookie (~2-year expiry, revoked only on sign-out or
password change). ``__Secure-1PSIDTS`` is designed to rotate, so a captured value
goes stale in days — which is the whole maintenance cost.

This module removes that cost: ``POST https://accounts.google.com/RotateCookies``
with body ``[000,null]`` reissues ``__Secure-1PSIDTS`` (verified: fresh +1-year
expiry) off the durable cookies. We call it opportunistically and persist the
rotated cookies to a small state file, so the engine refreshes the perishable
cookie itself. Net effect: the operator pastes the jar ONCE and it stays usable
until the durable SID dies (≈ a year or more).

The durable baseline stays in ``.env`` (``GOOGLE_SESSION_COOKIE``); only the
rotating cookies live in the cache overlay. Everything here is best-effort and
never raises — on any failure the caller falls back to the last known cookie, and
the module degrades to the stable MX signal.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..config import settings
from .http_client import build_client

_LOG = logging.getLogger(__name__)

_ROTATE_URL = "https://accounts.google.com/RotateCookies"
_ROTATE_BODY = "[000,null]"
# Google's response hints ~600s between rotations; stay just under it so a per-run
# refresh keeps __Secure-1PSIDTS perpetually fresh without hammering the endpoint.
_ROTATE_MIN_INTERVAL_S = 540
# The cookies RotateCookies reissues; we overlay these onto the durable baseline.
_ROTATING = (
    "__Secure-1PSIDTS",
    "__Secure-3PSIDTS",
    "SIDCC",
    "__Secure-1PSIDCC",
    "__Secure-3PSIDCC",
)
_STATE = Path.home() / ".mailaccess" / "cache" / "google_session.json"
# Health beacon the admin panel reads: {ok, checked_at, detail, box}. Written on every
# enrichment attempt; on a healthy->unhealthy transition we also POST the website's
# internal alert endpoint (if configured) so the operator sees it across all engine boxes.
_HEALTH = Path.home() / ".mailaccess" / "cache" / "google_session_status.json"
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _parse_cookie(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k and v:
            out[k] = v
    return out


def _load_overlay() -> dict:
    try:
        data = json.loads(_STATE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_overlay(overlay: dict) -> None:
    try:
        _STATE.parent.mkdir(parents=True, exist_ok=True)
        _STATE.write_text(json.dumps(overlay), encoding="utf-8")
        try:
            _STATE.chmod(0o600)
        except OSError:
            pass
    except Exception as exc:  # noqa: BLE001 — persistence is advisory, never fatal
        _LOG.debug("google_session: overlay save failed: %s", exc)


def _merge(baseline: str, overlay_cookies: dict[str, str]) -> str:
    jar = _parse_cookie(baseline)
    for name, value in overlay_cookies.items():
        if value:
            jar[name] = value
    return "; ".join(f"{name}={value}" for name, value in jar.items())


def current_cookie() -> str:
    """The durable ``.env`` baseline with any rotated cookies overlaid. ``""`` if unset."""
    baseline = (settings.google_session_cookie or "").strip()
    if not baseline:
        return ""
    return _merge(baseline, _load_overlay().get("cookies", {}))


def _read_health() -> dict:
    try:
        return json.loads(_HEALTH.read_text(encoding="utf-8"))
    except Exception:
        return {}


# A credential is reported dead after this many failures in a row, so one network blip
# while minting or looking up doesn't page the operator.
_ALERT_AFTER = 2


def _write_health(state: dict) -> None:
    try:
        _HEALTH.parent.mkdir(parents=True, exist_ok=True)
        _HEALTH.write_text(json.dumps(state), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("google_session: health write failed: %s", exc)


async def record_health(ok: bool, detail: str = "", credential: str = "") -> None:
    """Write the credential-health beacon and tell the website when it changes.

    The website's internal alert endpoint (``settings.engine_alert_url``, authenticated
    with ``settings.mailaccess_pro_internal_secret``) gets ``google_session_dead`` after
    ``_ALERT_AFTER`` failures in a row and ``google_session_recovered`` on the next
    success after that. An alert only counts as sent when the website accepts it, so a
    missed one is retried on the next check. Best-effort; never raises. ``credential`` is
    "master" (master token) or "cookie" (pasted cookie jar).
    """
    import socket

    prev = _read_health()
    fails = 0 if ok else int(prev.get("fails", 0) or 0) + 1
    alerted = bool(prev.get("alerted", False))
    box = ""
    try:
        box = socket.gethostname()
    except Exception:
        pass
    payload = {"ok": ok, "checked_at": int(time.time()), "detail": detail[:200], "box": box[:100],
               "credential": credential}
    send = None
    if not ok and fails >= _ALERT_AFTER and not alerted:
        send = "google_session_dead"
    elif ok and alerted:
        send = "google_session_recovered"
    if send:
        url = (getattr(settings, "engine_alert_url", "") or "").strip()
        secret = (getattr(settings, "mailaccess_pro_internal_secret", "") or "").strip()
        if url and secret:
            try:
                async with build_client(timeout=8.0) as client:
                    resp = await client.post(url, json={"type": send, **payload},
                                             headers={"X-Internal-Secret": secret})
                if 200 <= resp.status_code < 300:
                    alerted = send == "google_session_dead"
                    _LOG.info("google_session: sent %s alert", send)
                else:
                    _LOG.warning("google_session: alert endpoint answered HTTP %s", resp.status_code)
            except Exception as exc:  # noqa: BLE001 — alerting is best-effort
                _LOG.warning("google_session: alert post failed: %s", exc)
    _write_health({**payload, "fails": fails, "alerted": alerted})


async def fresh_cookie(force: bool = False) -> str:
    """Return a usable cookie, rotating ``__Secure-1PSIDTS`` first when it's due.

    Rotates at most once per ``_ROTATE_MIN_INTERVAL_S`` unless ``force`` (used on a
    401 retry). Persists the reissued cookies. On any error returns the last known
    merged cookie so the caller still gets a best effort.
    """
    baseline = (settings.google_session_cookie or "").strip()
    if not baseline:
        return ""
    overlay = _load_overlay()
    overlay_cookies: dict[str, str] = dict(overlay.get("cookies", {}))
    last = float(overlay.get("rotated_at", 0) or 0)
    if not force and (time.time() - last) < _ROTATE_MIN_INTERVAL_S:
        return _merge(baseline, overlay_cookies)

    try:
        async with build_client(timeout=15.0) as client:
            resp = await client.post(
                _ROTATE_URL,
                content=_ROTATE_BODY,
                headers={
                    "Cookie": _merge(baseline, overlay_cookies),
                    "User-Agent": _UA,
                    "Content-Type": "application/json",
                    "Origin": "https://accounts.google.com",
                },
            )
        # Read the parsed cookie jar (robust across httpx versions), falling back to the
        # raw Set-Cookie header. Capturing+persisting EVERY rotation is mandatory: the
        # SIDTS is a chain — each rotation invalidates the previous value, and a missed
        # link kills the session until the operator re-pastes.
        reissued: dict[str, str] = {}
        for name in _ROTATING:
            value = resp.cookies.get(name)
            if value:
                reissued[name] = value
        if not reissued:
            for set_cookie in resp.headers.get_list("set-cookie"):
                name = set_cookie.split("=", 1)[0].strip()
                if name in _ROTATING and "=" in set_cookie:
                    value = set_cookie.split("=", 1)[1].split(";", 1)[0]
                    if value:
                        reissued[name] = value
        if reissued:
            overlay_cookies.update(reissued)
            _save_overlay({"cookies": overlay_cookies, "rotated_at": time.time()})
            _LOG.debug("google_session: rotated %d cookie(s)", len(reissued))
    except Exception as exc:  # noqa: BLE001 — rotation is best-effort
        _LOG.debug("google_session: rotate failed: %s", exc)

    return _merge(baseline, overlay_cookies)
