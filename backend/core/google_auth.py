"""Operator Google auth via a durable Android master token (no GHunt dependency).

The people-pa profile lookup needs a logged-in Google session. A browser cookie jar
is fragile (the __Secure-1PSIDTS chain desyncs across processes/boxes and time-expires).
A master token fixes that: it is a long-lived credential (effectively until the account's
password changes) from which each engine box independently mints fresh session cookies on
demand — no shared chain, no desync, copy the one value to every box.

Flow (constants verified against the GHunt/gpsoauth implementations):
  1. One-time: operator signs in at accounts.google.com/EmbeddedSetup and copies the
     short-lived ``oauth_token`` cookie.
  2. ``exchange_oauth_token`` trades it for the durable master token (``aas_et/...``) via
     android.googleapis.com/auth (service ac2dm). Store that (GOOGLE_MASTER_TOKEN).
  3. ``session_cookie`` mints an OAuthLogin app token from the master token, exchanges it
     for an uberauth, and MergeSession's it into a fresh SID/SAPISID cookie jar — cached
     briefly and refreshed on demand. people-pa then authenticates with sapisidhash off
     that jar (see google_account_intel).

Everything here is best-effort and never raises to the caller except the explicit
exchange helper (used by the one-time setup command, which wants the error).
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..config import settings
from .http_client import build_client

_LOG = logging.getLogger(__name__)

_ANDROID_AUTH = "https://android.googleapis.com/auth"
_OAUTHLOGIN = "https://accounts.google.com/OAuthLogin"
_MERGE_SESSION = "https://accounts.google.com/MergeSession"

# GMS package + its signing-cert SHA1 — the first-party signature Google's auth endpoint
# expects (same value GHunt/gpsoauth use). Not a secret; identifies the Android GMS client.
_GMS_PKG = "com.google.android.gms"
_GMS_SIG = "38918a453d07199354f8b19af05ec6562ced5788"
# A stable synthetic Android device id for this operator client.
_ANDROID_ID = "3f1d8f1e2b9c4a7d"
_UA = "GoogleAuth/1.4 (generic KOT49H); gzip"

# Fresh cookies are cached here and reused until ~55 min old (uberauth cookies are ~1h).
_COOKIE_CACHE = Path.home() / ".mailaccess" / "cache" / "google_master_cookies.json"
_COOKIE_TTL_S = 55 * 60
_SESSION_COOKIES = ("SID", "HSID", "SSID", "APISID", "SAPISID",
                    "__Secure-1PSID", "__Secure-3PSID",
                    "__Secure-1PAPISID", "__Secure-3PAPISID")


def _parse_kv(body: str) -> dict[str, str]:
    """android.googleapis.com/auth returns newline-separated key=value pairs."""
    out: dict[str, str] = {}
    for line in body.splitlines():
        k, _, v = line.partition("=")
        if k:
            out[k.strip()] = v.strip()
    return out


async def _android_auth(params: dict[str, str]) -> dict[str, str]:
    async with build_client(timeout=20.0) as client:
        resp = await client.post(
            _ANDROID_AUTH,
            data=params,
            headers={
                "User-Agent": _UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "device": _ANDROID_ID,
                "app": params.get("app", _GMS_PKG),
            },
        )
    return _parse_kv(resp.text)


async def exchange_oauth_token(oauth_token: str, email: str) -> str:
    """One-time: trade the short-lived ``oauth_token`` for the durable master token.
    Raises ValueError with Google's error on failure (the setup command surfaces it)."""
    res = await _android_auth({
        "Token": oauth_token,
        "Email": email,
        "service": "ac2dm",
        "get_accountid": "1",
        "ACCESS_TOKEN": "1",
        "add_account": "1",
        "callerSig": _GMS_SIG,
        "droidguard_results": "dummy123",
        "androidId": _ANDROID_ID,
        "app": _GMS_PKG,
        "client_sig": _GMS_SIG,
        "device_country": "us",
        "operatorCountry": "us",
        "lang": "en",
        "sdk_version": "30",
    })
    token = res.get("Token", "")
    if not token.startswith("aas_et/"):
        raise ValueError(f"master-token exchange failed: {res.get('Error') or res.get('ErrorDetail') or res}")
    return token


async def _mint_oauthlogin_token(master_token: str, email: str) -> str | None:
    """Mint an app token scoped for OAuthLogin (the uberauth source) from the master token."""
    res = await _android_auth({
        "Token": master_token,
        "Email": email,
        "service": "oauth2:https://www.google.com/accounts/OAuthLogin",
        "app": _GMS_PKG,
        "client_sig": _GMS_SIG,
        "androidId": _ANDROID_ID,
        "device_country": "us",
        "operatorCountry": "us",
        "lang": "en",
        "sdk_version": "30",
    })
    return res.get("Auth")


async def _regenerate_cookies(master_token: str, email: str) -> dict[str, str]:
    """master token -> OAuthLogin token -> uberauth -> MergeSession -> fresh cookie jar."""
    auth = await _mint_oauthlogin_token(master_token, email)
    if not auth:
        return {}
    async with build_client(timeout=20.0) as client:
        # uberauth: issue a merge-session-capable token.
        r = await client.get(
            _OAUTHLOGIN,
            params={"source": "ChromiumBrowser", "issueuberauth": "1"},
            headers={"Authorization": f"Bearer {auth}", "User-Agent": _UA},
        )
        uberauth = (r.text or "").strip()
        if not uberauth or " " in uberauth:
            return {}
        # MergeSession sets the browser cookie jar.
        await client.get(
            _MERGE_SESSION,
            params={
                "source": "ChromiumAccountReconcilor",
                "uberauth": uberauth,
                "continue": "https://www.google.com",
                "externalCcResult": "doubleclick:null,youtube:null",
            },
            headers={"User-Agent": _UA},
        )
        jar = {c.name: c.value for c in client.cookies.jar if c.name in _SESSION_COOKIES}
    return jar


def configured() -> bool:
    """True when a master token and its account email are both set."""
    return bool((getattr(settings, "google_master_token", "") or "").strip()
                and (getattr(settings, "google_master_email", "") or "").strip())


def _load_cache() -> dict:
    try:
        return json.loads(_COOKIE_CACHE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(cookies: dict[str, str]) -> None:
    try:
        _COOKIE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _COOKIE_CACHE.write_text(json.dumps({"cookies": cookies, "at": time.time()}), encoding="utf-8")
        try:
            _COOKIE_CACHE.chmod(0o600)
        except OSError:
            pass
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("google_auth: cookie cache save failed: %s", exc)


async def session_cookie(force: bool = False) -> str:
    """Return a people-pa-ready ``Cookie`` header derived from the master token, or ``""``
    when no master token is configured. Caches the regenerated jar for ~55 min. Never raises.
    """
    master = (getattr(settings, "google_master_token", "") or "").strip()
    email = (getattr(settings, "google_master_email", "") or "").strip()
    if not (master and email):
        return ""
    cache = _load_cache()
    cookies = dict(cache.get("cookies", {}))
    fresh = (time.time() - float(cache.get("at", 0) or 0)) < _COOKIE_TTL_S
    if cookies and fresh and not force:
        return "; ".join(f"{k}={v}" for k, v in cookies.items())
    try:
        regen = await _regenerate_cookies(master, email)
        if regen.get("SAPISID"):
            _save_cache(regen)
            return "; ".join(f"{k}={v}" for k, v in regen.items())
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("google_auth: cookie regen failed: %s", exc)
    # Fall back to the last good jar if regen momentarily failed.
    return "; ".join(f"{k}={v}" for k, v in cookies.items()) if cookies else ""
