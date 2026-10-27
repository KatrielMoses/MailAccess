"""Native Google-account intelligence.

On-by-default module that establishes whether an address is a Google-hosted
account (a Gmail consumer account or a Google Workspace domain) using DNS/MX, a
stable signal that needs no credentials.

With an operator credential it also adds the account's public profile name and
photo from Google's people lookup. The preferred credential is a durable Android
master token (GOOGLE_MASTER_TOKEN + GOOGLE_MASTER_EMAIL, set up with
`mailaccess google-auth`); a pasted session cookie is the legacy fallback. Without
one, the module returns the MX signal only. The enrichment source is
health-registered (an endpoint change degrades to the MX signal), and credential
health is reported to the admin alert (google_session.record_health).
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from ..config import settings
from ..core import google_auth, google_session
from ..core.http_client import build_client
from ..core.mx_resolver import resolve_mx
from ..core.platform_health import get_health_db
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_GMAIL_DOMAINS = frozenset({"gmail.com", "googlemail.com"})
# Google Workspace inbound mail routes through hosts under these zones.
_GOOGLE_MX_MARKERS = ("google.com", "googlemail.com")

# Health-register the best-effort enrichment source under this key so an endpoint
# change auto-demotes it and the module keeps returning the stable signal.
_ENRICH_SOURCE = "google_account_intel"
_PEOPLE_ENDPOINT = "https://people-pa.clients6.google.com/v2/people/lookup"
# people-pa accepts a logged-in session (SAPISIDHASH) only when the request carries a
# public, origin-locked web API key and the matching Origin. These are the public
# photos.google.com values (not a user secret; Google rate-limits them by origin), so
# the feature needs only the operator session cookie. Either is overridable via settings.
_PEOPLE_API_KEY = "AIzaSyAa2odBewW-sPJu3jMORr0aNedh3YlkiQc"
_PEOPLE_ORIGIN = "https://photos.google.com"


def _cookie_value(cookie_header: str, name: str) -> str | None:
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name and v:
            return v
    return None


def _sapisidhash(sapisid: str, origin: str = _PEOPLE_ORIGIN) -> str:
    """Google's SAPISIDHASH auth for logged-in session calls: SHA1 of
    "<ts> <SAPISID> <origin>". The origin MUST match the API key's registered origin.
    Operator service-account session only."""
    ts = int(time.time())
    digest = hashlib.sha1(f"{ts} {sapisid} {origin}".encode()).hexdigest()
    return f"SAPISIDHASH {ts}_{digest}"


def _api_key() -> str:
    return (settings.google_people_api_key or settings.google_intel_api_key or _PEOPLE_API_KEY).strip()


async def _people_lookup(email: str, cookie_jar: str) -> Any:
    """One people-pa lookup (name + photo only) authenticated with the operator session."""
    headers = {
        "Origin": _PEOPLE_ORIGIN,
        "Referer": _PEOPLE_ORIGIN + "/",
        "X-Goog-Api-Key": _api_key(),
        "Cookie": cookie_jar,
    }
    sapisid = _cookie_value(cookie_jar, "SAPISID") or _cookie_value(cookie_jar, "__Secure-3PAPISID")
    if sapisid:
        headers["Authorization"] = _sapisidhash(sapisid)
    async with build_client(timeout=8.0) as client:
        return await client.get(
            _PEOPLE_ENDPOINT,
            params={
                "id": email,
                "type": "EMAIL",
                "matchType": "EXACT",
                # Repeated key (httpx expands the list) -> ask for name + photo only.
                "requestMask.includeField.paths": ["person.name", "person.photo"],
            },
            headers=headers,
        )


_MINT_FAILED = ("Could not mint a Google session from the master token. It was revoked or the "
                "account password changed: run `mailaccess google-auth` again.")


async def _operator_session(force: bool = False) -> tuple[str, str]:
    """(cookie header, credential kind). A configured master token is the only source
    (no cookie fallback, so the health state can't flip between the two); a master
    token that can't mint a session is recorded as a dead credential."""
    if google_auth.configured():
        cookie = await google_auth.session_cookie(force=force)
        if not cookie:
            await google_session.record_health(False, _MINT_FAILED, credential="master")
        return cookie, "master"
    return await google_session.fresh_cookie(force=force), "cookie"


async def check_credential() -> tuple[bool, str]:
    """Verify the operator credential now (`mailaccess google-auth --check`): mint a fresh
    session and look up the operator's own account. Records health either way, so the
    admin alert fires or clears. Network errors are reported but not recorded."""
    if not google_auth.configured():
        return False, "No master token is set. Run `mailaccess google-auth --email <operator account>`."
    email = (settings.google_master_email or "").strip()
    cookie, cred = await _operator_session(force=True)
    if not cookie:
        return False, _MINT_FAILED
    try:
        resp = await _people_lookup(email, cookie)
    except Exception as exc:  # noqa: BLE001
        return False, f"Couldn't reach Google ({type(exc).__name__}). Check the network and try again."
    if resp.status_code in (200, 404):
        await google_session.record_health(True, credential=cred)
        return True, f"The Google credential works (master token for {email})."
    if resp.status_code in (401, 403):
        await google_session.record_health(False, f"people-pa HTTP {resp.status_code} on a fresh session",
                                           credential=cred)
        return False, f"Google rejected the session (HTTP {resp.status_code}). Run `mailaccess google-auth` again."
    return False, f"Unexpected answer from Google (HTTP {resp.status_code}). Try again later."


def _hosting_kind(domain: str, mx_hosts: list[str]) -> str | None:
    if domain in _GMAIL_DOMAINS:
        return "gmail"
    for host in mx_hosts:
        low = host.lower()
        if any(marker in low for marker in _GOOGLE_MX_MARKERS):
            return "workspace"
    return None


class GoogleAccountIntelModule(BaseModule):
    name = "google_account_intel"
    email_linked = True
    description = (
        "Google-account intelligence: Gmail/Workspace account existence via MX/domain "
        "(no credentials), plus the public profile name and photo when an operator "
        "Google credential is configured. On by default."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.enable_google_account_intel:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_GOOGLE_ACCOUNT_INTEL=true to run this module"],
            )

        domain = email.split("@", 1)[-1].lower().strip()
        if not domain:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["No domain in address"])

        mx_hosts: list[str] = []
        if domain not in _GMAIL_DOMAINS:
            try:
                mx_hosts = [r.host for r in await resolve_mx(domain)]
            except Exception:  # noqa: BLE001 — resolver already degrades, defensive only
                mx_hosts = []

        kind = _hosting_kind(domain, mx_hosts)
        if kind is None:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={"found": False, "google_hosted": False, "email_domain": domain},
            )

        finding: dict[str, Any] = {
            "platform": "google_account",
            "username": email.split("@", 1)[0],
            "metadata": {
                "source": "google_account_intel",
                "google_hosted": True,
                "hosting_kind": kind,
                "email_domain": domain,
                "mx_hosts": mx_hosts[:5],
                "signal": "mx_domain",
            },
            # The hosting signal proves the address is a Google-served account
            # domain, not that a specific mailbox is active — hence medium.
            "confidence": "medium",
        }

        # Best-effort, health-registered public-profile enrichment. Never fatal.
        enrichment = await self._enrich_profile(email)
        if enrichment:
            finding["metadata"].update(enrichment)
            if enrichment.get("display_name"):
                # A confirmed public profile lifts confidence and feeds name-consensus.
                finding["confidence"] = "high"

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[finding],
            metadata={
                "found": True,
                "google_hosted": True,
                "hosting_kind": kind,
                "display_name": finding["metadata"].get("display_name"),
                "profile_enriched": bool(enrichment),
            },
        )

    async def _enrich_profile(self, email: str) -> dict[str, Any] | None:
        """Return public-profile fields (display_name / avatar_url / gaia_id) or None.

        Uses Google's public People lookup endpoint with a public web API key when
        one is configured. Health-registered: any non-answer records a probe outcome
        so a persistently-broken endpoint auto-demotes and stops being probed, and
        the module falls back to the stable hosting signal.
        """
        # Operator Google session: the master token when configured (fresh cookies minted
        # on demand), else the legacy pasted cookie. Absent -> keep the stable MX signal.
        cookie, cred = await _operator_session()
        if not cookie:
            return None

        health = get_health_db()
        try:
            if not await health.should_probe_async(_ENRICH_SOURCE):
                return None
        except Exception:  # noqa: BLE001 — health is advisory, never fatal
            pass

        outcome = "inconclusive"
        latency_ms = 0
        content_length = 0
        result: dict[str, Any] | None = None
        t0 = time.perf_counter()
        try:
            resp = await _people_lookup(email, cookie)
            # A 401 means the session went stale: re-mint (master token) or rotate the
            # perishable __Secure-1PSIDTS (pasted cookie), then retry once.
            if resp.status_code == 401:
                refreshed, _ = await _operator_session(force=True)
                if refreshed and refreshed != cookie:
                    resp = await _people_lookup(email, refreshed)
            content_length = len(resp.content or b"")
            if resp.status_code == 200:
                result = self._parse_people(resp.json())
                outcome = "hit" if result else "miss"
                # A 200 proves the session authenticated -> mark the credential healthy.
                await google_session.record_health(True, credential=cred)
            elif resp.status_code == 404:
                outcome = "miss"
                await google_session.record_health(True, credential=cred)
            elif resp.status_code in (401, 403):
                # Still unauthorized AFTER the force-rotate retry -> the operator session is
                # dead (password change / sign-out / chain break). Beacon + admin alert.
                outcome = "inconclusive"
                await google_session.record_health(
                    False, f"people-pa HTTP {resp.status_code} after a fresh session: the credential stopped working",
                    credential=cred,
                )
            else:
                outcome = "inconclusive"
        except Exception as exc:  # noqa: BLE001 — endpoint change / network / parse
            _LOG.debug("google_account_intel enrichment unavailable: %s", exc)
            outcome = "inconclusive"
        finally:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            try:
                await health.record_probe_async(
                    platform=_ENRICH_SOURCE,
                    domain=None,
                    outcome=outcome,
                    latency_ms=latency_ms,
                    content_length=content_length,
                )
            except Exception:  # noqa: BLE001
                pass
        return result

    @staticmethod
    def _parse_people(data: Any) -> dict[str, Any] | None:
        """Extract the stable public-profile fields from a People lookup response.

        Tolerant of shape drift: reads name/photo/gaia from the common nestings and
        returns only the fields it actually finds.
        """
        if not isinstance(data, dict):
            return None
        # People responses nest the matched person under people/{id} or matches[].
        person: dict[str, Any] | None = None
        people = data.get("people")
        if isinstance(people, dict) and people:
            first = next(iter(people.values()))
            if isinstance(first, dict):
                person = first
        if person is None:
            matches = data.get("matches") or data.get("personResponse")
            if isinstance(matches, list) and matches and isinstance(matches[0], dict):
                person = matches[0].get("person") if "person" in matches[0] else matches[0]
        if not isinstance(person, dict):
            return None

        out: dict[str, Any] = {}
        gaia = person.get("personId") or person.get("id")
        if gaia:
            out["gaia_id"] = str(gaia)

        names = person.get("name") or person.get("names") or []
        if isinstance(names, list) and names and isinstance(names[0], dict):
            display = names[0].get("displayName") or names[0].get("formattedName")
            if display:
                out["display_name"] = str(display)

        photos = person.get("photo") or person.get("photos") or []
        if isinstance(photos, list) and photos and isinstance(photos[0], dict):
            url = photos[0].get("url")
            if url:
                out["avatar_url"] = str(url)
                out["custom_profile_photo"] = not photos[0].get("isDefault", False)

        return out or None
