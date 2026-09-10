"""Native Google-account intelligence — unauthenticated, stable public signals.

On-by-default module that establishes whether an address is a Google-hosted
account (a Gmail consumer account or a Google Workspace domain) using DNS/MX — a
stable, credential-free signal — and, best-effort, enriches it with the public
GAIA profile (display name, avatar, GAIA id) when a public profile endpoint is
reachable.

No operator credentials are required. The profile-enrichment source is
health-registered, so a Google endpoint change degrades gracefully to the stable
MX/domain signal instead of erroring. The authenticated deep-profile capability
(operator cookies, Google's internal APIs) is deliberately out of scope: it
breaks frequently and must never be on the default path.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from ..config import settings
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
    description = (
        "Native, unauthenticated Google-account intelligence: Gmail/Workspace account "
        "existence via MX/domain plus best-effort public GAIA profile (name, avatar). "
        "On by default; no credentials required."
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
        key = (settings.google_intel_api_key or "").strip()
        if not key:
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
            async with build_client(timeout=8.0) as client:
                resp = await client.get(
                    _PEOPLE_ENDPOINT,
                    params={"id": email, "type": "EMAIL", "key": key},
                    headers={
                        "X-Goog-Api-Key": key,
                        "Origin": "https://contacts.google.com",
                    },
                )
            content_length = len(resp.content or b"")
            if resp.status_code == 200:
                result = self._parse_people(resp.json())
                outcome = "hit" if result else "miss"
            elif resp.status_code == 404:
                outcome = "miss"
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
