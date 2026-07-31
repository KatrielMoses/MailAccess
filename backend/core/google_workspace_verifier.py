"""Google Workspace account-existence signal with a cautious Gravatar fallback."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from .http_client import build_client

_LOG = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    email: str
    status: str = "inconclusive"
    exists: bool | None = None
    gravatar_hit: bool = False
    # Set the moment an actual Gravatar lookup is performed for this
    # address (regardless of outcome). Telemetry uses it to separate
    # candidates ROUTED to the verifier from mechanisms CONTACTED.
    gravatar_checked: bool = False
    http_status: int | None = None
    error: str | None = None


class GoogleWorkspaceVerifier:
    # Reacher's Gmail-specific implementation uses this legacy endpoint.
    # It is a HEAD request with the address in the query string and no body
    # or explicit request headers.
    lookup_url = "https://mail.google.com/mail/gxlu"
    gravatar_url = "https://www.gravatar.com/avatar/{hash}?d=404"

    def __init__(
        self,
        *,
        delay_seconds: float = 1.0,
        timeout_seconds: float = 8.0,
        gravatar_enabled: bool = True,
        smtp_fallback_enabled: bool = False,
        gxlu_enabled: bool = True,
        max_checks: int = 25,
    ) -> None:
        self.delay_seconds = max(float(delay_seconds), 0.0)
        self.timeout_seconds = max(float(timeout_seconds), 1.0)
        self.gravatar_enabled = bool(gravatar_enabled)
        self.smtp_fallback_enabled = bool(smtp_fallback_enabled)
        # The gxlu endpoint was patched by Google (uniform 204/no-set-cookie)
        # and yields zero information per request. The harvest tail disables
        # it and routes directly to the Gravatar signal instead.
        self.gxlu_enabled = bool(gxlu_enabled)
        self.max_checks = max(1, min(int(max_checks), 100))

    async def verify_batch(
        self,
        emails: list[str],
        domain: str,
        session: Any | None = None,
        max_checks: int = 25,
    ) -> list[VerificationResult]:
        cleaned = list(dict.fromkeys(
            e.strip().lower() for e in emails
            if isinstance(e, str) and "@" in e
        ))
        cap = max(1, min(int(max_checks), self.max_checks, 100))
        own_client = session is None
        client = session or build_client(timeout=self.timeout_seconds, follow_redirects=True)
        try:
            if not self.gxlu_enabled:
                # Gravatar-only path: no gxlu lookups, and NEVER an SMTP
                # RCPT fallback — Google MX returns no usable RCPT responses,
                # so SMTP probing burns the tail budget for zero information.
                results = [
                    VerificationResult(
                        email=email,
                        status="inconclusive" if index < cap else "not_attempted",
                        error=None if index < cap else "over_cap",
                    )
                    for index, email in enumerate(cleaned)
                ]
                if self.gravatar_enabled:
                    for result in results[:cap]:
                        await self._gravatar(client, result)
                return results
            gxlu_results = await self._gxlu_batch(client, cleaned, cap)

            # Google patched the gxlu endpoint: it now answers 204 with no
            # set-cookie for every address, so every probe that actually ran
            # comes back inconclusive. When the whole batch is inconclusive we
            # fall back to SMTP RCPT TO (the v0.12.8 Google path), which still
            # produces not_found / verified signal on many Workspace tenants.
            looked_up = [
                r for r in gxlu_results
                if r.status != "not_attempted" and r.error != "rate_limited"
            ]
            all_inconclusive = bool(looked_up) and all(
                r.status == "inconclusive" for r in looked_up
            )
            if self.smtp_fallback_enabled and all_inconclusive:
                smtp_results = await self._smtp_rcpt_fallback(
                    [r.email for r in looked_up], domain
                )
                if smtp_results is not None:
                    if self.gravatar_enabled:
                        for result in smtp_results:
                            if result.status == "inconclusive":
                                await self._gravatar(client, result)
                    tail = [
                        r for r in gxlu_results
                        if r.status == "not_attempted" or r.error == "rate_limited"
                    ]
                    return smtp_results + tail

            if self.gravatar_enabled:
                for result in looked_up:
                    if result.status == "inconclusive":
                        await self._gravatar(client, result)
            return gxlu_results
        finally:
            if own_client:
                close = getattr(client, "aclose", None)
                if close is not None:
                    await close()

    async def _gxlu_batch(
        self, client: Any, cleaned: list[str], cap: int
    ) -> list[VerificationResult]:
        """Run the raw gxlu lookups without any secondary signal applied."""
        results: list[VerificationResult] = []
        rate_limited = False
        for index, email in enumerate(cleaned):
            if index >= cap:
                results.append(VerificationResult(email=email, status="not_attempted"))
                continue
            if rate_limited:
                results.append(VerificationResult(email=email, status="inconclusive", error="rate_limited"))
                continue
            if index and self.delay_seconds:
                await asyncio.sleep(self.delay_seconds)
            result = await self._lookup(client, email)
            if result.http_status == 429:
                rate_limited = True
            results.append(result)
        return results

    async def _smtp_rcpt_fallback(
        self, emails: list[str], domain: str
    ) -> list[VerificationResult] | None:
        """SMTP RCPT TO fallback used when gxlu is uniformly inconclusive.

        Returns ``None`` when the domain has no MX record (nothing to probe);
        otherwise reuses the shared :class:`SMTPVerifier` (with its catch-all
        detection) and maps its results into Google verifier result objects.
        """
        from ..config import settings
        from .mx_resolver import resolve_mx
        from .smtp_verifier import (
            DEFAULT_PROBE_DELAY,
            DEFAULT_SENDER,
            MAX_PROBES_HARD_CAP,
            SMTPVerifier,
        )

        mx_records = await resolve_mx(domain)
        if not mx_records:
            return None

        async with SMTPVerifier(
            mx_records=mx_records,
            sender_address=settings.smtp_sender_address,
            probe_delay_seconds=float(settings.smtp_probe_delay_seconds) or DEFAULT_PROBE_DELAY,
            connect_timeout_seconds=float(settings.smtp_connect_timeout_seconds),
            probe_domain_pattern=settings.smtp_probe_domain_pattern,
            probe_custom_domain=settings.smtp_probe_custom_domain,
        ) as verifier:
            batch = await verifier.verify_batch(
                domain,
                list(emails),
                max_probes=min(int(settings.smtp_max_probes_per_domain), MAX_PROBES_HARD_CAP),
            )

        status_map = {"verified": "verified", "not_found": "not_found"}
        results: list[VerificationResult] = []
        for probe in batch.results:
            results.append(
                VerificationResult(
                    email=probe.email,
                    status=status_map.get(probe.verification_status, "inconclusive"),
                    exists=probe.exists,
                    http_status=probe.response_code,
                    error=probe.transport_error,
                )
            )
        return results

    async def _lookup(self, client: Any, email: str) -> VerificationResult:
        try:
            response = await asyncio.wait_for(
                client.head(
                    self.lookup_url,
                    params={"email": email},
                ),
                timeout=self.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(email=email, error=f"{type(exc).__name__}: {exc}")
        result = VerificationResult(email=email, http_status=response.status_code)
        if response.status_code == 429:
            result.error = "rate_limited"
            return result
        headers = getattr(response, "headers", {})
        has_set_cookie = any(str(name).lower() == "set-cookie" for name in headers)
        if has_set_cookie:
            result.status, result.exists = "verified", True
        else:
            result.error = "no_set_cookie"
            _LOG.warning("Google Workspace verifier returned an unexpected response")
        return result

    async def _gravatar(self, client: Any, result: VerificationResult) -> None:
        result.gravatar_checked = True
        digest = hashlib.md5(result.email.encode("utf-8"), usedforsecurity=False).hexdigest()
        try:
            response = await asyncio.wait_for(
                client.get(self.gravatar_url.format(hash=digest)),
                timeout=self.timeout_seconds,
            )
        except Exception:
            return
        if response.status_code == 200:
            result.status = "possibly_exists"
            result.gravatar_hit = True

    @staticmethod
    def _classify_response(body: str) -> str:
        text = body.lower()
        not_found = (
            "couldn't find your google account",
            "couldn’t find your google account",
            "could not find your google account",
            "no google account",
            "account does not exist",
        )
        if any(signal in text for signal in not_found):
            return "not_found"
        existing = (
            "enter your password",
            "choose an account",
            "account exists",
            "password assistance",
            "signinchallenge",
            "identifier_exists",
        )
        if any(signal in text for signal in existing):
            return "verified"
        return "inconclusive"


__all__ = ["GoogleWorkspaceVerifier", "VerificationResult"]
