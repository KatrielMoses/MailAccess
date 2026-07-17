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
        max_checks: int = 25,
    ) -> None:
        self.delay_seconds = max(float(delay_seconds), 0.0)
        self.timeout_seconds = max(float(timeout_seconds), 1.0)
        self.gravatar_enabled = bool(gravatar_enabled)
        self.max_checks = max(1, min(int(max_checks), 100))

    async def verify_batch(
        self,
        emails: list[str],
        domain: str,
        session: Any | None = None,
        max_checks: int = 25,
    ) -> list[VerificationResult]:
        del domain  # Provider detection is performed by the caller.
        cleaned = list(dict.fromkeys(
            e.strip().lower() for e in emails
            if isinstance(e, str) and "@" in e
        ))
        cap = max(1, min(int(max_checks), self.max_checks, 100))
        own_client = session is None
        client = session or build_client(timeout=self.timeout_seconds, follow_redirects=True)
        results: list[VerificationResult] = []
        try:
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
                    continue
                if result.status == "inconclusive" and self.gravatar_enabled:
                    await self._gravatar(client, result)
                results.append(result)
            return results
        finally:
            if own_client:
                close = getattr(client, "aclose", None)
                if close is not None:
                    await close()

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
