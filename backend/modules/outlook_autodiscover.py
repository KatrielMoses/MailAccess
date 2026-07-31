"""Microsoft Autodiscover account-existence probe (FIX 2).

The Autodiscover v1 JSON endpoint answers whether a mailbox is
serviced by Microsoft 365 without authentication, without sending any
mail, and without the throttling that hits ``GetCredentialType``. It is
therefore run FIRST on M365 domains; ``GetCredentialType`` is only
consulted for addresses Autodiscover cannot confirm.

Response interpretation (redirects are NOT followed, so the raw status
is observed):

    HTTP 200 → mailbox exists      → status="verified"
    HTTP 302 → mailbox not found   → status="not_found"
    HTTP 429 → rate limited        → status="inconclusive" (stop; no retry)
    other    → inconclusive        → status="inconclusive"

The verifier is reused by the domain-harvest orchestrator; the
``OutlookAutodiscoverModule`` wraps it for the single-email investigate
path and self-skips for any non-consumer-Microsoft domain.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

#: Source-type identifier mirrored in email_confidence.SOURCE_WEIGHTS.
SOURCE_TYPE = "autodiscover_m365"

#: Check 3 — REST Autodiscover variant. Source-type mirrored in
#: email_confidence.SOURCE_WEIGHTS (0.88, just below autodiscover_m365).
REST_SOURCE_TYPE = "autodiscover_rest"

#: Consumer Microsoft mail domains that the investigate path probes
#: directly (custom M365 tenants are handled by the orchestrator).
CONSUMER_MS_DOMAINS: frozenset[str] = frozenset(
    {"outlook.com", "hotmail.com", "live.com", "msn.com"}
)

_ENDPOINT = (
    "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/"
    "{email}?Protocol=Autodiscoverv1"
)

#: Check 3 — REST Autodiscover variant. Unlike the v1 probe (which reads the
#: raw 200/302), the REST probe FOLLOWS redirects and inspects the final URL
#: host: still on ``outlook.office365.com`` means the mailbox exists; a
#: redirect away means it does not.
_REST_ENDPOINT = (
    "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/"
    "{email}?Protocol=rest"
)

#: Host that a REST probe must land on for the mailbox to be considered
#: existent.
_REST_EXPECTED_HOST = "outlook.office365.com"

#: Hard cap on probes per harvest run (spec: max 50).
DEFAULT_MAX_PROBES = 50
#: Per-request timeout (spec: 8s).
DEFAULT_TIMEOUT = 8.0


@dataclass
class AutodiscoverResult:
    email: str
    status: str = "inconclusive"  # verified / not_found / inconclusive / not_attempted
    http_status: int | None = None
    error: str | None = None
    source_type: str = SOURCE_TYPE


class AutodiscoverVerifier:
    """Batch Autodiscover existence probe with a per-run cap."""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT,
        max_checks: int = DEFAULT_MAX_PROBES,
    ) -> None:
        self.timeout_seconds = max(float(timeout_seconds), 1.0)
        self.max_checks = max(1, min(int(max_checks), DEFAULT_MAX_PROBES))

    async def verify_batch(self, emails: list[str]) -> list[AutodiscoverResult]:
        cleaned = list(
            dict.fromkeys(
                e.strip().lower() for e in emails if isinstance(e, str) and "@" in e
            )
        )
        results: list[AutodiscoverResult] = []
        if not cleaned:
            return results
        # follow_redirects MUST stay False: a 302 is the "not found"
        # signal, and following it would hide it behind the redirect
        # target's status.
        async with build_client(
            timeout=self.timeout_seconds, follow_redirects=False
        ) as client:
            stop = False
            for index, email in enumerate(cleaned):
                if stop or index >= self.max_checks:
                    results.append(
                        AutodiscoverResult(email=email, status="not_attempted")
                    )
                    continue
                result = await self._probe_one(client, email)
                results.append(result)
                # FIX 2: no retry on 429 — mark inconclusive and stop the
                # rest of the batch so we do not hammer a throttling host.
                if result.http_status == 429:
                    stop = True
        return results

    async def _probe_one(self, client: Any, email: str) -> AutodiscoverResult:
        url = _ENDPOINT.format(email=email)
        try:
            response = await asyncio.wait_for(
                client.post(
                    url,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                ),
                timeout=self.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - surface as inconclusive
            return AutodiscoverResult(
                email=email, error=f"{type(exc).__name__}: {exc}"
            )
        result = AutodiscoverResult(email=email, http_status=response.status_code)
        if response.status_code == 200:
            result.status = "verified"
        elif response.status_code == 302:
            result.status = "not_found"
        elif response.status_code == 429:
            result.status = "inconclusive"
            result.error = "rate_limited"
        else:
            result.status = "inconclusive"
            result.error = f"http_{response.status_code}"
        return result

    async def rest_verify_batch(self, emails: list[str]) -> list[AutodiscoverResult]:
        """Check 3 — probe the REST Autodiscover variant for a batch.

        Runs alongside :meth:`verify_batch`. The REST variant FOLLOWS
        redirects, so a dedicated client with ``follow_redirects=True`` is
        used and the final URL host is inspected rather than the raw status.
        """
        cleaned = list(
            dict.fromkeys(
                e.strip().lower() for e in emails if isinstance(e, str) and "@" in e
            )
        )
        results: list[AutodiscoverResult] = []
        if not cleaned:
            return results
        # follow_redirects MUST be True here: the "does it still land on
        # office365" test is the entire signal.
        async with build_client(
            timeout=self.timeout_seconds, follow_redirects=True
        ) as client:
            stop = False
            for index, email in enumerate(cleaned):
                if stop or index >= self.max_checks:
                    results.append(
                        AutodiscoverResult(
                            email=email,
                            status="not_attempted",
                            source_type=REST_SOURCE_TYPE,
                        )
                    )
                    continue
                result = await self._probe_rest_one(client, email)
                results.append(result)
                if result.http_status == 429:
                    stop = True
        return results

    async def _probe_rest_one(self, client: Any, email: str) -> AutodiscoverResult:
        url = _REST_ENDPOINT.format(email=email)
        try:
            response = await asyncio.wait_for(
                client.get(
                    url,
                    headers={"Accept": "application/json"},
                ),
                timeout=self.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - surface as inconclusive
            return AutodiscoverResult(
                email=email,
                error=f"{type(exc).__name__}: {exc}",
                source_type=REST_SOURCE_TYPE,
            )
        result = AutodiscoverResult(
            email=email,
            http_status=response.status_code,
            source_type=REST_SOURCE_TYPE,
        )
        if response.status_code == 429:
            result.status = "inconclusive"
            result.error = "rate_limited"
            return result
        final_host = _final_host(response)
        if final_host is None:
            result.status = "inconclusive"
            result.error = "no_final_url"
        elif final_host == _REST_EXPECTED_HOST or final_host.endswith(
            "." + _REST_EXPECTED_HOST
        ):
            # Still on outlook.office365.com after following redirects → the
            # mailbox exists.
            result.status = "verified"
        else:
            # Redirected away from office365 → the mailbox does not exist.
            result.status = "not_found"
        return result


def _final_host(response: Any) -> str | None:
    """Extract the final URL host from an httpx-style response.

    Handles both ``httpx.URL`` (``.host``) and plain-string ``.url`` shapes
    so the REST probe is easy to drive from tests.
    """
    url = getattr(response, "url", None)
    if url is None:
        return None
    host = getattr(url, "host", None)
    if host:
        return str(host).strip().lower().rstrip(".")
    parsed = urlparse(str(url))
    return parsed.hostname.strip().lower().rstrip(".") if parsed.hostname else None


@dataclass
class AutodiscoverReconciliation:
    """Cross-variant reconciliation of the v1 and REST Autodiscover probes."""

    status: str  # verified | not_found | inconclusive
    agreement: bool
    higher_confidence: bool
    v1_status: str
    rest_status: str


def reconcile_autodiscover(
    v1_status: str, rest_status: str
) -> AutodiscoverReconciliation:
    """Reconcile the two Autodiscover variants (Check 3).

    * both agree on a decisive verdict → that verdict, ``agreement=True``;
      ``higher_confidence`` is True only for a shared ``verified`` (two
      independent existence confirmations).
    * they disagree (one verified, one not_found) → ``inconclusive``.
    * one decisive, the other inconclusive → the decisive verdict, but not
      flagged as higher-confidence.
    """
    decisive = {"verified", "not_found"}
    if v1_status == rest_status and v1_status in decisive:
        return AutodiscoverReconciliation(
            status=v1_status,
            agreement=True,
            higher_confidence=v1_status == "verified",
            v1_status=v1_status,
            rest_status=rest_status,
        )
    if v1_status in decisive and rest_status in decisive:
        # Genuine disagreement between two decisive verdicts.
        return AutodiscoverReconciliation(
            status="inconclusive",
            agreement=False,
            higher_confidence=False,
            v1_status=v1_status,
            rest_status=rest_status,
        )
    for status in (v1_status, rest_status):
        if status in decisive:
            return AutodiscoverReconciliation(
                status=status,
                agreement=False,
                higher_confidence=False,
                v1_status=v1_status,
                rest_status=rest_status,
            )
    return AutodiscoverReconciliation(
        status="inconclusive",
        agreement=False,
        higher_confidence=False,
        v1_status=v1_status,
        rest_status=rest_status,
    )


class OutlookAutodiscoverModule(BaseModule):
    name = "outlook_autodiscover"
    description = (
        "Confirm a consumer Microsoft mailbox (@outlook.com / @hotmail.com / "
        "@live.com / @msn.com) via the unauthenticated Autodiscover v1 endpoint."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_outlook_autodiscover:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "outlook_autodiscover disabled — "
                    "set ENABLE_OUTLOOK_AUTODISCOVER=true to enable"
                ],
            )
        cleaned = (email or "").strip().lower()
        domain = cleaned.rsplit("@", 1)[-1] if "@" in cleaned else ""
        if domain not in CONSUMER_MS_DOMAINS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["outlook_autodiscover: not a consumer Microsoft domain"],
                metadata={"skip_reason": "non_microsoft_domain", "domain": domain},
            )

        verifier = AutodiscoverVerifier(
            timeout_seconds=settings.autodiscover_timeout_seconds,
            max_checks=settings.autodiscover_max_probes,
        )
        results = await verifier.verify_batch([cleaned])
        result = results[0] if results else AutodiscoverResult(email=cleaned)

        findings: list[dict[str, Any]] = []
        if result.status == "verified":
            findings.append(
                {
                    "platform": "outlook_autodiscover",
                    "profile_url": None,
                    "username": cleaned.split("@", 1)[0],
                    "confidence": "high",
                    "metadata": {
                        "email": cleaned,
                        "source_type": SOURCE_TYPE,
                        "verification_status": "verified",
                        "provider_verification_provider": "autodiscover",
                        "provider_verification_status": "verified",
                        "http_status": result.http_status,
                    },
                }
            )
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "email": cleaned,
                "domain": domain,
                "autodiscover_status": result.status,
                "http_status": result.http_status,
                "error": result.error,
            },
        )


__all__ = [
    "AutodiscoverResult",
    "AutodiscoverReconciliation",
    "AutodiscoverVerifier",
    "OutlookAutodiscoverModule",
    "SOURCE_TYPE",
    "REST_SOURCE_TYPE",
    "CONSUMER_MS_DOMAINS",
    "reconcile_autodiscover",
]
