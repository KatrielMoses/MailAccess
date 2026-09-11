"""Opt-in Microsoft Entra account-existence signal.

The endpoint is undocumented and tenant-config-dependent. Results are
therefore deliberately typed as evidence, with unmanaged/throttled/error
responses remaining inconclusive.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from .http_client import build_client

_LOG = logging.getLogger(__name__)


@dataclass
class M365VerificationResult:
    email: str
    status: str = "inconclusive"
    if_exists_result: int | None = None
    is_unmanaged: bool | None = None
    throttle_status: int | None = None
    http_status: int | None = None
    error: str | None = None
    # Check 2: explicit existence verdict + confidence. ``exists`` is True for
    # any IfExistsResult that means the account is present (0 / 5 / 6); the
    # federated-IdP case (5) carries a ``note`` and a slightly lower
    # ``confidence`` because the third-party IdP adds one layer of indirection.
    exists: bool | None = None
    note: str | None = None
    confidence: float | None = None


class M365Verifier:
    endpoint = "https://login.microsoftonline.com/common/GetCredentialType"

    def __init__(self, *, delay_seconds: float = 0.1, timeout_seconds: float = 10.0, max_checks: int = 50) -> None:
        self.delay_seconds = max(float(delay_seconds), 0.0)
        self.timeout_seconds = max(float(timeout_seconds), 1.0)
        self.max_checks = max(1, min(int(max_checks), 100))

    async def verify_batch(self, emails: list[str]) -> list[M365VerificationResult]:
        cleaned = list(
            dict.fromkeys(
                e.strip().lower() for e in emails if isinstance(e, str) and "@" in e
            )
        )
        # FIX (Root E cross-tenant): GetCredentialType's catch-all control probe is
        # a PER-TENANT signal, but a pattern batch can span many domains/tenants. A
        # single control taken from the first email only covers the first tenant, so
        # a catch-all SECOND-domain tenant would falsely report "verified" for its
        # addresses. Group by domain and run one control probe per domain/tenant,
        # while sharing ONE max_checks budget across the whole batch so the per-run
        # cap is honoured regardless of how many tenants are present.
        by_domain: dict[str, list[str]] = {}
        for e in cleaned:
            by_domain.setdefault(e.rsplit("@", 1)[-1], []).append(e)

        results_by_email: dict[str, M365VerificationResult] = {}
        checks_used = 0
        async with build_client(timeout=self.timeout_seconds, follow_redirects=True) as client:
            first_probe = True
            for control_domain, group in by_domain.items():
                # Per-tenant control probe: a guaranteed-nonexistent address on THIS
                # domain. If the tenant reports it existing (IfExistsResult == 0 →
                # "verified"), it returns "exists" for everything on this tenant —
                # mark only this domain's addresses inconclusive and skip probing them.
                if not first_probe and self.delay_seconds:
                    await asyncio.sleep(self.delay_seconds)
                first_probe = False
                control_email = f"probe-{uuid.uuid4().hex[:12]}@{control_domain}"
                control = await self._verify_one(client, control_email)
                if control.if_exists_result == 0 or control.status == "verified":
                    _LOG.warning(
                        "M365 tenant appears to return exists for all (%s)",
                        control_domain,
                    )
                    for email in group:
                        results_by_email[email] = M365VerificationResult(
                            email=email,
                            status="inconclusive",
                            error="catchall_tenant",
                        )
                    continue
                for email in group:
                    if checks_used >= self.max_checks:
                        results_by_email[email] = M365VerificationResult(
                            email=email, status="not_attempted"
                        )
                        continue
                    if self.delay_seconds:
                        await asyncio.sleep(self.delay_seconds)
                    results_by_email[email] = await self._verify_one(client, email)
                    checks_used += 1
        # Preserve the caller's input order.
        return [results_by_email[e] for e in cleaned]

    async def _verify_one(self, client: Any, email: str) -> M365VerificationResult:
        try:
            response = await client.post(
                self.endpoint,
                json={"Username": email, "isOtherIdpSupported": True},
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001
            return M365VerificationResult(email=email, error=f"{type(exc).__name__}: {exc}")
        result = M365VerificationResult(email=email, http_status=response.status_code)
        if response.status_code == 429:
            result.status = "throttled"
            return result
        if response.status_code != 200:
            result.error = f"http_{response.status_code}"
            return result
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            result.error = f"invalid_json:{exc}"
            return result
        result.if_exists_result = _int_or_none(payload.get("IfExistsResult"))
        result.is_unmanaged = _bool_or_none(payload.get("IsUnmanaged"))
        result.throttle_status = _int_or_none(payload.get("ThrottleStatus"))
        if result.throttle_status not in (None, 0) or result.if_exists_result == 2:
            result.status = "throttled"
        elif result.is_unmanaged is True:
            result.status = "inconclusive"
        elif result.if_exists_result in (0, 5, 6):
            result.status = "verified"
            result.exists = True
            if result.if_exists_result == 5:
                # Check 2: IfExistsResult 5 == account exists but on a
                # different IdP (Google / Okta / Ping). This is a real
                # existence signal — treat it as exists, but at a slightly
                # lower confidence than a native M365 mailbox because the
                # federated IdP introduces one layer of indirection.
                result.note = "federated_idp"
                result.confidence = 0.75
        elif result.if_exists_result == 1:
            result.status = "not_found"
            result.exists = False
        else:
            result.status = "inconclusive"
        return result


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None
