"""Hunter.io email verification module (investigate path).

Phase 6 (0.14.0).  Verifies a single email address against Hunter.io's
email-verifier endpoint and surfaces the deliverability verdict + score in
the investigation's verification panel.  The domain-wide harvest path lives
in :func:`backend.core.hunter_client.search_domain` (wrapped by the harvest
orchestrator); this module is the per-email verify half.

Mapping (result + score → MailAccess confidence):

* ``deliverable`` & score >= 80 → 0.85 (``hunter_verified``)
* ``deliverable`` & score <  80 → 0.70 (``hunter_high``)
* ``risky``                     → 0.45 (``hunter_low``)
* ``undeliverable``            → not_found
* ``unknown``                  → inconclusive
"""

from __future__ import annotations

from ..config import settings
from ..core.hunter_client import verify_email
from .base import BaseModule, ModuleResult, ModuleStatus


class HunterIoModule(BaseModule):
    name = "hunter_io"
    description = "Verify email deliverability and find associated domain info via Hunter.io."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.hunter_io_api_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["HUNTER_IO_API_KEY not set"],
            )

        result = await verify_email(email, settings.hunter_io_api_key)
        if result is None:
            # Capped quota, invalid key, network error, or unparseable body —
            # all already logged inside the client.  Nothing to surface.
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["Hunter.io verification unavailable"],
            )

        confidence, source_type, verification_status = result.mailaccess
        summary = f"Hunter.io: {result.result} (score: {result.score})"

        metadata = {
            "email": result.email,
            "result": result.result,
            "score": result.score,
            "verification_status": verification_status,
            "confidence_score": confidence,
            "source_type": source_type,
            "regexp": result.regexp,
            "gibberish": result.gibberish,
            "disposable": result.disposable,
            "webmail": result.webmail,
            "mx_records": result.mx_records,
            "smtp_server": result.smtp_server,
            "smtp_check": result.smtp_check,
            "block": result.block,
            "sources": result.sources,
            "summary": summary,
        }

        if verification_status == "not_found":
            # Hunter says the address is undeliverable — record the verdict
            # but do not assert existence.
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[
                    {
                        "platform": "hunter_io",
                        "confidence": "none",
                        "severity": "info",
                        "metadata": metadata,
                    }
                ],
                metadata={
                    "verification_status": "not_found",
                    "hunter_result": result.result,
                    "hunter_score": result.score,
                    "summary": summary,
                },
            )

        if verification_status == "inconclusive":
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[
                    {
                        "platform": "hunter_io",
                        "confidence": "none",
                        "severity": "info",
                        "metadata": metadata,
                    }
                ],
                metadata={
                    "verification_status": "inconclusive",
                    "hunter_result": result.result,
                    "hunter_score": result.score,
                    "summary": summary,
                },
            )

        # Deliverable or risky — a usable verification result.
        confidence_label = "high" if (confidence or 0) >= 0.80 else "medium"
        if verification_status == "verified" and source_type == "hunter_low":
            confidence_label = "low"

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "hunter_io",
                    "confidence": confidence_label,
                    "severity": "info",
                    "metadata": metadata,
                }
            ],
            metadata={
                "verification_status": verification_status,
                "hunter_result": result.result,
                "hunter_score": result.score,
                "confidence_score": confidence,
                "source_type": source_type,
                "summary": summary,
            },
        )
