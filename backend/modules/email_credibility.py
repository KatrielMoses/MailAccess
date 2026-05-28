from __future__ import annotations

from ..core.email_credibility import assess_email_reputation, export_email_credibility
from .base import BaseModule, ModuleResult, ModuleStatus


class EmailCredibilityModule(BaseModule):
    name = "email_credibility"
    description = "Normalize the email, detect aliases and disposable domains, and assess credibility."
    requires_key = False
    priority = 0

    async def run(self, email: str) -> ModuleResult:
        result = await assess_email_reputation(email)
        payload = export_email_credibility(result)
        payload["provider"] = result.provider_family
        payload["is_alias"] = result.is_alias
        payload["canonical_email"] = result.canonical_email
        payload["aliases_detected"] = result.aliases_detected
        payload["reputation_verdict"] = result.reputation_verdict
        payload["reputation_flags"] = result.reputation_flags
        payload["first_seen"] = result.first_seen
        payload["sources_checked"] = result.sources_checked
        payload["is_malicious"] = result.is_malicious
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "email_credibility",
                    "confidence": "high",
                    "severity": "high" if result.reputation_verdict != "clean" else "info",
                    "metadata": payload,
                }
            ],
            metadata=payload,
        )
