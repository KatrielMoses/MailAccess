"""Adaptive enrichment wrapper for public identity sources.

The underlying Gravatar and GitHub-commit modules predate adaptive harvest
mode and accept an email as their direct input.  This wrapper gives them the
same payload/transport seam as the name pivots and attaches the triggering
email to every returned finding so aggregation can retain the identity link.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .base import BaseModule, ModuleResult, ModuleStatus
from .github_commits import GitHubCommitsModule
from .gravatar_lookup import GravatarLookupModule


class EmailIdentityEnrichmentModule(BaseModule):
    name = "email_identity_enrichment"
    description = "Enrich discovered emails with Gravatar and GitHub commit identity evidence"
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        return ModuleResult(status=ModuleStatus.SKIPPED, findings=[])

    async def run_with_payload(
        self,
        payload: dict[str, Any],
        *,
        fetch: Any | None = None,
    ) -> ModuleResult:
        email = str(payload.get("email") or "").strip().lower()
        if "@" not in email:
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"email": email})

        original_email = str(payload.get("original_email") or email).strip().lower()
        gravatar, github = await asyncio.gather(
            GravatarLookupModule().run(email),
            GitHubCommitsModule().run(email, original_email=original_email),
            return_exceptions=True,
        )
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        statuses: dict[str, str] = {}
        for source, result in (("gravatar", gravatar), ("github_commits", github)):
            if isinstance(result, Exception):
                errors.append(f"{source}: {result}")
                statuses[source] = "failed"
                continue
            statuses[source] = result.status.value
            errors.extend(f"{source}: {error}" for error in result.errors or [])
            for finding in result.findings or []:
                if not isinstance(finding, dict):
                    continue
                enriched = dict(finding)
                metadata = dict(enriched.get("metadata") or {})
                metadata.setdefault("email", email)
                metadata.setdefault("original_email", original_email)
                metadata.setdefault("source_type", source)
                enriched["metadata"] = metadata
                findings.append(enriched)

        return ModuleResult(
            status=ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL,
            findings=findings,
            errors=errors,
            metadata={
                "email": email,
                "original_email": original_email,
                "sources": statuses,
                "findings_count": len(findings),
            },
        )
