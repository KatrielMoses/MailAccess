"""Reactive name-to-email pivot across public search snippets."""

from __future__ import annotations

from typing import Any

from ..config import settings
from ..core.email_extraction import extract_emails
from ..core.search_provider_router import SearchProviderRouter
from .base import BaseModule, ModuleResult, ModuleStatus


class PersonaEmailPivotModule(BaseModule):
    name = "persona_email_pivot"
    description = "Dork for a specific person's email addresses across the web"
    requires_key = False
    default_enabled = False

    async def run(self, domain: str) -> ModuleResult:
        return ModuleResult(status=ModuleStatus.SKIPPED, findings=[])

    async def run_with_payload(
        self,
        payload: dict[str, Any],
        *,
        fetch: Any | None = None,
        progress_callback: Any | None = None,
    ) -> ModuleResult:
        if not bool(getattr(settings, "persona_pivot_enabled", True)):
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"reason": "disabled"})
        name = " ".join(str(payload.get("name") or "").split())
        domain = str(payload.get("domain") or "").strip().lower().rstrip(".")
        title = str(payload.get("title") or "").strip()
        if len(name.split()) < 2 or not domain:
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"reason": "invalid_payload"})

        queries = [
            f'"{name}" "@{domain}"',
            f'"{name}" "email" "{domain}"',
            f'"{name}" "@gmail.com" OR "@outlook.com" OR "@yahoo.com"',
        ][: max(0, int(getattr(settings, "persona_pivot_max_queries_per_name", 3)))]
        router = SearchProviderRouter(fetch=fetch)
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        errors: list[str] = []
        for index, query in enumerate(queries, 1):
            if progress_callback:
                progress_callback(f"Searching for {name} ({index}/{len(queries)})...")
            try:
                results = await router.search(query, max_results=10)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"query {index}: {exc}")
                continue
            for result in results:
                text = f"{getattr(result, 'title', '')} {getattr(result, 'snippet', '')}"
                for extracted in extract_emails(text):
                    email = extracted.email.strip().lower()
                    if email in seen:
                        continue
                    seen.add(email)
                    is_org = email.rsplit("@", 1)[-1] == domain
                    source_type = "persona_pivot_org" if is_org else "persona_pivot_personal"
                    tag = "org_email_candidate" if is_org else "personal_email_candidate"
                    score = 0.45 if is_org else 0.35
                    findings.append(
                        {
                            "platform": self.name,
                            "profile_url": getattr(result, "url", None),
                            "username": email.split("@", 1)[0],
                            "confidence": "low",
                            "metadata": {
                                "email": email,
                                "name": name,
                                "source_name": name,
                                "title_or_role": title,
                                "source_url": getattr(result, "url", None),
                                "source_type": source_type,
                                "tags": [tag],
                                "confidence_score": score,
                                "on_domain": is_org,
                                "personal_email_candidate": not is_org,
                                "search_provider": getattr(result, "provider", "unknown"),
                            },
                        }
                    )
        return ModuleResult(
            status=ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL,
            findings=findings,
            errors=errors,
            metadata={"name": name, "queries_run": len(queries), "emails_found": len(findings)},
        )


__all__ = ["PersonaEmailPivotModule"]
