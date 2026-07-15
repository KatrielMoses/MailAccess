"""Keyless public forge discovery, currently GitLab.com."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from ..config import settings
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_API = "https://gitlab.com/api/v4"


def _json(response: Any) -> Any:
    method = getattr(response, "json", None)
    if callable(method):
        return method()
    return json.loads(getattr(response, "text", "") or "{}")


def _keyword(domain: str) -> str:
    parts = [p for p in domain.lower().split(".") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


class PublicForgeModule(BaseModule):
    name = "public_forge"
    description = "Bounded GitLab public project and commit metadata discovery without an API key."
    requires_key = False
    default_enabled = True

    async def run(self, domain: str, *, fetch: CachedFetch | None = None) -> ModuleResult:
        domain = (domain or "").strip().lower()
        if not settings.enable_public_forge:
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"domain": domain})
        keyword = _keyword(domain)
        if not keyword:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["no forge keyword"])

        async def get(url: str) -> Any:
            if fetch is not None:
                return await fetch.get(url)
            async with build_client(timeout=8.0) as client:
                return await client.get(url)

        errors: list[str] = []
        findings: list[dict[str, Any]] = []
        projects_checked = 0
        try:
            response = await get(f"{_API}/projects?search={quote(keyword)}&simple=true&per_page={settings.public_forge_max_projects}")
            if int(getattr(response, "status_code", 0) or 0) >= 400:
                return ModuleResult(status=ModuleStatus.FAILED, errors=[f"gitlab projects: HTTP {response.status_code}"], metadata={"domain": domain})
            projects = _json(response)
            if not isinstance(projects, list):
                projects = []
            for project in projects[: settings.public_forge_max_projects]:
                project_id = project.get("id") if isinstance(project, dict) else None
                if not project_id:
                    continue
                commits = await get(f"{_API}/projects/{project_id}/repository/commits?per_page={settings.public_forge_max_commits}")
                projects_checked += 1
                if int(getattr(commits, "status_code", 0) or 0) >= 400:
                    errors.append(f"project {project_id}: HTTP {commits.status_code}")
                    continue
                rows = _json(commits)
                if not isinstance(rows, list):
                    continue
                for commit in rows:
                    if not isinstance(commit, dict):
                        continue
                    raw = commit.get("author_email") or commit.get("committer_email") or ""
                    for item in extract_emails(str(raw), target_domain=domain):
                        if item.on_domain:
                            findings.append({
                                "platform": self.name,
                                "profile_url": project.get("web_url", ""),
                                "username": item.email.split("@", 1)[0],
                                "confidence": "high",
                                "metadata": {"email": item.email, "on_domain": True, "forge": "gitlab", "project": project.get("path_with_namespace"), "commit": commit.get("id")},
                            })
        except Exception as exc:
            errors.append(f"gitlab: {exc}")
        status = ModuleStatus.SUCCESS if projects_checked else ModuleStatus.FAILED
        if errors and projects_checked:
            status = ModuleStatus.PARTIAL
        return ModuleResult(status=status, findings=findings, metadata={"domain": domain, "projects_checked": projects_checked, "email_hits": len(findings)}, errors=errors[:10])
