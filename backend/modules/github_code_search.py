from __future__ import annotations

import logging
import re
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_NOISE_EMAIL_EXACT = frozenset({"noreply@github.com", "support@github.com"})
_NOISE_EMAIL_DOMAINS = frozenset({"users.noreply.github.com"})

_GITHUB_HEADERS: dict[str, str] = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

_CODE_SEARCH_CAP = 50
_GIST_SEARCH_CAP = 10
_ASSOCIATE_EMAIL_CAP = 10


def _is_noise_email(addr: str) -> bool:
    addr = addr.lower()
    if addr in _NOISE_EMAIL_EXACT:
        return True
    domain = addr.split("@", 1)[-1] if "@" in addr else ""
    return domain in _NOISE_EMAIL_DOMAINS


class GitHubCodeSearchModule(BaseModule):
    name = "github_code_search"
    description = (
        "Search public GitHub code and gists for the target email and surface associates."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_github_code_search or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "github_code_search disabled — set ENABLE_GITHUB_CODE_SEARCH=true to enable"
                ],
            )

        authenticated = bool(settings.github_token)
        headers = dict(_GITHUB_HEADERS)
        if authenticated:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        code_hits = 0
        gist_hits = 0
        rate_limit_remaining: int = -1
        associate_emails: list[str] = []
        associate_usernames: list[str] = []

        async with build_client(timeout=10.0) as client:
            # Code search
            code_result = await self._fetch_code(client, headers, email)
            if isinstance(code_result, str):
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    errors=[code_result],
                    metadata={
                        "code_hits": 0,
                        "gist_hits": 0,
                        "associate_emails_found": 0,
                        "associate_usernames_found": 0,
                        "authenticated": authenticated,
                        "rate_limit_remaining": rate_limit_remaining,
                    },
                )

            code_items, rate_limit_remaining = code_result
            code_hits = len(code_items)

            for item in code_items:
                repo = item["repo"]
                file_path = item["file_path"]
                html_url = item["html_url"]
                repo_owner = item["repo_owner"]

                findings.append({
                    "platform": f"github:{repo}",
                    "profile_url": html_url,
                    "username": repo_owner,
                    "confidence": "medium",
                    "metadata": {
                        "source": "github_code_search",
                        "type": "code_search_hit",
                        "repo": repo,
                        "file_path": file_path,
                        "associate_emails": [],
                        "associate_usernames": [],
                        "rate_limit_remaining": rate_limit_remaining,
                    },
                })

                for m in _EMAIL_RE.finditer(file_path):
                    addr = m.group(0).lower()
                    if (
                        addr != email.lower()
                        and not _is_noise_email(addr)
                        and addr not in associate_emails
                        and len(associate_emails) < _ASSOCIATE_EMAIL_CAP
                    ):
                        associate_emails.append(addr)

                if repo_owner and repo_owner not in associate_usernames:
                    associate_usernames.append(repo_owner)

            # Gist search
            gist_result = await self._fetch_gists(client, headers, email)
            if isinstance(gist_result, str):
                errors.append(gist_result)
            else:
                gist_items, gist_rate_remaining = gist_result
                if gist_rate_remaining >= 0:
                    rate_limit_remaining = gist_rate_remaining
                gist_hits = len(gist_items)

                for item in gist_items:
                    gist_id = item["gist_id"]
                    html_url = item["html_url"]
                    owner = item["owner"]
                    description = item.get("description") or ""

                    findings.append({
                        "platform": f"gist:{gist_id}",
                        "profile_url": html_url,
                        "username": owner,
                        "confidence": "medium",
                        "metadata": {
                            "source": "github_code_search",
                            "type": "gist_hit",
                            "associate_emails": [],
                            "associate_usernames": [],
                            "rate_limit_remaining": rate_limit_remaining,
                        },
                    })

                    for m in _EMAIL_RE.finditer(description):
                        addr = m.group(0).lower()
                        if (
                            addr != email.lower()
                            and not _is_noise_email(addr)
                            and addr not in associate_emails
                            and len(associate_emails) < _ASSOCIATE_EMAIL_CAP
                        ):
                            associate_emails.append(addr)

                    if owner and owner not in associate_usernames:
                        associate_usernames.append(owner)

        logger.debug(
            "github_code_search: rate_limit_remaining=%d authenticated=%s",
            rate_limit_remaining,
            authenticated,
        )

        for finding in findings:
            finding["metadata"]["associate_emails"] = list(associate_emails)
            finding["metadata"]["associate_usernames"] = list(associate_usernames)

        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "code_hits": code_hits,
                "gist_hits": gist_hits,
                "associate_emails_found": len(associate_emails),
                "associate_usernames_found": len(associate_usernames),
                "authenticated": authenticated,
                "rate_limit_remaining": rate_limit_remaining,
            },
            errors=errors,
        )

    async def _fetch_code(
        self,
        client: Any,
        headers: dict[str, str],
        email: str,
    ) -> tuple[list[dict[str, Any]], int] | str:
        """Return (items, rate_limit_remaining) or an error string on failure."""
        try:
            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": f"{email} in:file", "per_page": 30},
                headers=headers,
            )
        except Exception as exc:
            return f"GitHub code search request failed: {exc}"

        rate_limit_remaining = int(resp.headers.get("X-RateLimit-Remaining", -1))
        logger.debug("github_code_search code: X-RateLimit-Remaining=%d", rate_limit_remaining)

        if resp.status_code == 403 and rate_limit_remaining == 0:
            return (
                "GitHub API rate limit exceeded. "
                "Set GITHUB_TOKEN to increase limits."
            )
        if resp.status_code == 422:
            logger.warning("GitHub code search: 422 Unprocessable Entity — skipping")
            return [], rate_limit_remaining
        if resp.status_code != 200:
            return f"GitHub code search: HTTP {resp.status_code}"

        try:
            data = resp.json()
        except Exception as exc:
            return f"GitHub code search: invalid JSON: {exc}"

        raw_items = (data.get("items") or [])[:_CODE_SEARCH_CAP]
        items: list[dict[str, Any]] = []
        for raw in raw_items:
            repo_full = (raw.get("repository") or {}).get("full_name", "")
            parts = repo_full.split("/", 1)
            repo_owner = parts[0] if parts else ""
            items.append({
                "repo": repo_full,
                "file_path": raw.get("path", ""),
                "html_url": raw.get("html_url", ""),
                "repo_owner": repo_owner,
                "repo_name": parts[1] if len(parts) > 1 else "",
            })
        return items, rate_limit_remaining

    async def _fetch_gists(
        self,
        client: Any,
        headers: dict[str, str],
        email: str,
    ) -> tuple[list[dict[str, Any]], int] | str:
        """Return (items, rate_limit_remaining) or an error string on failure."""
        try:
            resp = await client.get(
                "https://api.github.com/search/gists",
                params={"q": email},
                headers=headers,
            )
        except Exception as exc:
            return f"GitHub gist search request failed: {exc}"

        rate_limit_remaining = int(resp.headers.get("X-RateLimit-Remaining", -1))
        logger.debug("github_code_search gists: X-RateLimit-Remaining=%d", rate_limit_remaining)

        if resp.status_code == 403 and rate_limit_remaining == 0:
            return (
                "GitHub gist search: rate limit exceeded. "
                "Set GITHUB_TOKEN to increase limits."
            )
        if resp.status_code in (404, 422):
            logger.debug("GitHub gist search: HTTP %d — skipping", resp.status_code)
            return [], rate_limit_remaining
        if resp.status_code != 200:
            return f"GitHub gist search: HTTP {resp.status_code}"

        try:
            data = resp.json()
        except Exception as exc:
            return f"GitHub gist search: invalid JSON: {exc}"

        raw_items = (data.get("items") or [])[:_GIST_SEARCH_CAP]
        items: list[dict[str, Any]] = []
        for raw in raw_items:
            owner_obj = raw.get("owner") or {}
            owner_login = (
                owner_obj.get("login", "")
                if isinstance(owner_obj, dict)
                else str(owner_obj)
            )
            items.append({
                "gist_id": raw.get("id", ""),
                "html_url": raw.get("html_url", ""),
                "owner": owner_login,
                "description": raw.get("description", ""),
            })
        return items, rate_limit_remaining
