from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote_plus

from ..config import settings
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.work_scheduler import PRIORITY_HIGH_SIGNAL, TRACK_GUARANTEED, WorkItem
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)


async def _github_name_pivot(
    name: str,
    source: str,
    metadata: dict
) -> list[WorkItem]:
    from backend.core.name_classifier import classify_name

    result = classify_name(name)
    if not result.is_person and not metadata.get("derived_from_email"):
        return []
    if len(name.strip().split()) < 2 and not metadata.get("derived_from_email"):
        return []
    module_name = "person_email_pivot" if metadata.get("derived_from_email") else "name_to_github_profile"
    return [WorkItem(
        kind="run_module",
        module_name=module_name,
        payload={
            "name": name,
            "domain": metadata.get("domain", ""),
            "title": metadata.get("title_or_role", ""),
        },
        priority=PRIORITY_HIGH_SIGNAL,
        track=TRACK_GUARANTEED,
        source="name_subscriber",
    )]


class NameToGitHubProfileModule(BaseModule):
    name = "name_to_github_profile"
    description = (
        "Find a person's GitHub profile by name and extract their public email and blog URL"
    )
    requires_key = False

    async def run(self, domain: str) -> ModuleResult:
        # Not expected to be called directly with just domain
        return ModuleResult(status=ModuleStatus.SKIPPED, findings=[])

    async def run_with_payload(
        self,
        payload: dict,
        *,
        fetch: CachedFetch | None = None,
    ) -> ModuleResult:
        name = payload["name"]
        domain = payload.get("domain", "")

        token = getattr(settings, "github_token", "") or ""
        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"

        query = quote_plus(name)
        search_urls = [
            f"https://api.github.com/search/users?q={query}&per_page=5"
        ]
        if domain:
            org = quote_plus(domain.split(".", 1)[0])
            search_urls.insert(
                0,
                f"https://api.github.com/search/users?q={query}+org:{org}&per_page=5",
            )

        findings: list[dict[str, Any]] = []
        new_items: list[WorkItem] = []

        client = fetch or getattr(self, "session", None)
        if client is None:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                errors=["GitHub profile pivot has no HTTP transport"],
            )

        async def _get(url: str) -> Any:
            # CachedFetch deliberately accepts URL-only requests so identical
            # harvest URLs can be coalesced.  The unauthenticated GitHub API
            # path is sufficient here; injected legacy sessions may still
            # receive the optional token header.
            if fetch is not None:
                return await fetch.get(url)
            return await client.get(url, headers=headers)

        def _json(response: Any) -> dict[str, Any]:
            parser = getattr(response, "json", None)
            if callable(parser):
                value = parser()
                return value if isinstance(value, dict) else {}
            body = getattr(response, "text", "") or ""
            if not body:
                content = getattr(response, "content", b"") or b""
                body = content.decode("utf-8", errors="replace")
            value = json.loads(body)
            return value if isinstance(value, dict) else {}

        try:
            users = []
            query_statuses: list[int] = []
            for search_url in search_urls:
                resp = await _get(search_url)
                query_statuses.append(resp.status_code)
                if resp.status_code == 200:
                    users.extend(_json(resp).get("items", [])[:5])
                if users:
                    break
            if not users:
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    findings=[],
                    errors=[f"GitHub search yielded no users (statuses={query_statuses})"],
                    metadata={"search_queries": len(query_statuses), "profiles_checked": 0},
                )

            deduped_users = []
            seen_logins: set[str] = set()
            for user in users:
                login = user.get("login", "")
                if login and login not in seen_logins:
                    seen_logins.add(login)
                    deduped_users.append(user)
            users = deduped_users[:5]

            for user in users:
                login = user.get("login", "")
                if not login:
                    continue
                profile_url = (
                    f"https://api.github.com/users/{login}"
                )
                profile_resp = await _get(profile_url)
                if profile_resp.status_code != 200:
                    continue
                profile = _json(profile_resp)

                email = profile.get("email") or ""
                blog = profile.get("blog") or ""
                html_url = profile.get("html_url") or ""

                if email and "@" in email and email.casefold().endswith("@" + str(domain).casefold()):
                    findings.append({
                        "platform": "github_profile",
                        "profile_url": html_url,
                        "confidence": "high",
                        "metadata": {
                            "email": email,
                            "github_login": login,
                            "source_name": name,
                            "source_url": html_url,
                            "pivot": "name_to_github_profile",
                            "confidence_score": 0.85,
                            "source_type": "github_profile_email",
                            "name": name,
                            "on_domain": True,
                        },
                    })

                if blog and blog.startswith("http"):
                    new_items.append(WorkItem(
                        kind="fetch_page",
                        url=blog,
                        priority=PRIORITY_HIGH_SIGNAL,
                        track=TRACK_GUARANTEED,
                        source=f"github_blog:{login}",
                        payload={"source_name": name},
                    ))

        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                errors=[str(exc)]
            )

        result = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "source_name": name,
                "profiles_checked": len(users),
                "search_queries": len(search_urls),
                "emails_found": len(findings),
                "blog_urls_queued": len(new_items),
            }
        )
        setattr(result, "new_items", new_items)
        return result
