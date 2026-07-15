from __future__ import annotations

from collections import Counter
from typing import Any

import httpx

from ..config import settings
from ..core.bio_analyzer import analyze_bio, is_aggregator_url
from ..core.bio_link_extractor import extract_from_aggregator
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_GITHUB_API = "https://api.github.com"
_REPO_FETCH_LIMIT = 5
_UNKNOWN_LANGUAGE = "Unknown"


def _truncate(value: str, limit: int) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"


class GitHubCommitsModule(BaseModule):
    name = "github_commits"
    description = (
        "Search GitHub commit history for direct author-email matches, related "
        "GitHub users, and deep profile extraction."
    )
    requires_key = False

    async def run(self, email: str, original_email: str | None = None) -> ModuleResult:
        token = settings.github_token
        rate_limiter.set_delay("api.github.com", 2.0 if token else 6.0)

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        domain = email.split("@", 1)[1] if "@" in email else None
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        partial = False

        # Search original email first (exact git commit metadata match), then canonical.
        emails_to_search: list[str] = []
        if original_email and original_email.lower() != email.lower():
            emails_to_search.append(original_email)
        emails_to_search.append(email)

        try:
            async with build_client(base_url=_GITHUB_API, timeout=10.0) as client:
                seen_shas: set[str] = set()
                commit_findings: list[dict[str, Any]] = []
                for search_email in emails_to_search:
                    cf, ce, rl = await self._search_commits(client, headers, search_email)
                    for f in cf:
                        sha = str(f.get("metadata", {}).get("commit_sha") or "")
                        if sha not in seen_shas:
                            seen_shas.add(sha)
                            commit_findings.append(f)
                    errors.extend(ce)
                    partial = partial or rl
                findings.extend(commit_findings)
                await self._enrich_commit_repos(client, headers, commit_findings)

                user_findings, user_errors, rate_limited = await self._search_user(
                    client, headers, email, domain, commit_findings
                )
                findings.extend(user_findings)
                errors.extend(user_errors)
                partial = partial or rate_limited
        except httpx.TimeoutException:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub request timed out"])
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"GitHub unreachable: {exc}"])
        except Exception as exc:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"GitHub unexpected error: {exc}"])

        commit_findings = [f for f in findings if f.get("platform") == "github_commit"]
        commit_dates = [
            str(f.get("metadata", {}).get("commit_date"))
            for f in commit_findings
            if f.get("metadata", {}).get("commit_date")
        ]
        repos = [
            str(f.get("metadata", {}).get("repo"))
            for f in commit_findings
            if f.get("metadata", {}).get("repo")
        ]
        names = [
            str(f.get("metadata", {}).get("author_name"))
            for f in commit_findings
            if f.get("metadata", {}).get("author_name")
        ]
        languages: list[str] = []
        repos_counted_for_language: set[str] = set()
        for finding in commit_findings:
            metadata = finding.get("metadata", {})
            repo = str(metadata.get("repo") or "")
            language = str(metadata.get("repo_language") or "")
            if (
                repo
                and language
                and language != _UNKNOWN_LANGUAGE
                and repo not in repos_counted_for_language
            ):
                languages.append(language)
                repos_counted_for_language.add(repo)

        status = ModuleStatus.SUCCESS
        if partial:
            status = ModuleStatus.PARTIAL
        elif errors and findings:
            status = ModuleStatus.PARTIAL
        elif errors and not findings:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "commits_found": len(commit_findings),
                "repos_contributed_to": sorted(set(repos)),
                "real_name_from_git": Counter(names).most_common(1)[0][0] if names else None,
                "earliest_commit": min(commit_dates) if commit_dates else "",
                "latest_commit": max(commit_dates) if commit_dates else "",
                "primary_language": Counter(languages).most_common(1)[0][0] if languages else "",
                "github_user_found": any(f.get("platform") == "github_user" for f in findings),
            },
            errors=errors,
        )

    async def _search_commits(
        self, client: httpx.AsyncClient, headers: dict[str, str], email: str
    ) -> tuple[list[dict[str, Any]], list[str], bool]:
        try:
            response = await client.get(
                "/search/commits",
                params={
                    "q": f"author-email:{email}",
                    "sort": "author-date",
                    "order": "desc",
                    "per_page": "10",
                },
                headers=headers,
            )
        except httpx.TimeoutException:
            return [], ["GitHub commit search timed out"], False
        except Exception as exc:
            return [], [f"GitHub commit search failed: {exc}"], False

        if _is_rate_limited(response):
            return [], ["GitHub API rate limit reached during commit search"], True
        if response.status_code in (403, 422) and "Authorization" not in headers:
            return [], ["GitHub commit search requires GITHUB_TOKEN. Set via: mailaccess keys set GITHUB_TOKEN your-token-here"], True
        if response.status_code != 200:
            return [], [f"GitHub commit search returned {response.status_code}"], False

        try:
            items = response.json().get("items") or []
        except Exception:
            return [], ["GitHub commit search returned unparseable JSON"], False

        findings: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
            author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
            repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            repo_name = str(repository.get("full_name") or "")
            repo_url = str(repository.get("html_url") or "")
            sha = str(item.get("sha") or "")
            findings.append(
                {
                    "platform": "github_commit",
                    "profile_url": str(item.get("html_url") or ""),
                    "confidence": "high",
                    "metadata": {
                        "repo": repo_name,
                        "repo_url": repo_url,
                        "commit_sha": sha[:7],
                        "commit_message": _truncate(str(commit.get("message") or ""), 100),
                        "author_name": str(author.get("name") or ""),
                        "commit_date": str(author.get("date") or ""),
                        "repo_description": None,
                        "repo_stars": 0,
                        "repo_language": _UNKNOWN_LANGUAGE,
                    },
                }
            )
        return findings, [], False


    async def _enrich_commit_repos(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        findings: list[dict[str, Any]],
    ) -> None:
        repo_names = []
        for finding in findings:
            repo_name = str(finding.get("metadata", {}).get("repo") or "")
            if repo_name and repo_name not in repo_names:
                repo_names.append(repo_name)

        repo_cache: dict[str, dict[str, Any]] = {}
        for repo_name in repo_names[:_REPO_FETCH_LIMIT]:
            repo_cache[repo_name] = await self._fetch_repo_detail(client, headers, repo_name)

        for finding in findings:
            metadata = finding.get("metadata")
            if not isinstance(metadata, dict):
                continue
            repo_detail = repo_cache.get(str(metadata.get("repo") or ""))
            if not repo_detail:
                continue
            metadata["repo_description"] = repo_detail.get("description")
            metadata["repo_stars"] = int(repo_detail.get("stargazers_count") or 0)
            metadata["repo_language"] = repo_detail.get("language") or _UNKNOWN_LANGUAGE

    async def _fetch_repo_detail(
        self, client: httpx.AsyncClient, headers: dict[str, str], full_name: str
    ) -> dict[str, Any]:
        try:
            response = await client.get(f"/repos/{full_name}", headers=headers, timeout=5.0)
        except (httpx.TimeoutException, httpx.HTTPError):
            return {}
        except Exception:
            return {}

        if response.status_code != 200:
            return {}
        try:
            data = response.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    async def _search_user(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        email: str,
        domain: str | None,
        commit_findings: list[dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], list[str], bool]:
        try:
            response = await client.get(
                "/search/users",
                params={"q": f"{email} in:email"},
                headers=headers,
            )
        except httpx.TimeoutException:
            return [], ["GitHub user search timed out"], False
        except Exception as exc:
            return [], [f"GitHub user search failed: {exc}"], False

        if _is_rate_limited(response):
            return [], ["GitHub API rate limit reached during user search"], True
        if response.status_code != 200:
            return [], [f"GitHub user search returned {response.status_code}"], False

        try:
            items = response.json().get("items") or []
        except Exception:
            return [], ["GitHub user search returned unparseable JSON"], False

        if not items or not isinstance(items[0], dict):
            # Fall back to looking up the repo owner extracted from commit findings.
            if commit_findings:
                owners: list[str] = []
                for cf in commit_findings:
                    repo = str(cf.get("metadata", {}).get("repo") or "")
                    if "/" in repo:
                        owner = repo.split("/", 1)[0]
                        if owner and owner not in owners:
                            owners.append(owner)
                for owner in owners:
                    detail, detail_error, rate_limited = await self._fetch_user_detail(
                        client, headers, f"{_GITHUB_API}/users/{owner}"
                    )
                    if detail:
                        findings = await self._build_user_findings(detail, domain, client)
                        errors = [detail_error] if detail_error else []
                        return findings, errors, rate_limited
            return [], [], False

        user = dict(items[0])
        detail_url = user.get("url")
        if isinstance(detail_url, str) and detail_url:
            detail, detail_error, rate_limited = await self._fetch_user_detail(
                client, headers, detail_url
            )
            if detail:
                user.update(detail)
            if detail_error:
                findings = await self._build_user_findings(user, domain, client)
                return findings, [detail_error], rate_limited
            if rate_limited:
                findings = await self._build_user_findings(user, domain, client)
                return findings, [], True

        findings = await self._build_user_findings(user, domain, client)
        return findings, [], False

    async def _fetch_user_detail(
        self, client: httpx.AsyncClient, headers: dict[str, str], url: str
    ) -> tuple[dict[str, Any] | None, str | None, bool]:
        try:
            response = await client.get(url, headers=headers)
        except httpx.TimeoutException:
            return None, "GitHub user detail lookup timed out", False
        except Exception as exc:
            return None, f"GitHub user detail lookup failed: {exc}", False

        if _is_rate_limited(response):
            return None, None, True
        if response.status_code != 200:
            return None, f"GitHub user detail lookup returned {response.status_code}", False
        try:
            return response.json(), None, False
        except Exception:
            return None, "GitHub user detail lookup returned unparseable JSON", False

    async def _build_user_findings(
        self,
        user: dict[str, Any],
        domain: str | None,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        blog = str(user.get("blog") or "").strip()
        bio_text = str(user.get("bio") or "").strip()
        twitter = str(user.get("twitter_username") or "").strip()
        public_email = str(user.get("email") or "").strip()

        findings.append(
            {
                "platform": "github_user",
                "profile_url": str(user.get("html_url") or ""),
                "confidence": "high",
                "source": "github_profile",
                "signal_type": "profile",
                "metadata": {
                    "login": user.get("login"),
                    "name": user.get("name"),
                    "company": str(user.get("company") or "").strip() or None,
                    "blog": blog or None,
                    "location": str(user.get("location") or "").strip() or None,
                    "bio": bio_text or None,
                    "twitter_username": twitter or None,
                    "public_email": public_email or None,
                    "public_repos": int(user.get("public_repos") or 0),
                    "followers": int(user.get("followers") or 0),
                    "avatar_url": user.get("avatar_url"),
                    "created_at": str(user.get("created_at") or ""),
                },
            }
        )

        # Bio PII extraction
        if bio_text:
            bio = analyze_bio(bio_text, exclude_domain=domain)
            for phone in bio.phones:
                findings.append(
                    {
                        "platform": "github_bio",
                        "confidence": "medium",
                        "source": "github_profile",
                        "signal_type": "phone_in_bio",
                        "metadata": {
                            "phone": phone,
                            "source_field": "bio",
                            "source_platform": "github",
                        },
                    }
                )
            for extra_email in bio.emails:
                findings.append(
                    {
                        "platform": "github_bio",
                        "confidence": "high",
                        "source": "github_profile",
                        "signal_type": "email_in_bio",
                        "metadata": {
                            "email": extra_email,
                            "source_field": "bio",
                            "source_platform": "github",
                        },
                    }
                )
            # Aggregator sub-extraction from bio
            for agg_url in bio.aggregator_urls:
                agg_links = await extract_from_aggregator(agg_url, client)
                findings.extend(_aggregator_findings(agg_links, agg_url, "github"))

        # Blog URL — check if it's an aggregator
        if blog and is_aggregator_url(blog):
            agg_links = await extract_from_aggregator(blog, client)
            findings.extend(_aggregator_findings(agg_links, blog, "github"))

        return findings


def _aggregator_findings(
    links: list[Any], agg_url: str, source_platform: str
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for link in links:
        if link.link_type == "phone":
            out.append(
                {
                    "platform": "github_bio",
                    "confidence": "medium",
                    "source": "github_profile",
                    "signal_type": "phone_in_bio",
                    "metadata": {
                        "phone": link.handle,
                        "source_field": "aggregator",
                        "source_url": agg_url,
                        "source_platform": source_platform,
                    },
                }
            )
        elif link.link_type == "whatsapp":
            out.append(
                {
                    "platform": "github_bio",
                    "confidence": "medium",
                    "source": "github_profile",
                    "signal_type": "phone_in_bio",
                    "metadata": {
                        "phone": f"WhatsApp: {link.handle}",
                        "source_field": "aggregator",
                        "source_url": agg_url,
                        "source_platform": source_platform,
                    },
                }
            )
        elif link.link_type == "email":
            out.append(
                {
                    "platform": "github_bio",
                    "confidence": "high",
                    "source": "github_profile",
                    "signal_type": "email_in_bio",
                    "metadata": {
                        "email": link.handle,
                        "source_field": "aggregator",
                        "source_url": agg_url,
                        "source_platform": source_platform,
                    },
                }
            )
        elif link.link_type == "social":
            out.append(
                {
                    "platform": f"github_aggregator_{link.platform}",
                    "url": link.url,
                    "confidence": "high",
                    "source": "github_profile",
                    "signal_type": "aggregator_link",
                    "metadata": {
                        "link_platform": link.platform,
                        "handle": link.handle,
                        "aggregator_url": agg_url,
                    },
                }
            )
    return out


class GitHubDomainCommitsModule(BaseModule):
    """DOMAIN-mode GitHub commit search independent of discovered repos."""

    name = "github_domain_commits"
    description = "Search public GitHub commit history for target-domain authors."
    requires_key = False

    async def run(self, target: str, **_kwargs: Any) -> ModuleResult:  # type: ignore[override]
        domain = (target or "").strip().lower()
        if not domain or "@" in domain or "." not in domain:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["github_domain_commits: invalid domain"], metadata={"skip_reason": "invalid_domain"})
        token = settings.github_token
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        query = f"author-email:@{domain}"
        signal_pool = _kwargs.get("signal_pool")
        candidate_names: list[str] = []
        if signal_pool is not None and hasattr(signal_pool, "get_names_for_domain"):
            try:
                for payload in signal_pool.get_names_for_domain(domain) or []:
                    name = str(payload.get("name") or "").strip() if isinstance(payload, dict) else ""
                    key = name.casefold()
                    if len(name.split()) >= 2 and key not in {item.casefold() for item in candidate_names}:
                        candidate_names.append(name)
                    if len(candidate_names) >= 5:
                        break
            except Exception:
                candidate_names = []
        try:
            async with build_client(base_url=_GITHUB_API, timeout=10.0) as client:
                response = await client.get("/search/commits", params={"q": query, "sort": "author-date", "order": "desc", "per_page": "100"}, headers=headers)
        except httpx.TimeoutException:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub domain commit search timed out"], metadata={"health_category": "timeout", "query": query})
        except Exception as exc:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"GitHub domain commit search failed: {exc}"], metadata={"health_category": "transport_or_provider_failure", "query": query})
        if _is_rate_limited(response):
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub API rate limit reached during domain commit search"], metadata={"health_category": "blocked_or_rate_limited", "query": query, "rate_limited": True})
        if response.status_code in (403, 422) and not token:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub domain commit search requires GITHUB_TOKEN"], metadata={"health_category": "configuration", "query": query, "requires_token": True})
        if response.status_code != 200:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"GitHub domain commit search returned {response.status_code}"], metadata={"health_category": "provider_failure", "query": query, "http_status": response.status_code})
        try:
            items = response.json().get("items") or []
        except Exception:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub domain commit search returned unparseable JSON"], metadata={"health_category": "provider_failure", "query": query})

        queries = [query]
        if not items:
            fallback_query = f"@{domain}"
            try:
                async with build_client(base_url=_GITHUB_API, timeout=10.0) as client:
                    fallback_response = await client.get("/search/commits", params={"q": fallback_query, "sort": "author-date", "order": "desc", "per_page": "100"}, headers=headers)
                if _is_rate_limited(fallback_response):
                    return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub API rate limit reached during domain commit fallback search"], metadata={"health_category": "blocked_or_rate_limited", "queries": [query, fallback_query], "rate_limited": True})
                if fallback_response.status_code == 200:
                    items = fallback_response.json().get("items") or []
                    queries.append(fallback_query)
            except Exception:
                pass

        def has_matching_email(rows: list[Any]) -> bool:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                commit = row.get("commit") if isinstance(row.get("commit"), dict) else {}
                author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
                email = str(author.get("email") or "").strip().lower()
                if email.rsplit("@", 1)[-1] == domain and "@" in email:
                    return True
            return False

        name_queries: list[str] = []
        name_query_errors: list[str] = []
        if candidate_names and not has_matching_email(items):
            try:
                async with build_client(base_url=_GITHUB_API, timeout=10.0) as client:
                    for name in candidate_names:
                        name_query = f'author:"{name}"'
                        name_response = await client.get(
                            "/search/commits",
                            params={"q": name_query, "sort": "author-date", "order": "desc", "per_page": "100"},
                            headers=headers,
                        )
                        name_queries.append(name_query)
                        if _is_rate_limited(name_response):
                            name_query_errors.append(f"GitHub API rate limit reached during name pivot: {name}")
                            break
                        if name_response.status_code != 200:
                            name_query_errors.append(f"GitHub name pivot returned {name_response.status_code}: {name}")
                            continue
                        try:
                            items.extend(name_response.json().get("items") or [])
                        except Exception:
                            name_query_errors.append(f"GitHub name pivot returned unparseable JSON: {name}")
            except httpx.TimeoutException:
                name_query_errors.append("GitHub name pivot search timed out")
            except Exception as exc:
                name_query_errors.append(f"GitHub name pivot search failed: {exc}")

        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
            author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
            email = str(author.get("email") or "").strip().lower()
            if "@" not in email or email.rsplit("@", 1)[-1] != domain or email in seen:
                continue
            seen.add(email)
            repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            breakdown = compute_confidence_breakdown(source_types=["github_commit_author"], is_smtp_verified=False, is_ca_attested=False)
            findings.append({"platform": "github_domain_commit", "profile_url": str(item.get("html_url") or ""), "username": email.split("@", 1)[0], "confidence": label_for_score(breakdown.score).lower(), "metadata": {"email": email, "on_domain": True, "source_type": "github_commit_author", "author_name": str(author.get("name") or ""), "commit_sha": str(item.get("sha") or "")[:7], "commit_date": str(author.get("date") or ""), "repo": str(repository.get("full_name") or ""), "repo_url": str(repository.get("html_url") or ""), "html_url": str(item.get("html_url") or ""), "confidence_score": round(breakdown.score, 4), "confidence_breakdown": breakdown.breakdown}})
        metadata = {"query": query, "queries": queries, "name_queries": name_queries, "names_considered": len(candidate_names), "raw_items": len(items), "accepted_emails": len(findings), "health_category": "ok" if findings else "success_empty"}
        if name_query_errors:
            metadata["name_query_errors"] = name_query_errors
        status = ModuleStatus.PARTIAL if name_query_errors and not findings else ModuleStatus.SUCCESS
        errors = name_query_errors
        return ModuleResult(status=status, findings=findings, errors=errors, metadata=metadata)
