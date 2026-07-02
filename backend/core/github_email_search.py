"""Domain-wide GitHub email discovery for Phase B2 of the 0.10.0 rebuild.

Reuses the existing MailAccess GitHub auth pattern (Bearer token from
``settings.github_token``) and the same ``Accept``/``X-GitHub-Api-Version``
headers as ``backend.modules.github_code_search``.

Two discovery methods:

* :meth:`GitHubEmailSearcher.search_code_mentions` — code search for
  ``"@<domain>"`` plus two narrower queries (env files, READMEs).
  Catches placeholder/config mentions, which are *lower* confidence
  than commit authorship.

* :meth:`GitHubEmailSearcher.search_commit_authors` — the high-value
  addition: once we know a few repos that mention the domain, we
  page their recent commit lists and lift ``commit.author.email``
  + ``commit.committer.email``.  Emails ending in ``@<domain>`` are
  authoritative.

The two are decoupled on purpose.  The orchestrator module wires them
together sequentially so commit-author discovery can use the repo
list produced by code search.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from .email_extraction import extract_emails

_LOG = logging.getLogger(__name__)

# Reused verbatim from backend.modules.github_code_search — keep in sync
# there if it ever changes.
_GITHUB_API = "https://api.github.com"
_GITHUB_HEADERS_BASE: dict[str, str] = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Headers GitHub sets to communicate quota.  See:
#   https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting
_RATE_LIMIT_REMAINING_HEADER = "x-ratelimit-remaining"


@dataclass
class GitHubMatch:
    email: str
    match_type: str  # "code_mention" or "commit_author"
    repo_full_name: str = ""
    file_path: str = ""
    html_url: str = ""
    commit_sha: str = ""
    author_name: str | None = None


@dataclass
class CodeMentionResult:
    matches: list[GitHubMatch] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    rate_limited: bool = False
    error: str | None = None


@dataclass
class CommitAuthorResult:
    matches: list[GitHubMatch] = field(default_factory=list)
    repos_checked: int = 0
    commits_inspected: int = 0
    rate_limited: bool = False
    error: str | None = None


def _build_headers() -> dict[str, str]:
    headers = dict(_GITHUB_HEADERS_BASE)
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return (
        response.status_code == 403
        and response.headers.get(_RATE_LIMIT_REMAINING_HEADER) == "0"
    )


class GitHubEmailSearcher:
    """Async GitHub domain searcher used by the Phase B2 module.

    A single instance is fine per harvest — shares the auth headers
    and rate-limit detection.  Concurrent calls into the same instance
    are guarded by an :class:`asyncio.Lock` so we don't overshoot GitHub's
    10/30 req/min search-endpoint limit when the user is unauthenticated.
    """

    # Reasonable lower bound — keeps tests fast even when tokenless.
    SEARCH_MIN_INTERVAL = 6.0 if not settings.github_token else 2.0

    def __init__(
        self,
        transport: httpx.AsyncClient | None = None,
        min_interval: float | None = None,
    ) -> None:
        self._owns_transport = transport is None
        if transport is None:
            self._client: httpx.AsyncClient = httpx.AsyncClient(
                timeout=10.0,
                headers=_build_headers(),
            )
        else:
            self._client = transport
        self._last_request_at: float = 0.0
        self._lock = asyncio.Lock()
        if min_interval is not None:
            self._min_interval = max(float(min_interval), 0.0)
        else:
            self._min_interval = float(self.SEARCH_MIN_INTERVAL)

    async def aclose(self) -> None:
        if self._owns_transport:
            await self._client.aclose()

    async def __aenter__(self) -> GitHubEmailSearcher:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Code-mention search
    # ------------------------------------------------------------------
    async def search_code_mentions(
        self,
        domain: str,
        max_results: int = 30,
    ) -> CodeMentionResult:
        """Search public GitHub code for ``"@<domain>"`` mentions.

        Returns a :class:`CodeMentionResult` containing the matches and
        the set of unique repo full names found — the orchestrator
        passes those on to :meth:`search_commit_authors`.
        """
        cleaned = (domain or "").strip().lower()
        if not cleaned or "." not in cleaned:
            return CodeMentionResult(error="invalid_domain")

        queries = [
            f'"@{cleaned}"',  # broad
            f'"@{cleaned}" extension:env',  # high-signal env files
            f'"@{cleaned}" extension:md',  # README mentions
        ]

        all_matches: list[GitHubMatch] = []
        repos_seen: dict[str, None] = {}
        rate_limited = False
        first_error: str | None = None

        for query in queries[:_quota_for_queries(len(queries))]:
            outcome = await self._search_code_query(
                query, max_results=max_results, target_domain=cleaned
            )
            if outcome.error:
                if not first_error:
                    first_error = outcome.error
                if outcome.rate_limited:
                    rate_limited = True
                    break
                continue
            if outcome.rate_limited:
                rate_limited = True
                break
            all_matches.extend(outcome.matches)
            for repo in outcome.repos:
                repos_seen.setdefault(repo, None)

        # De-dupe matches on (email, repo, file_path) so the same
        # hit from overlapping queries doesn't double-count.
        deduped_matches = _dedupe_code_matches(all_matches)
        return CodeMentionResult(
            matches=deduped_matches,
            repos=list(repos_seen.keys()),
            rate_limited=rate_limited,
            error=first_error,
        )

    async def _search_code_query(
        self, query: str, max_results: int, target_domain: str = ""
    ) -> CodeMentionResult:
        async with self._lock:
            await self._throttle()
            try:
                response = await self._client.get(
                    f"{_GITHUB_API}/search/code",
                    params={"q": query, "per_page": str(min(int(max_results), 100))},
                )
            except httpx.TimeoutException:
                return CodeMentionResult(error="timeout")
            except Exception as exc:  # pragma: no cover - defensive
                return CodeMentionResult(error=f"request_error:{exc}")

            if _is_rate_limited(response):
                return CodeMentionResult(
                    rate_limited=True,
                    error="github_rate_limit",
                )

            if response.status_code in (403, 422) and not settings.github_token:
                # Code search is authenticated-only since 2021.
                return CodeMentionResult(
                    error="github_code_search_requires_token",
                )

            if response.status_code != 200:
                return CodeMentionResult(error=f"github_code_http_{response.status_code}")

            try:
                payload = response.json()
            except Exception:
                return CodeMentionResult(error="invalid_json")

            matches, repos = _parse_code_search_results(
                payload, max_results=max_results, target_domain=target_domain
            )
            return CodeMentionResult(matches=matches, repos=repos)

    # ------------------------------------------------------------------
    # Commit-author discovery
    # ------------------------------------------------------------------
    async def search_commit_authors(
        self,
        domain: str,
        repos: list[str],
        max_repos: int = 10,
        max_commits_per_repo: int = 20,
    ) -> CommitAuthorResult:
        """For each repo in *repos*, page recent commits and lift emails
        ending in ``@<domain>``.
        """
        cleaned = (domain or "").strip().lower()
        if not cleaned or "." not in cleaned:
            return CommitAuthorResult(error="invalid_domain")

        capped_repos = [r for r in repos if "/" in r][:max_repos]
        if not capped_repos:
            return CommitAuthorResult(error="no_repos")

        domain_lower = "@" + cleaned

        all_matches: list[GitHubMatch] = []
        rate_limited = False
        first_error: str | None = None
        commits_inspected = 0

        for repo in capped_repos:
            commits = await self._fetch_recent_commits(repo, max_commits_per_repo)
            if commits.error and not first_error:
                first_error = commits.error
            if commits.rate_limited:
                rate_limited = True
                break
            commits_inspected += len(commits.items)
            for item in commits.items:
                if not isinstance(item, dict):
                    continue
                sha = str(item.get("sha") or "")
                html_url = str(item.get("html_url") or "")
                repo_full = str((item.get("repository") or {}).get("full_name") or repo)
                commit_obj = (
                    item.get("commit")
                    if isinstance(item.get("commit"), dict)
                    else {}
                )
                author_obj = (
                    commit_obj.get("author")
                    if isinstance(commit_obj.get("author"), dict)
                    else {}
                )
                committer_obj = (
                    commit_obj.get("committer")
                    if isinstance(commit_obj.get("committer"), dict)
                    else {}
                )
                author_name = str(author_obj.get("name") or "")

                candidate_emails: list[str] = []
                for who in (author_obj, committer_obj):
                    raw_email = who.get("email") if isinstance(who, dict) else None
                    if isinstance(raw_email, str) and raw_email:
                        candidate_emails.append(raw_email)

                for raw in candidate_emails:
                    if raw.lower().endswith(domain_lower):
                        all_matches.append(
                            GitHubMatch(
                                email=raw.lower(),
                                match_type="commit_author",
                                repo_full_name=repo_full,
                                commit_sha=sha,
                                html_url=html_url,
                                author_name=author_name or None,
                            )
                        )

        return CommitAuthorResult(
            matches=_dedupe_commit_matches(all_matches),
            repos_checked=len(capped_repos),
            commits_inspected=commits_inspected,
            rate_limited=rate_limited,
            error=first_error,
        )

    async def _fetch_recent_commits(
        self, repo_full_name: str, per_page: int
    ) -> _RecentCommitsOutcome:
        async with self._lock:
            await self._throttle()
            try:
                response = await self._client.get(
                    f"{_GITHUB_API}/repos/{repo_full_name}/commits",
                    params={"per_page": str(min(int(per_page), 100))},
                )
            except httpx.TimeoutException:
                return _RecentCommitsOutcome(error="timeout")
            except Exception as exc:  # pragma: no cover - defensive
                return _RecentCommitsOutcome(error=f"request_error:{exc}")

            if _is_rate_limited(response):
                return _RecentCommitsOutcome(rate_limited=True, error="github_rate_limit")
            if response.status_code == 404:
                # private repo or deleted — treat as empty
                return _RecentCommitsOutcome(items=[])
            if response.status_code != 200:
                return _RecentCommitsOutcome(error=f"github_commits_http_{response.status_code}")

            try:
                payload = response.json()
            except Exception:
                return _RecentCommitsOutcome(error="invalid_json")

            items = payload if isinstance(payload, list) else []
            return _RecentCommitsOutcome(items=items)

    async def _throttle(self) -> None:
        interval = getattr(self, "_min_interval", self.SEARCH_MIN_INTERVAL)
        if interval <= 0:
            return
        import time as _time

        elapsed = _time.monotonic() - self._last_request_at
        wait = interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at = _time.monotonic()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _quota_for_queries(total: int) -> int:
    """Reduce query count when unauthenticated to respect 10 req/min."""
    limit = 10 if not settings.github_token else 30
    return max(1, min(total, limit))


def _parse_code_search_results(
    payload: Any, max_results: int, target_domain: str = ""
) -> tuple[list[GitHubMatch], list[str]]:
    if not isinstance(payload, dict):
        return [], []
    raw_items = payload.get("items") or []
    if not isinstance(raw_items, list):
        return [], []

    matches: list[GitHubMatch] = []
    repos: list[str] = []
    repos_seen: set[str] = set()

    for raw in raw_items[:max_results]:
        if not isinstance(raw, dict):
            continue
        repo = (raw.get("repository") or {})
        repo_full = str(repo.get("full_name") or "")
        file_path = str(raw.get("path") or "")
        html_url = str(raw.get("html_url") or "")

        if repo_full and repo_full not in repos_seen:
            repos_seen.add(repo_full)
            repos.append(repo_full)

        # Use GitHub's API-provided text fragments when present
        # (``text_matches``).  Fall back to scanning the file path if
        # we don't get snippets — the snippet keys rarely carry the
        # literal ``@<domain>`` string GitHub already matched on,
        # so this is best-effort only.
        snippet_blob = ""
        text_matches = raw.get("text_matches")
        if isinstance(text_matches, list):
            for tm in text_matches:
                if not isinstance(tm, dict):
                    continue
                snippet_blob += " " + str(tm.get("fragment") or "")

        # Always also scan the file_path — useful for monorepos where
        # the path encodes the email (e.g. ``config/devops@team.io.yaml``).
        combined = (snippet_blob + "\n" + file_path).strip()

        # W6 MUST-FIX: pass target_domain so extract_emails filters at
        # extraction time. Without this, any email-shaped token in the
        # snippet / file_path text would leak through — including
        # placeholder emails like ``billing@example.com`` that often
        # appear in README files, env examples, and test fixtures in
        # repos whose content merely mentions the target domain.
        cleaned_target = (target_domain or "").strip().lower()
        for extracted in extract_emails(combined, target_domain=cleaned_target):
            matches.append(
                GitHubMatch(
                    email=extracted.email,
                    match_type="code_mention",
                    repo_full_name=repo_full,
                    file_path=file_path,
                    html_url=html_url,
                )
            )

    return matches, repos


def _dedupe_code_matches(matches: list[GitHubMatch]) -> list[GitHubMatch]:
    seen: dict[tuple[str, str, str], None] = {}
    out: list[GitHubMatch] = []
    for m in matches:
        key = (m.email, m.repo_full_name, m.file_path)
        if key in seen:
            continue
        seen[key] = None
        out.append(m)
    return out


def _dedupe_commit_matches(matches: list[GitHubMatch]) -> list[GitHubMatch]:
    """Same email from many commits collapses; keep one with most detail."""
    best: dict[str, GitHubMatch] = {}
    for m in matches:
        existing = best.get(m.email)
        if existing is None or len(m.author_name or "") > len(existing.author_name or ""):
            best[m.email] = m
    return list(best.values())


@dataclass
class _RecentCommitsOutcome:
    items: list[Any] = field(default_factory=list)
    error: str | None = None
    rate_limited: bool = False
