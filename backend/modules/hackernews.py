from __future__ import annotations

import re
from datetime import datetime, timezone
from html import unescape
from typing import Any

import httpx

from ..core.bio_analyzer import analyze_bio
from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_HN_FIREBASE = "https://hacker-news.firebaseio.com/v0"
_HN_ALGOLIA = "https://hn.algolia.com/api/v1"
_NAME_PATTERNS = [
    re.compile(r"\bI(?:'m| am)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"),
    re.compile(r"\bMy name is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"),
    re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s+here\b"),
    re.compile(r"^\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s*,\s+[A-Za-z]"),
]
_SOCIAL_URL_RE = re.compile(r"https?://(?:www\.)?(?:linkedin\.com|github\.com|twitter\.com|x\.com)/[^\s<>\"]+")


class HackerNewsModule(BaseModule):
    name = "hackernews"
    description = "Check Hacker News profiles derived from email username candidates."
    requires_key = False
    default_enabled = True

    async def run(self, email: str) -> ModuleResult:
        rate_limiter.set_delay("hacker-news.firebaseio.com", 1.0)
        rate_limiter.set_delay("hn.algolia.com", 1.0)

        candidates = _username_candidates(email)[:3]
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        seen: set[str] = set()

        async with build_client(timeout=8.0, follow_redirects=True) as client:
            for username in candidates:
                found, found_errors = await self._lookup_user(client, username)
                errors.extend(found_errors)
                for finding in found:
                    found_username = str((finding.get("metadata") or {}).get("username") or "")
                    if found_username and found_username not in seen:
                        seen.add(found_username)
                        findings.append(finding)

        return ModuleResult(
            status=ModuleStatus.PARTIAL if errors and not findings else ModuleStatus.SUCCESS if not errors else ModuleStatus.PARTIAL,
            findings=findings,
            metadata={"usernames_checked": candidates, "profiles_found": len(findings)},
            errors=errors,
        )

    async def _lookup_user(
        self, client: httpx.AsyncClient, username: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        data: dict[str, Any] | None = None
        try:
            response = await client.get(f"{_HN_FIREBASE}/user/{username}.json")
            if response.status_code == 200:
                payload = response.json()
                if isinstance(payload, dict):
                    data = payload
            elif response.status_code != 404:
                errors.append(f"HackerNews Firebase returned HTTP {response.status_code} for {username}")
        except httpx.TimeoutException:
            errors.append(f"HackerNews Firebase timed out for {username}")
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            return [], [f"HackerNews network error for {username}: {exc}"]
        except Exception as exc:
            errors.append(f"HackerNews Firebase error for {username}: {exc}")

        if data is None:
            fallback, fallback_errors = await self._lookup_algolia(client, username)
            errors.extend(fallback_errors)
            data = fallback

        if not data:
            return [], errors

        about = unescape(str(data.get("about") or "")).strip()
        created = data.get("created") or data.get("created_at")
        linked_urls = _linked_urls(about)
        bio = analyze_bio(about)
        for url in bio.urls:
            if url not in linked_urls:
                linked_urls.append(url)

        finding = {
            "platform": "hackernews_profile",
            "profile_url": f"https://news.ycombinator.com/user?id={username}",
            "confidence": "medium",
            "metadata": {
                "username": str(data.get("id") or data.get("username") or username),
                "about": _truncate(about, 500),
                "karma": int(data.get("karma") or 0),
                "member_since": _member_since(created),
                "extracted_name": _extract_name(about),
                "linked_urls": linked_urls,
                "submitted": (data.get("submitted") or [])[:5] if isinstance(data.get("submitted"), list) else [],
            },
        }
        return [finding], errors

    async def _lookup_algolia(
        self, client: httpx.AsyncClient, username: str
    ) -> tuple[dict[str, Any] | None, list[str]]:
        try:
            response = await client.get(f"{_HN_ALGOLIA}/users/{username}")
        except httpx.TimeoutException:
            return None, [f"HackerNews Algolia timed out for {username}"]
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            return None, [f"HackerNews Algolia network error for {username}: {exc}"]
        except Exception as exc:
            return None, [f"HackerNews Algolia error for {username}: {exc}"]
        if response.status_code in (404, 200) and response.text.strip() in ("null", ""):
            return None, []
        if response.status_code != 200:
            return None, [f"HackerNews Algolia returned HTTP {response.status_code} for {username}"]
        payload = response.json()
        return payload if isinstance(payload, dict) else None, []


def _username_candidates(email: str) -> list[str]:
    local = email.split("@", 1)[0].lower()
    collapsed = re.sub(r"[^a-z0-9]", "", local)
    parts = [p for p in re.split(r"[^a-z0-9]+", local) if p]
    candidates = [collapsed]
    if parts:
        candidates.append(parts[0])
    if len(parts) >= 2:
        candidates.append(f"{parts[0][0]}{parts[-1]}")
        candidates.append("_".join(parts[:2]))
    out: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _extract_name(about: str) -> str | None:
    text = re.sub(r"<[^>]+>", " ", unescape(about or ""))
    text = " ".join(text.split())
    for pattern in _NAME_PATTERNS:
        match = pattern.search(text)
        if match:
            value = match.group(1).strip()
            if len(value.split()) >= 2 and not any(char.isdigit() for char in value):
                return value
    return None


def _linked_urls(about: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in _SOCIAL_URL_RE.finditer(about or ""):
        url = match.group(0).rstrip(".,)")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _member_since(value: Any) -> str:
    if isinstance(value, int):
        return datetime.fromtimestamp(value, tz=timezone.utc).date().isoformat()
    if isinstance(value, str):
        return value
    return ""


def _truncate(value: str, limit: int) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."
