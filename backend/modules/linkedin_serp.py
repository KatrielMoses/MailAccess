from __future__ import annotations

import re
import urllib.parse
from typing import Any

import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_DDG_HTML_URL = "https://html.duckduckgo.com/html/"
_LINKEDIN_RE = re.compile(r'https?://(?:www\.)?linkedin\.com/in/([\w\-]+)/?')

_FREE_PROVIDERS = frozenset({
    "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "hotmail.co.uk",
    "outlook.com", "live.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "protonmail.com", "proton.me", "pm.me", "tutanota.com", "tuta.io",
    "gmx.com", "gmx.net", "yandex.com", "yandex.ru", "mail.com",
    "fastmail.com", "fastmail.fm", "zoho.com", "mailinator.com",
})

_DDG_UA = (
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
)


def _find_confirmed_name(
    collected: dict[str, Any],
) -> tuple[str | None, str]:
    """Return (name, source_label) for the highest-confidence confirmed name."""
    # GitHub profile — highest confidence (tied to email via commit authorship)
    github = collected.get("github_commits")
    if github and hasattr(github, "findings"):
        for f in github.findings:
            if not isinstance(f, dict) or f.get("platform") != "github_user":
                continue
            name = str((f.get("metadata") or {}).get("name") or "").strip()
            if name and "@" not in name and len(name) >= 3:
                return name, "github_user"

    # Gravatar
    gravatar = collected.get("gravatar")
    if gravatar and hasattr(gravatar, "findings"):
        for f in gravatar.findings:
            if not isinstance(f, dict) or f.get("platform") != "gravatar_profile":
                continue
            meta = f.get("metadata") or {}
            name = str(
                meta.get("name") or meta.get("display_name") or ""
            ).strip()
            if name and "@" not in name and len(name) >= 3:
                return name, "gravatar_profile"

    # Keybase
    keybase = collected.get("keybase")
    if keybase and hasattr(keybase, "findings"):
        for f in keybase.findings:
            if not isinstance(f, dict) or f.get("platform") != "keybase_profile":
                continue
            name = str((f.get("metadata") or {}).get("name") or "").strip()
            if name and "@" not in name and len(name) >= 3:
                return name, "keybase_profile"

    return None, ""


def _count_name_sources(collected: dict[str, Any]) -> int:
    """Count how many independent sources have a confirmed real name."""
    count = 0
    for module_name, platform_key in (
        ("github_commits", "github_user"),
        ("gravatar", "gravatar_profile"),
        ("keybase", "keybase_profile"),
    ):
        result = collected.get(module_name)
        if not result or not hasattr(result, "findings"):
            continue
        for f in result.findings:
            if not isinstance(f, dict) or f.get("platform") != platform_key:
                continue
            meta = f.get("metadata") or {}
            name = str(
                meta.get("name") or meta.get("display_name") or ""
            ).strip()
            if name and "@" not in name and len(name) >= 3:
                count += 1
                break
    return count


class LinkedInSerpModule(BaseModule):
    name = "linkedin_serp"
    description = "Search LinkedIn via DuckDuckGo/SerpAPI using a confirmed real name."
    requires_key = False

    async def run(
        self, email: str, collected: dict[str, Any] | None = None
    ) -> ModuleResult:
        if collected is None:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Runs in post-primary phase only"],
            )

        name, name_source = _find_confirmed_name(collected)
        if not name:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "LinkedIn search requires confirmed name from other sources first"
                ],
            )

        domain = email.split("@", 1)[1].lower() if "@" in email else ""
        name_sources = _count_name_sources(collected)

        if domain in _FREE_PROVIDERS and name_sources < 2:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "LinkedIn search skipped: free email provider and name "
                    "confirmed from fewer than 2 independent sources"
                ],
            )

        if settings.serpapi_key:
            return await self._serpapi_search(name, name_source, email)
        return await self._ddg_search(name, name_source)

    async def _ddg_search(self, name: str, name_source: str) -> ModuleResult:
        query = f'site:linkedin.com/in/ "{name}"'
        try:
            async with build_client(timeout=12.0, follow_redirects=True) as client:
                resp = await client.get(
                    _DDG_HTML_URL,
                    params={"q": query},
                    headers={"User-Agent": _DDG_UA},
                )
        except httpx.TimeoutException:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["DuckDuckGo request timed out"],
            )
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"DuckDuckGo request error: {exc}"],
            )

        if resp.status_code in (403, 429):
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[
                    f"DuckDuckGo CAPTCHA/block (HTTP {resp.status_code})"
                ],
            )
        if resp.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"DuckDuckGo HTTP {resp.status_code}"],
            )

        return _parse_ddg_html(resp.text, name, query, name_source)

    async def _serpapi_search(
        self, name: str, name_source: str, email: str
    ) -> ModuleResult:
        query = f'site:linkedin.com/in/ "{name}"'
        try:
            async with build_client(timeout=15.0) as client:
                resp = await client.get(
                    "https://serpapi.com/search",
                    params={
                        "q": query,
                        "api_key": settings.serpapi_key,
                        "num": 3,
                    },
                )
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"SerpAPI request error: {exc}"],
            )

        if resp.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"SerpAPI HTTP {resp.status_code}"],
            )

        try:
            data = resp.json()
        except Exception:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["SerpAPI returned unparseable JSON"],
            )

        for result in (data.get("organic_results") or [])[:3]:
            if not isinstance(result, dict):
                continue
            link = str(result.get("link") or "")
            m = _LINKEDIN_RE.search(link)
            if not m:
                continue
            slug = m.group(1)
            title = str(result.get("title") or "").strip()
            snippet = str(result.get("snippet") or "").strip()
            parsed = _parse_linkedin_snippet(title, snippet, name)
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[
                    _make_finding(slug, parsed, snippet, query, "serpapi")
                ],
            )

        return ModuleResult(status=ModuleStatus.SUCCESS, findings=[])


def _parse_ddg_html(
    html: str, name: str, query: str, name_source: str
) -> ModuleResult:
    # DDG HTML results: look for LinkedIn URLs in anchor hrefs
    # Pattern 1: direct LinkedIn href
    for m in re.finditer(
        r'<a[^>]+href="([^"]*linkedin\.com/in/[^"]*)"[^>]*>(.*?)</a>',
        html,
        re.DOTALL | re.IGNORECASE,
    ):
        slug = _extract_slug(m.group(1))
        if not slug:
            continue
        title_raw = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        snippet = _extract_nearby_snippet(html, slug)
        parsed = _parse_linkedin_snippet(title_raw, snippet, name)
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[_make_finding(slug, parsed, snippet, query, "duckduckgo")],
        )

    # Pattern 2: DDG redirect link containing uddg= param
    for m in re.finditer(
        r'href="([^"]*uddg=[^"]*linkedin\.com[^"]*)"[^>]*>(.*?)</a>',
        html,
        re.DOTALL | re.IGNORECASE,
    ):
        try:
            decoded = urllib.parse.unquote(
                re.search(r"uddg=([^&\"]+)", m.group(1)).group(1)
            )
        except Exception:
            continue
        lm = _LINKEDIN_RE.search(decoded)
        if not lm:
            continue
        slug = lm.group(1)
        title_raw = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        snippet = _extract_nearby_snippet(html, slug)
        parsed = _parse_linkedin_snippet(title_raw, snippet, name)
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[_make_finding(slug, parsed, snippet, query, "duckduckgo")],
        )

    return ModuleResult(status=ModuleStatus.SUCCESS, findings=[])


def _extract_slug(href: str) -> str | None:
    # Decode DDG redirect if present
    if "uddg=" in href:
        try:
            href = urllib.parse.unquote(
                re.search(r"uddg=([^&\"]+)", href).group(1)
            )
        except Exception:
            return None
    m = _LINKEDIN_RE.search(href)
    return m.group(1) if m else None


def _extract_nearby_snippet(html: str, slug: str) -> str:
    """Find snippet text near the LinkedIn slug in the HTML."""
    pattern = re.compile(
        rf'{re.escape(slug)}.{{0,500}}?class="result__snippet"[^>]*>(.*?)</(?:a|span|div)>',
        re.DOTALL | re.IGNORECASE,
    )
    m = pattern.search(html)
    if m:
        return re.sub(r"<[^>]+>", "", m.group(1)).strip()

    # Fallback: find snippet class anywhere near slug
    idx = html.find(slug)
    if idx == -1:
        return ""
    window = html[max(0, idx - 100): idx + 800]
    sm = re.search(
        r'class="result__snippet[^"]*"[^>]*>(.*?)</(?:a|span|div)>',
        window,
        re.DOTALL | re.IGNORECASE,
    )
    if sm:
        return re.sub(r"<[^>]+>", "", sm.group(1)).strip()
    return ""


def _parse_linkedin_snippet(
    title: str, snippet: str, search_name: str
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "display_name": "",
        "headline": "",
        "employer": "",
        "location": "",
    }

    if title:
        # Typical: "John Doe - Software Engineer at Acme | LinkedIn"
        name_part = re.split(r"\s*[|·—\-]\s*", title)[0].strip()
        # Strip trailing "LinkedIn"
        name_part = re.sub(r"\s*[-|]\s*LinkedIn\s*$", "", name_part, flags=re.IGNORECASE)
        result["display_name"] = name_part or search_name

    if snippet:
        # "Software Engineer at Acme · London, England"
        at_m = re.search(
            r"^(.+?)\s+at\s+([^\n·•|]+)", snippet, re.IGNORECASE
        )
        if at_m:
            result["headline"] = at_m.group(1).strip()
            employer_rest = at_m.group(2)
            loc_m = re.search(r"[·•|]\s*(.+)", employer_rest)
            if loc_m:
                result["employer"] = employer_rest[: loc_m.start()].strip()
                result["location"] = loc_m.group(1).strip()
            else:
                result["employer"] = employer_rest.strip()
        else:
            first_line = snippet.split("\n")[0].strip()
            if first_line:
                result["headline"] = first_line

    return result


def _make_finding(
    slug: str,
    parsed: dict[str, Any],
    snippet: str,
    query: str,
    method: str,
) -> dict[str, Any]:
    return {
        "platform": "linkedin_snippet",
        "profile_url": f"https://www.linkedin.com/in/{slug}",
        "confidence": "medium",
        "source": "linkedin_serp",
        "metadata": {
            **parsed,
            "linkedin_url": f"https://www.linkedin.com/in/{slug}",
            "snippet_text": snippet,
            "search_query": query,
            "extraction_method": "serp_snippet",
            "search_engine": method,
            "note": (
                "Name/title/employer from search snippet. "
                "Phone/email not accessible without LinkedIn login."
            ),
        },
    }
