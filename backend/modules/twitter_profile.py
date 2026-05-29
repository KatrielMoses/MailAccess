from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from ..core.bio_analyzer import analyze_bio
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_TWITTER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_TWITTER_PLATFORM_NAMES = frozenset({
    "twitter",
    "x",
    "twitter archived",
    "twitter - archived",
    "x (twitter)",
    "twitter (archived)",
})


def _find_twitter_username(collected: dict[str, Any]) -> str | None:
    for module_name in ("whatsmyname", "username_pivot"):
        result = collected.get(module_name)
        if not result or not hasattr(result, "findings"):
            continue
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            platform = str(finding.get("platform") or "").lower().strip()
            if platform not in _TWITTER_PLATFORM_NAMES:
                continue
            confidence = str(finding.get("confidence") or "").lower()
            if confidence != "high":
                continue
            meta = finding.get("metadata") or {}
            username = str(
                finding.get("username")
                or meta.get("matched_username")
                or ""
            ).strip().lstrip("@")
            if username:
                return username
    return None


class TwitterProfileModule(BaseModule):
    name = "twitter_profile"
    description = "Extract public Twitter/X profile data for confirmed usernames."
    requires_key = False

    async def run(
        self, email: str, collected: dict[str, Any] | None = None
    ) -> ModuleResult:
        if collected is None:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Runs in post-primary phase only"],
            )

        username = _find_twitter_username(collected)
        if not username:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No confirmed Twitter/X username found"],
            )

        await asyncio.sleep(2.0)

        profile_url = f"https://twitter.com/{username}"
        headers = {
            "User-Agent": _TWITTER_UA,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        try:
            async with build_client(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(profile_url, headers=headers)
        except httpx.TimeoutException:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[_existence_finding(username, profile_url)],
                errors=["Twitter/X request timed out"],
            )
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[_existence_finding(username, profile_url)],
                errors=[str(exc)],
            )

        if resp.status_code in (401, 403, 429):
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[_existence_finding(username, profile_url)],
                errors=[
                    f"Twitter/X blocked the request (HTTP {resp.status_code}) — "
                    "profile data unavailable without authentication"
                ],
            )

        if resp.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[_existence_finding(username, profile_url)],
                errors=[f"Twitter/X HTTP {resp.status_code}"],
            )

        profile_data = _parse_twitter_html(resp.text, username)
        confidence = "high" if profile_data else "low"

        finding: dict[str, Any] = {
            "platform": "twitter_profile",
            "profile_url": profile_url,
            "username": username,
            "confidence": confidence,
            "source": "twitter_profile",
            "metadata": {"username": username, **profile_data},
        }

        extra_findings: list[dict[str, Any]] = []
        bio_text = str(profile_data.get("bio") or "")
        if bio_text:
            domain = email.split("@", 1)[1] if "@" in email else None
            analysis = analyze_bio(bio_text, exclude_domain=domain)
            for phone in analysis.phones:
                extra_findings.append({
                    "platform": "twitter_profile",
                    "signal_type": "phone_in_bio",
                    "confidence": "medium",
                    "source": "twitter_profile",
                    "metadata": {
                        "phone": phone,
                        "source_field": "bio",
                        "source_platform": "twitter_profile",
                    },
                })
            for addr in analysis.emails:
                extra_findings.append({
                    "platform": "twitter_profile",
                    "signal_type": "email_in_bio",
                    "confidence": "medium",
                    "source": "twitter_profile",
                    "metadata": {
                        "email": addr,
                        "source_field": "bio",
                        "source_platform": "twitter_profile",
                    },
                })
            if analysis.aggregator_urls:
                finding["metadata"]["aggregator_urls"] = analysis.aggregator_urls

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[finding] + extra_findings,
        )


def _existence_finding(username: str, profile_url: str) -> dict[str, Any]:
    return {
        "platform": "twitter_profile",
        "profile_url": profile_url,
        "username": username,
        "confidence": "low",
        "source": "twitter_profile",
        "metadata": {
            "username": username,
            "extraction_method": "existence_only",
            "note": (
                "Twitter/X blocked the request — profile data "
                "unavailable without authentication"
            ),
        },
    }


def _parse_twitter_html(html: str, username: str) -> dict[str, Any]:
    # Try __NEXT_DATA__ first (most structured)
    nd_match = re.search(
        r'<script id="__NEXT_DATA__"[^>]*>(\{.*?\})</script>',
        html,
        re.DOTALL,
    )
    if nd_match:
        try:
            nd = json.loads(nd_match.group(1))
            result = _extract_from_next_data(nd, username)
            if result:
                return result
        except Exception:
            pass

    # Try JSON-LD
    for m in re.finditer(
        r'<script type="application/ld\+json"[^>]*>(.*?)</script>',
        html,
        re.DOTALL | re.IGNORECASE,
    ):
        try:
            ld = json.loads(m.group(1))
            result = _extract_from_jsonld(ld)
            if result:
                return result
        except Exception:
            pass

    # Fall back to Open Graph / Twitter meta tags
    return _extract_from_meta(html)


def _extract_from_next_data(data: Any, username: str, _depth: int = 0) -> dict[str, Any]:
    if _depth > 12 or not isinstance(data, (dict, list)):
        return {}
    if isinstance(data, list):
        for item in data:
            r = _extract_from_next_data(item, username, _depth + 1)
            if r:
                return r
        return {}
    # Check if this node looks like a Twitter user object
    screen = str(
        data.get("screen_name")
        or data.get("legacy", {}).get("screen_name", "")
    ).lower()
    if screen == username.lower():
        legacy = data.get("legacy") if isinstance(data.get("legacy"), dict) else data
        return {
            "display_name": str(legacy.get("name") or ""),
            "bio": str(legacy.get("description") or ""),
            "location": str(legacy.get("location") or ""),
            "website": str(legacy.get("url") or ""),
            "followers_count": legacy.get("followers_count"),
            "following_count": legacy.get("friends_count"),
            "tweet_count": legacy.get("statuses_count"),
            "verified": bool(
                legacy.get("verified") or legacy.get("is_blue_verified")
            ),
            "profile_image_url": str(
                legacy.get("profile_image_url_https") or ""
            ),
            "join_date": str(legacy.get("created_at") or ""),
        }
    for val in data.values():
        r = _extract_from_next_data(val, username, _depth + 1)
        if r:
            return r
    return {}


def _extract_from_jsonld(data: Any) -> dict[str, Any]:
    if isinstance(data, list):
        for item in data:
            r = _extract_from_jsonld(item)
            if r:
                return r
        return {}
    if not isinstance(data, dict):
        return {}
    if data.get("@type") in ("Person", "ProfilePage"):
        result: dict[str, Any] = {}
        name = str(data.get("name") or "").strip()
        if name:
            result["display_name"] = name
        desc = str(data.get("description") or "").strip()
        if desc:
            result["bio"] = desc
        return result
    return {}


def _extract_from_meta(html: str) -> dict[str, Any]:
    og: dict[str, str] = {}
    for m in re.finditer(
        r'<meta\s+(?:property|name)="([^"]+)"\s+content="([^"]*)"',
        html,
        re.IGNORECASE,
    ):
        og[m.group(1)] = m.group(2)
    for m in re.finditer(
        r'<meta\s+content="([^"]*)"\s+(?:property|name)="([^"]+)"',
        html,
        re.IGNORECASE,
    ):
        og[m.group(2)] = m.group(1)

    result: dict[str, Any] = {}
    title = str(og.get("og:title") or og.get("twitter:title") or "").strip()
    if title:
        result["display_name"] = title
    desc = str(
        og.get("og:description") or og.get("twitter:description") or ""
    ).strip()
    if desc:
        result["bio"] = desc
    image = str(og.get("og:image") or og.get("twitter:image") or "").strip()
    if image:
        result["profile_image_url"] = image
    return result
