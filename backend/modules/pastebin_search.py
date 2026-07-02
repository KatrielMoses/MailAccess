from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import APP_VERSION, settings
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_NOISE_EMAIL_LOCAL = frozenset({"noreply"})
_NOISE_EMAIL_DOMAINS = frozenset({"pastebin.com", "paste.ee"})

_ASSOCIATE_EMAIL_CAP = 10

_USER_AGENT = f"mailaccess/{APP_VERSION}"


def _is_noise_email(addr: str, target: str) -> bool:
    addr = addr.lower()
    if addr == target.lower():
        return True
    local, _, domain = addr.partition("@")
    if local in _NOISE_EMAIL_LOCAL:
        return True
    if domain in _NOISE_EMAIL_DOMAINS:
        return True
    return False


def _derive_platform(url: str, paste_id: str) -> tuple[str, str]:
    """Return (platform_key, source_site) derived from the paste URL host."""
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
    except Exception:
        host = ""

    if host == "pastebin.com":
        return f"pastebin:{paste_id}", "pastebin"
    if host == "paste.ee":
        return f"paste.ee:{paste_id}", "paste.ee"
    return f"paste:{paste_id}", "other"


class PastebinSearchModule(BaseModule):
    name = "pastebin_search"
    description = (
        "Search public paste sites (Pastebin, paste.ee, etc.) via psbdmp.ws for the target email."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_pastebin_search or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "pastebin_search disabled — set ENABLE_PASTEBIN_SEARCH=true to enable"
                ],
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://psbdmp.ws/api/v3/search/{email}",
                    headers={"User-Agent": _USER_AGENT},
                )
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"psbdmp request failed: {exc}"],
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        if resp.status_code == 204:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        if resp.status_code == 422:
            logger.warning("psbdmp: 422 Unprocessable Entity for %s", email)
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["psbdmp: invalid query (422)"],
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        if resp.status_code == 429:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["psbdmp: rate limited (429)"],
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        if resp.status_code >= 500:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"psbdmp: server error HTTP {resp.status_code}"],
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        if resp.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"psbdmp: unexpected HTTP {resp.status_code}"],
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        try:
            data = resp.json()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"psbdmp: invalid JSON: {exc}"],
                metadata={"pastes_found": 0, "source_sites": [], "anonymous_pastes": 0},
            )

        findings: list[dict[str, Any]] = []
        associate_emails: list[str] = []
        associate_usernames: list[str] = []
        source_sites_seen: set[str] = set()
        anonymous_pastes = 0

        for item in data.get("data") or []:
            paste_id = item.get("id", "")
            title = item.get("title", "")
            author = item.get("author") or ""
            date = item.get("date", "")
            tags = item.get("tags") or []
            url = item.get("url", "")
            content = item.get("content") or ""

            platform_key, source_site = _derive_platform(url, paste_id)
            source_sites_seen.add(source_site)

            username = author if author and author.lower() != "anonymous" else None
            if username is None:
                anonymous_pastes += 1

            logger.debug("psbdmp hit: %s title=%r", url, title)

            findings.append({
                "platform": platform_key,
                "profile_url": url,
                "username": username,
                "confidence": "medium",
                "metadata": {
                    "source": "psbdmp",
                    "title": title,
                    "tags": list(tags) if isinstance(tags, list | tuple) else [],
                    "date": date,
                    "content_snippet": content[:200],
                    "source_site": source_site,
                },
            })

            for m in _EMAIL_RE.finditer(content):
                addr = m.group(0).lower()
                if (
                    not _is_noise_email(addr, email)
                    and addr not in associate_emails
                    and len(associate_emails) < _ASSOCIATE_EMAIL_CAP
                ):
                    associate_emails.append(addr)

            if username and username not in associate_usernames:
                associate_usernames.append(username)

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "pastes_found": len(findings),
                "source_sites": sorted(source_sites_seen),
                "anonymous_pastes": anonymous_pastes,
                "associate_emails": associate_emails,
                "associate_usernames": associate_usernames,
            },
        )
