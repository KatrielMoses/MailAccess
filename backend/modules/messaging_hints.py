from __future__ import annotations

import asyncio
import re
from html import unescape
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_MAX_TELEGRAM_CHECKS = 3
_DISPLAY_KEYS = frozenset({"display_name", "name", "full_name", "real_name"})
_USERNAME_KEYS = frozenset({"username", "login", "user", "handle"})

# Generic Telegram landing-page titles that come back when {username} doesn't
# resolve to a real channel/user. Lowercased for case-insensitive comparison.
_TELEGRAM_GENERIC_TITLES = frozenset(
    {
        "telegram",
        "telegram messenger",
        "a new era of messaging",
        "telegram – a new era of messaging",
        "telegram - a new era of messaging",
        "join group chat on telegram",
        "telegram group",
        "telegram channel",
    }
)


def _slug_variants(display_name: str) -> list[str]:
    s = display_name.strip().lower()
    if not s or "@" in s:
        return []
    variants = [
        re.sub(r"\s+", "_", s),
        re.sub(r"\s+", "", s),
        re.sub(r"\s+", ".", s),
    ]
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        v = re.sub(r"[^a-z0-9._]", "", v)
        if 3 <= len(v) <= 32 and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _collect_usernames(email: str, phone_hints: list[str] | None = None) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        u = value.strip().lower().lstrip("@")
        if not u or "@" in u or len(u) < 3 or len(u) > 32:
            return
        if u not in seen:
            seen.add(u)
            candidates.append(u)

    if "@" in email:
        _add(email.split("@", 1)[0])

    return candidates[:_MAX_TELEGRAM_CHECKS]


async def _check_telegram_username(client: Any, username: str) -> dict[str, Any] | None:
    url = f"https://t.me/{username}"
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code != 200:
            return None
        body = resp.text
        if "tgme_page_title" not in body:
            return None

        display_name = ""
        photo_url = ""
        title_m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
        if title_m:
            display_name = unescape(title_m.group(1))
        img_m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
        if img_m:
            photo_url = unescape(img_m.group(1))

        og_url = ""
        url_m = re.search(r'property="og:url"\s+content="([^"]+)"', body)
        if url_m:
            og_url = unescape(url_m.group(1))

        page_title = ""
        page_title_m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        if page_title_m:
            page_title = unescape(page_title_m.group(1)).strip()

        # t.me/{username} returns Telegram's own homepage meta tags when the
        # username does not exist. Reject any response whose title is generic
        # branding or does not mention the username we asked about.
        u_lower = username.lower()
        title_lower = display_name.lower().strip()
        page_lower = page_title.lower()

        if title_lower in _TELEGRAM_GENERIC_TITLES or page_lower in _TELEGRAM_GENERIC_TITLES:
            return None

        if "join" in title_lower or "group chat" in title_lower:
            return None

        if og_url and og_url != url:
            return None

        if u_lower not in title_lower:
            return None

        return {
            "platform": "telegram",
            "profile_url": url,
            "metadata": {
                "username": username,
                "display_name": display_name,
                "photo_url": photo_url,
                "check_type": "username",
                "experimental": True,
            },
            "confidence": "low",
        }
    except Exception:
        return None


async def _check_whatsapp_phone(client: Any, phone: str) -> dict[str, Any] | None:
    digits = re.sub(r"\D", "", phone)
    if not digits:
        return None
    url = f"https://wa.me/{digits}"
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code not in (200, 302):
            return None
        # wa.me returns a landing page; presence is inconclusive — flag experimental
        body = resp.text.lower()
        if "whatsapp" not in body:
            return None
        from ..core.phone_extractor import mask_phone

        return {
            "platform": "whatsapp",
            "profile_url": url,
            "metadata": {
                "phone_number": mask_phone(f"+{digits}"),
                "check_type": "phone",
                "experimental": True,
                "platform_hint": "possible_registration",
            },
            "confidence": "low",
        }
    except Exception:
        return None


class MessagingHintsModule(BaseModule):
    name = "messaging_hints"
    description = (
        "Best-effort Telegram username and WhatsApp phone hints. "
        "All findings are low-confidence / experimental."
    )
    requires_key = False

    async def run(
        self,
        email: str,
        phone_hints: list[str] | None = None,
        collected: dict[str, Any] | None = None,
    ) -> ModuleResult:
        if not settings.enable_messaging_hints:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_MESSAGING_HINTS=true to run this module"],
            )

        usernames = _collect_usernames(email)
        if collected:
            for result in collected.values():
                if not hasattr(result, "findings"):
                    continue
                for finding in result.findings:
                    if not isinstance(finding, dict):
                        continue
                    payloads = [finding]
                    meta = finding.get("metadata")
                    if isinstance(meta, dict):
                        payloads.append(meta)
                    for payload in payloads:
                        for key in _USERNAME_KEYS:
                            val = payload.get(key)
                            if isinstance(val, str):
                                u = val.strip().lower().lstrip("@")
                                if (
                                    u
                                    and u not in usernames
                                    and len(usernames) < _MAX_TELEGRAM_CHECKS
                                ):
                                    usernames.append(u)
                        for key in _DISPLAY_KEYS:
                            val = payload.get(key)
                            if isinstance(val, str):
                                for variant in _slug_variants(val):
                                    if (
                                        variant not in usernames
                                        and len(usernames) < _MAX_TELEGRAM_CHECKS
                                    ):
                                        usernames.append(variant)
        usernames = usernames[:_MAX_TELEGRAM_CHECKS]

        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # scrapingant: dropped in S5 audit (Telegram/WhatsApp landing HTML is static)
        async with build_client(timeout=12.0, follow_redirects=True) as client:
            tg_tasks = [_check_telegram_username(client, u) for u in usernames]
            tg_results = await asyncio.gather(*tg_tasks)
            for item in tg_results:
                if item:
                    findings.append(item)

            phones = list(phone_hints or [])[:3]
            if phones:
                wa_tasks = [_check_whatsapp_phone(client, p) for p in phones]
                wa_results = await asyncio.gather(*wa_tasks)
                for item in wa_results:
                    if item:
                        findings.append(item)

        status = ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL
        if not findings and not usernames and not phone_hints:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "telegram_checks": len(usernames),
                "whatsapp_checks": len(phone_hints or []),
                "signal_checkable": False,
            },
            errors=errors,
        )
