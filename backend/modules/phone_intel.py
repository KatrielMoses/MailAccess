from __future__ import annotations

import asyncio
import re
from html import unescape
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from ..core.phone_extractor import extract_phones, mask_phone
from .base import BaseModule, ModuleResult, ModuleStatus


async def _validate_phone(client: Any, phone: str) -> dict[str, Any] | None:
    """NumVerify-style validation via apilayer (best-effort, no key)."""
    try:
        resp = await client.get(
            "http://apilayer.net/api/validate",
            params={"number": phone},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("valid") and data.get("number") is None:
            return None
        return {
            "platform": "phone_validation",
            "metadata": {
                "phone_number": mask_phone(phone),
                "valid": bool(data.get("valid")),
                "country": data.get("country_name") or data.get("country_code"),
                "carrier": data.get("carrier"),
                "line_type": data.get("line_type"),
                "platform_hint": "numverify",
            },
            "confidence": "high",
        }
    except Exception:
        return None


async def _check_whatsapp(client: Any, phone: str) -> dict[str, Any] | None:
    digits = re.sub(r"\D", "", phone)
    if not digits:
        return None
    url = f"https://wa.me/{digits}"
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code not in (200, 302):
            return None
        if "whatsapp" not in resp.text.lower():
            return None
        return {
            "platform": "whatsapp",
            "profile_url": url,
            "metadata": {
                "phone_number": mask_phone(phone),
                "platform_hint": "possible_registration",
                "experimental": True,
            },
            "confidence": "low",
        }
    except Exception:
        return None


async def _check_telegram_phone(client: Any, phone: str) -> dict[str, Any] | None:
    """Public t.me profile by phone (rare; best-effort)."""
    digits = re.sub(r"\D", "", phone)
    url = f"https://t.me/+{digits}"
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code != 200:
            return None
        body = resp.text
        if "tgme_page_title" not in body and "og:title" not in body:
            return None
        display_name = ""
        title_m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
        if title_m:
            display_name = unescape(title_m.group(1))
        return {
            "platform": "telegram",
            "profile_url": url,
            "metadata": {
                "phone_number": mask_phone(phone),
                "display_name": display_name,
                "check_type": "phone",
                "experimental": True,
            },
            "confidence": "low",
        }
    except Exception:
        return None


class PhoneIntelModule(BaseModule):
    name = "phone_intel"
    description = (
        "Validate recovered phone numbers and probe WhatsApp/Telegram hints. "
        "Runs automatically when phones are found in primary findings."
    )
    requires_key = False

    async def run(self, email: str, collected: dict[str, Any] | None = None) -> ModuleResult:
        if collected is None:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Runs in post-primary phase only"],
            )

        if not settings.enable_phone_intel:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_PHONE_INTEL=true to run this module"],
            )

        all_findings: list[dict[str, Any]] = []
        for result in collected.values():
            if hasattr(result, "findings"):
                all_findings.extend(result.findings)

        phones = extract_phones(all_findings)
        if not phones:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No phone numbers found in primary findings"],
            )

        findings: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(3)

        # scrapingant: dropped in S5 audit (phone validation JSON and static landing pages)
        async with build_client(timeout=12.0, follow_redirects=True) as client:

            async def _process(phone: str) -> list[dict[str, Any]]:
                async with sem:
                    results = await asyncio.gather(
                        _validate_phone(client, phone),
                        _check_whatsapp(client, phone),
                        _check_telegram_phone(client, phone),
                    )
                    return [r for r in results if r]

            batch = await asyncio.gather(*[_process(p) for p in phones[:5]])
            for group in batch:
                findings.extend(group)

        status = ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "phones_processed": len(phones[:5]),
                "phones_found": len(phones),
            },
        )
