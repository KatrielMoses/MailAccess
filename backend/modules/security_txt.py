from __future__ import annotations

import logging
from typing import Any

from ..core.concurrent_fetch_cache import CachedFetch
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

class SecurityTxtModule(BaseModule):
    name = "security_txt"
    description = "Email discovery via RFC 9116 /.well-known/security.txt"
    requires_key = False
    default_enabled = False

    async def run(
        self,
        domain: str,
        *,
        fetch: CachedFetch | None = None,
    ) -> ModuleResult:
        urls = [
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/security.txt",
        ]
        client = fetch or getattr(self, "session", None)
        if client is None:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                errors=["security_txt has no HTTP transport"],
                metadata={"emails_found": 0},
            )
        for url in urls:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                text = resp.text
                emails = _parse_security_txt(text, domain)
                if emails:
                    return ModuleResult(
                        status=ModuleStatus.SUCCESS,
                        findings=[_to_finding(e, url) for e in emails],
                        metadata={
                            "url": url,
                            "emails_found": len(emails),
                        }
                    )
            except Exception:
                continue
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[],
            metadata={"emails_found": 0}
        )

def _parse_security_txt(text: str, domain: str) -> list[str]:
    emails = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        for field in ("Contact:", "Email:"):
            if line.lower().startswith(field.lower()):
                value = line[len(field):].strip()
                if value.startswith("mailto:"):
                    value = value[7:]
                if "@" in value:
                    candidate = value.lower().strip()
                    if candidate.rsplit("@", 1)[-1] == domain.lower():
                        emails.append(candidate)
    return list(dict.fromkeys(emails))

def _to_finding(email: str, url: str) -> dict[str, Any]:
    return {
        "platform": "security_txt",
        "profile_url": url,
        "confidence": "high",
        "metadata": {
            "email": email,
            "source_url": url,
            "source_type": "security_txt_contact",
            "confidence_score": 0.90,
        },
    }
