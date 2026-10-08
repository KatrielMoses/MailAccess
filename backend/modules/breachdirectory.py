from __future__ import annotations

from typing import Any

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_API_URL = "https://breachdirectory.p.rapidapi.com/"
_HOST = "breachdirectory.p.rapidapi.com"


def _password_hint(password: str | None) -> str | None:
    if not password:
        return None
    p = str(password)
    if len(p) <= 2:
        return f"{p[0]}***" if p else None
    return f"{p[:2]}***"


def _looks_like_hash(value: str) -> bool:
    v = value.strip()
    if len(v) in (40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
        return True
    return False


class BreachDirectoryModule(BaseModule):
    name = "breachdirectory"
    email_linked = True
    description = (
        "Search breach records via BreachDirectory (RapidAPI). "
        "Requires BREACHDIRECTORY_API_KEY."
    )
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.breachdirectory_api_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["BREACHDIRECTORY_API_KEY not set"],
            )

        headers = {
            "X-RapidAPI-Key": settings.breachdirectory_api_key,
            "X-RapidAPI-Host": _HOST,
        }
        params = {"func": "auto", "term": email}

        async with build_client(timeout=20.0, follow_redirects=True) as client:
            try:
                resp = await client.get(_API_URL, headers=headers, params=params)
            except Exception as exc:
                return ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[f"BreachDirectory network error: {exc}"],
                )

        if resp.status_code == 429:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                errors=["Rate limit exceeded"],
            )
        if resp.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"BreachDirectory API error: {resp.status_code}"],
            )

        data = resp.json()
        records: list[dict[str, Any]] = data.get("result") or []
        findings: list[dict[str, Any]] = []
        sources_seen: set[str] = set()
        has_plaintext_hashes = False

        for record in records:
            password = record.get("password") or ""
            sha1 = record.get("sha1") or ""
            has_hash = bool(sha1 or password)
            if password and not _looks_like_hash(password):
                has_plaintext_hashes = True

            hint = _password_hint(password if password else None)

            for source in record.get("sources") or []:
                if not source or source in sources_seen:
                    continue
                sources_seen.add(source)

                severity = "critical" if has_hash else "high"
                findings.append({
                    "platform": source,
                    "metadata": {
                        "breach_source": source,
                        "has_password_hash": has_hash,
                        "password_hint": hint,
                    },
                    "confidence": "high",
                    "severity": severity,
                })

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "total_records_found": data.get("found", len(records)),
                "sources_list": sorted(sources_seen),
                "has_plaintext_hashes": has_plaintext_hashes,
            },
        )
