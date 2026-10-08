from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_API_BASE = "https://leakcheck.io"
_API_HOST = "leakcheck.io"
_MIN_DELAY_SECONDS = 2.0
_GENERIC_SOURCE_LABELS = (
    "stealer",
    "stealer logs",
    "combolist",
    "combo list",
    "collection",
    "collections",
)


def _is_generic_source_label(name: str) -> bool:
    normalized = "".join(ch.lower() for ch in name if ch.isalnum() or ch.isspace()).strip()
    normalized = " ".join(normalized.split())
    if not normalized:
        return False
    if normalized in _GENERIC_SOURCE_LABELS:
        return True
    return any(
        normalized.startswith(prefix)
        for prefix in ("stealer", "combolist", "combo list", "collection")
    )


class LeakCheckModule(BaseModule):
    name = "leakcheck"
    email_linked = True
    description = "Check LeakCheck's public API for direct email-to-breach associations."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        rate_limiter.set_delay(
            _API_HOST, max(rate_limiter.get_delay(_API_HOST), _MIN_DELAY_SECONDS)
        )

        path = f"/api/public?check={quote(email, safe='')}"
        status_code = None
        data: dict[str, Any] | None = None
        error_msg: str | None = None

        async with build_client(base_url=_API_BASE, timeout=15.0) as client:
            try:
                response = await client.get(path)
                status_code = response.status_code
                if status_code == 429:
                    error_msg = "LeakCheck rate limit exceeded; retry after a short pause."
                elif status_code != 200:
                    error_msg = f"LeakCheck API error: {status_code}"
                else:
                    try:
                        data = response.json()
                    except Exception:
                        error_msg = "LeakCheck response was not valid JSON"
            except httpx.TimeoutException:
                error_msg = "LeakCheck direct breach check timed out"
            except Exception as exc:
                error_msg = f"LeakCheck direct breach check failed: {exc}"

        if error_msg:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                metadata={"email": email, "sources_found": 0, "breach_names": []},
                errors=[error_msg],
            )

        if not isinstance(data, dict):
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                metadata={"email": email, "sources_found": 0, "breach_names": []},
                errors=["LeakCheck response had an unexpected shape"],
            )

        success = data.get("success")
        if not success:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={"email": email, "sources_found": 0, "breach_names": []},
                errors=[],
            )

        sources = data.get("sources", [])
        if not isinstance(sources, list):
            sources = []

        findings: list[dict[str, Any]] = []
        breach_names: list[str] = []
        stealer_signals: list[str] = []

        for source in sources:
            if isinstance(source, dict):
                name = str(source.get("name") or "").strip()
                date = str(source.get("date") or "").strip()
            else:
                name = str(source).strip()
                date = ""

            if name.lower().endswith(".com"):
                name = name[:-4]

            if not name:
                continue

            metadata = {"source_module": "leakcheck"}
            if date:
                metadata["breach_date"] = date

            finding: dict[str, Any] = {
                "platform": name,
                "source": "leakcheck",
                "confidence": "high",
                "severity": "medium",
                "metadata": metadata,
            }

            if _is_generic_source_label(name):
                stealer_signals.append(name)
                finding["signal_type"] = "stealer_signal"
                metadata["source_category"] = name
            else:
                breach_names.append(name)
                metadata["breach_name"] = name
                finding["breach_name"] = name

            findings.append(finding)

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "email": email,
                "sources_found": len(findings),
                "breach_names": breach_names,
                "stealer_signals": stealer_signals,
            },
            errors=[],
        )
