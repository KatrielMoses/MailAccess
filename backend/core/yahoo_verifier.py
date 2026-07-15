"""Opt-in Yahoo signup-flow existence signal.

Yahoo may change this undocumented flow or introduce CAPTCHA. Any bootstrap,
parse, or challenge response is therefore inconclusive rather than negative.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from .http_client import build_client


@dataclass
class YahooVerificationResult:
    email: str
    status: str = "inconclusive"
    http_status: int | None = None
    error: str | None = None


class YahooVerifier:
    bootstrap_url = "https://login.yahoo.com/account/create?specId=yidReg&lang=en-US&src=&done=https%3A%2F%2Fwww.yahoo.com&display=login"
    check_url = "https://login.yahoo.com/account/module/create?validateField=yid"

    def __init__(self, *, delay_seconds: float = 1.2, timeout_seconds: float = 10.0, max_checks: int = 25) -> None:
        self.delay_seconds = max(float(delay_seconds), 0.0)
        self.timeout_seconds = max(float(timeout_seconds), 1.0)
        self.max_checks = max(1, min(int(max_checks), 50))

    async def verify_batch(self, emails: list[str]) -> list[YahooVerificationResult]:
        cleaned = list(dict.fromkeys(e.strip().lower() for e in emails if isinstance(e, str) and "@" in e))
        results: list[YahooVerificationResult] = []
        async with build_client(timeout=self.timeout_seconds, follow_redirects=True) as client:
            bootstrap = await self._bootstrap(client)
            if isinstance(bootstrap, str):
                return [YahooVerificationResult(email=e, error=bootstrap) for e in cleaned]
            acrumb, session_index, spec_id = bootstrap
            for index, email in enumerate(cleaned):
                if index >= self.max_checks:
                    results.append(YahooVerificationResult(email=email, status="not_attempted"))
                    continue
                if index and self.delay_seconds:
                    await asyncio.sleep(self.delay_seconds)
                results.append(await self._check(client, email, acrumb, session_index, spec_id))
        return results

    async def _bootstrap(self, client: Any) -> tuple[str, str, str] | str:
        try:
            response = await client.get(self.bootstrap_url, headers={"User-Agent": "Mozilla/5.0"})
        except Exception as exc:  # noqa: BLE001
            return f"bootstrap_{type(exc).__name__}:{exc}"
        if response.status_code != 200:
            return f"bootstrap_http_{response.status_code}"
        cookie_values = [str(value) for value in response.cookies.values()]
        cookie_text = "; ".join(cookie_values)
        acrumb_match = re.search(r"(?:^|[;&])s=([^;&]+)", cookie_text)
        if not acrumb_match:
            acrumb_match = re.search(
                r'name=["\']acrumb["\']\s+value=["\']([^"\']+)',
                response.text,
                re.IGNORECASE,
            )
        session_match = re.search(
            r'name=["\']sessionIndex["\']\s+value=["\']([^"\']+)',
            response.text,
            re.IGNORECASE,
        )
        spec_match = re.search(r'[?&]specId=([^&"\']+)', str(response.url))
        if not spec_match:
            spec_match = re.search(
                r'name=["\']specId["\']\s+value=["\']([^"\']+)',
                response.text,
                re.IGNORECASE,
            )
        if not acrumb_match or not session_match:
            return "bootstrap_parse_failed"
        return acrumb_match.group(1), session_match.group(1), spec_match.group(1) if spec_match else "yidReg"

    async def _check(
        self,
        client: Any,
        email: str,
        acrumb: str,
        session_index: str,
        spec_id: str = "yidReg",
    ) -> YahooVerificationResult:
        local = email.rsplit("@", 1)[0]
        try:
            response = await client.post(
                self.check_url,
                data={"userId": local, "specId": spec_id, "acrumb": acrumb, "sessionIndex": session_index},
                headers={"X-Requested-With": "XMLHttpRequest", "Origin": "https://login.yahoo.com", "Referer": self.bootstrap_url},
            )
        except Exception as exc:  # noqa: BLE001
            return YahooVerificationResult(email=email, error=f"{type(exc).__name__}:{exc}")
        result = YahooVerificationResult(email=email, http_status=response.status_code)
        if response.status_code in (429, 403) or "captcha" in response.text.lower():
            result.status = "throttled"
            return result
        if response.status_code != 200:
            result.error = f"http_{response.status_code}"
            return result
        try:
            payload = response.json()
        except Exception:
            result.error = "invalid_json"
            return result
        errors = payload.get("errors") if isinstance(payload, dict) else None
        codes = {str(item.get("error") or "").upper() for item in errors or [] if isinstance(item, dict)}
        if codes & {"IDENTIFIER_EXISTS", "IDENTIFIER_NOT_AVAILABLE"}:
            result.status = "verified"
        elif "IDENTIFIER_AVAILABLE" in codes or not errors:
            result.status = "not_found"
        else:
            result.error = "unrecognized_response"
        return result
