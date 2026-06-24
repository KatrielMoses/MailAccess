from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from .sherlock_detector import _USER_AGENT, _WAF, WAFDetector, interpolate_string


def _interpolate_account(template: Any, username: str) -> Any:
    """Interpolate WMN's {account} placeholder via the shared helper."""
    if isinstance(template, str):
        template = template.replace("{account}", "{}")
    return interpolate_string(template, username)


def _clean_username(username: str, strip_bad_char: Any) -> str:
    if not isinstance(strip_bad_char, str) or not strip_bad_char:
        return username
    return re.sub(f"[{re.escape(strip_bad_char)}]", "", username)


async def probe_blackbird_site(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    site_name: str,
    defn: dict[str, Any],
    username: str,
    timeout: float = 8.0,
) -> tuple[str, str | None]:
    """Probe one WMN site using its two-marker detection scheme.

    Returns (outcome, detail), where outcome is ``hit``, ``miss``,
    ``inconclusive``, or ``illegal``. This function never raises.
    """
    del site_name  # Retained in the public signature for detector symmetry.

    uri_check = defn.get("uri_check")
    if not isinstance(uri_check, str) or not uri_check:
        return ("inconclusive", "missing_uri_check")

    cleaned_username = _clean_username(username, defn.get("strip_bad_char"))
    probe_url = _interpolate_account(uri_check, cleaned_username)
    pretty_template = defn.get("uri_pretty") or uri_check
    pretty_url = _interpolate_account(pretty_template, cleaned_username)

    headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    site_headers = defn.get("headers") or {}
    if isinstance(site_headers, dict):
        headers.update({str(key): str(value) for key, value in site_headers.items()})

    post_body = defn.get("post_body")
    method = "POST" if post_body is not None else "GET"
    request_body = (
        _interpolate_account(post_body, cleaned_username) if post_body is not None else None
    )

    async with sem:
        try:
            response = await client.request(
                method,
                probe_url,
                headers=headers,
                content=request_body,
                timeout=timeout,
                follow_redirects=True,
            )
        except httpx.TimeoutException:
            return ("inconclusive", "timeout")
        except Exception as exc:
            return ("inconclusive", str(exc)[:80])

    try:
        body = response.text
    except Exception:
        body = ""

    if body and _WAF.is_waf_blocked(body):
        return ("inconclusive", "waf_blocked")

    status = response.status_code
    e_code = defn.get("e_code")
    m_code = defn.get("m_code")
    e_str_match = defn.get("e_string", "") in body
    e_code_match = status == e_code
    m_str_absent = defn.get("m_string", "") not in body
    m_code_distinct = m_code != e_code
    m_code_match = (not m_code_distinct) or (status != m_code)

    if e_str_match and e_code_match and m_str_absent and m_code_match:
        return ("hit", str(pretty_url))
    return ("miss", None)


__all__ = ["WAFDetector", "probe_blackbird_site"]
