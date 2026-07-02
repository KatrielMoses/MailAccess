from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from ..config import APP_VERSION

# ---------------------------------------------------------------------------
# String interpolation helpers (mirror sherlock upstream exactly)
# ---------------------------------------------------------------------------

def interpolate_string(template: Any, username: str) -> Any:
    """Replace {} with username recursively through str / dict / list."""
    if isinstance(template, str):
        return template.replace("{}", username)
    if isinstance(template, dict):
        return {k: interpolate_string(v, username) for k, v in template.items()}
    if isinstance(template, list):
        return [interpolate_string(item, username) for item in template]
    return template


def check_for_parameter(username: str) -> bool:
    """Return True when {?} appears in username (multi-char-symbol probe)."""
    return "{?}" in username


def multiple_usernames(username: str) -> list[str]:
    """Expand {?} into _, -, . variants; return [username] when no placeholder."""
    if not check_for_parameter(username):
        return [username]
    return [username.replace("{?}", sym) for sym in ("_", "-", ".")]


# ---------------------------------------------------------------------------
# WAF fingerprint detector (ported verbatim from sherlock upstream)
# ---------------------------------------------------------------------------

_WAF_FINGERPRINTS: tuple[str, ...] = (
    # 2024-05-13 Cloudflare JS challenge
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}"
    "body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}"
    "body.dark a:hover{color:#ee730a;text-decoration:underline}"
    "body.dark .lds-ring div{border-color:#999 transparent transparent}"
    "body.dark .font-red{color:#b20f03}body.dark",
    # 2024-11-11 Cloudflare error page
    '<span id="challenge-error-text">',
    # 2024-11-11 AWS WAF / CloudFront
    "AwsWafIntegration.forceRefreshToken",
    # 2024-04-09 PerimeterX / Human Security
    '{return l.onPageView}}),Object.defineProperty(r,"perimeterxIdentifiers",{enumerable:',
)


class WAFDetector:
    def is_waf_blocked(self, body: str) -> bool:
        return any(fp in body for fp in _WAF_FINGERPRINTS)


_WAF = WAFDetector()

_USER_AGENT = f"mailaccess/{APP_VERSION}"


# ---------------------------------------------------------------------------
# Async probe (mirrors sherlock() detection logic, ported to httpx)
# ---------------------------------------------------------------------------

async def probe_sherlock_site(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    site_name: str,
    defn: dict[str, Any],
    username: str,
    timeout: float = 8.0,
) -> tuple[str, str | None]:
    """Probe one Sherlock site. Returns (outcome, detail). Never raises.

    outcome: 'hit' | 'miss' | 'inconclusive' | 'illegal'
    detail:  profile URL on hit, 'waf_blocked' or error text on inconclusive, None otherwise
    """
    url_template = defn.get("url", "")
    if not url_template:
        return ("inconclusive", "missing_url")

    display_url = interpolate_string(url_template, username)

    # Regex check uses re.search (mirrors upstream: re.search(regex_check, username))
    regex_check = defn.get("regex_check")
    if regex_check:
        try:
            if re.search(str(regex_check), username) is None:
                return ("illegal", None)
        except re.error:
            pass

    error_type = str(defn.get("error_type") or "status_code")

    url_probe_template = defn.get("url_probe")
    probe_url = (
        interpolate_string(url_probe_template, username) if url_probe_template else display_url
    )

    request_method = (defn.get("request_method") or "").upper()
    if not request_method:
        # Mirror upstream: HEAD for status_code (body not needed), GET otherwise
        request_method = "HEAD" if error_type == "status_code" else "GET"

    # response_url detection requires no redirect so we capture the original status
    follow_redirects = error_type != "response_url"

    headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    site_headers = defn.get("headers") or {}
    if isinstance(site_headers, dict):
        headers.update({str(k): str(v) for k, v in site_headers.items()})

    request_payload = defn.get("request_payload")
    if request_payload is not None:
        request_payload = interpolate_string(request_payload, username)

    async with sem:
        try:
            response = await client.request(
                request_method,
                probe_url,
                headers=headers,
                json=request_payload if isinstance(request_payload, dict | list) else None,
                data=(
                    request_payload
                    if request_payload and not isinstance(request_payload, dict | list)
                    else None
                ),
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
        except httpx.TimeoutException:
            return ("inconclusive", "timeout")
        except Exception as exc:
            return ("inconclusive", str(exc)[:80])

    try:
        body = response.text
    except Exception:
        body = ""

    status = response.status_code

    # WAF check before content analysis (requires body; HEAD responses have none)
    if body and _WAF.is_waf_blocked(body):
        return ("inconclusive", "waf_blocked")

    if error_type == "status_code":
        error_codes = defn.get("error_code")
        if isinstance(error_codes, int):
            error_codes = [error_codes]
        elif not isinstance(error_codes, list):
            error_codes = None

        if error_codes and status in error_codes:
            return ("miss", None)
        if status < 200 or status >= 300:
            return ("miss", None)
        return ("hit", display_url)

    if error_type == "message":
        error_msg = defn.get("error_msg")
        if isinstance(error_msg, str):
            errors_list: list[str] = [error_msg]
        elif isinstance(error_msg, list):
            errors_list = [str(e) for e in error_msg]
        else:
            errors_list = []

        if errors_list and any(e in body for e in errors_list):
            return ("miss", None)
        return ("hit", display_url)

    if error_type == "response_url":
        if 200 <= status < 300:
            return ("hit", display_url)
        return ("miss", None)

    if error_type == "api":
        # Nexfil API mode: a non-404 JSON response is a hit only when one of
        # the configured result keys contains at least one list item.
        try:
            body_json = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return ("miss", None)
        if not isinstance(body_json, dict) or status == 404:
            return ("miss", None)
        api_keys = defn.get("api_keys") or ["results", "users", "username"]
        if not isinstance(api_keys, list):
            api_keys = ["results", "users", "username"]
        for key in api_keys:
            value = body_json.get(str(key))
            if isinstance(value, list) and value:
                return ("hit", display_url)
        return ("miss", None)

    return ("inconclusive", f"unknown error_type: {error_type}")
