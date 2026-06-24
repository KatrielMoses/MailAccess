from __future__ import annotations

import asyncio
import html
import re
from typing import Any
from urllib.parse import urlparse

import httpx


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _domains_match(left: str, right: str) -> bool:
    left_host = urlparse(left).netloc.lower().removeprefix("www.")
    right_host = urlparse(right).netloc.lower().removeprefix("www.")
    return bool(left_host and right_host and left_host == right_host)


def _detect_message(defn: dict[str, Any], body: str) -> str:
    body = html.unescape(body)

    for marker in _as_list(defn.get("absenceStrs")):
        if marker in body:
            return "miss"

    presense = _as_list(defn.get("presenseStrs"))
    if presense:
        return "hit" if all(marker in body for marker in presense) else "miss"

    if _as_list(defn.get("absenceStrs")):
        return "hit"
    return "miss"


def detect_hit(defn: dict[str, Any], body: str, status: int, final_url: str) -> str:
    """Classify a Maigret probe result as hit, miss, or inconclusive."""
    body = html.unescape(body)

    for marker in (defn.get("errors") or {}):
        if str(marker) in body:
            return "inconclusive"

    check_type = str(defn.get("checkType") or "status_code")

    if check_type == "status_code":
        if status == 200:
            for marker in _as_list(defn.get("absenceStrs")):
                if marker in body:
                    return "miss"
            min_response_bytes = defn.get("min_response_bytes", 500)
            try:
                min_response_bytes = int(min_response_bytes)
            except (TypeError, ValueError):
                min_response_bytes = 500
            if len(body) < min_response_bytes:
                return "inconclusive"
            return "hit"
        if status == 404:
            return "miss"
        if status == 403 and defn.get("ignore403"):
            return "inconclusive"
        if status in (429, 503, 599):
            return "inconclusive"
        return "miss"

    if check_type in ("message", "tags"):
        return _detect_message(defn, body)

    if check_type == "response_url":
        error_url = str(defn.get("errorUrl") or "")
        if error_url and error_url in final_url:
            return "miss"
        main_url = str(defn.get("urlMain") or "")
        parsed = urlparse(final_url)
        if main_url and _domains_match(main_url, final_url) and parsed.path in ("", "/", "/404"):
            return "miss"
        if status in (404, 410):
            return "miss"
        if status in (429, 503):
            return "inconclusive"
        return "hit"

    return "miss"


def prepare_platform_defn(defn: dict[str, Any], username: str) -> dict[str, Any]:
    prepared = dict(defn)
    if prepared.get("engine") == "Discourse" and not prepared.get("url"):
        main = str(prepared.get("urlMain") or "").rstrip("/")
        prepared["urlProbe"] = f"{main}/u/{{username}}.json"
        prepared["url"] = f"{main}/u/{{username}}"
        prepared["checkType"] = "status_code"
    return prepared


def username_matches_regex(defn: dict[str, Any], username: str) -> bool:
    regex = defn.get("regexCheck")
    if not regex:
        return True
    try:
        return re.fullmatch(str(regex), username) is not None
    except re.error:
        return False


def substitute_username(value: Any, username: str) -> Any:
    if isinstance(value, str):
        return value.replace("{username}", username)
    if isinstance(value, dict):
        return {key: substitute_username(item, username) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute_username(item, username) for item in value]
    return value


async def probe_platform(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    name: str,
    defn: dict[str, Any],
    username: str,
    timeout: float = 8.0,
) -> tuple[str, str | None]:
    """Probe one platform. Never raises."""
    prepared = prepare_platform_defn(defn, username)
    if not username_matches_regex(prepared, username):
        return ("inconclusive", "regex_rejected")

    probe_template = prepared.get("urlProbe") or prepared.get("url")
    display_template = prepared.get("url")
    if not probe_template or not display_template:
        return ("inconclusive", "missing_url")

    probe_url = str(probe_template).replace("{username}", username)
    display_url = str(display_template).replace("{username}", username)
    method = str(prepared.get("requestMethod") or "GET").upper()
    headers = dict(prepared.get("headers") or {})
    payload = prepared.get("requestPayload")
    if payload:
        payload = substitute_username(payload, username)
    if prepared.get("protection"):
        timeout = max(timeout, 12.0)

    async with sem:
        try:
            response = await client.request(
                method,
                probe_url,
                headers=headers,
                json=payload if isinstance(payload, (dict, list)) else None,
                data=payload if payload and not isinstance(payload, (dict, list)) else None,
                timeout=timeout,
                follow_redirects=True,
            )
            verdict = detect_hit(prepared, response.text, response.status_code, str(response.url))
            if verdict == "hit":
                return ("hit", display_url)
            if verdict == "miss":
                return ("miss", None)
            return ("inconclusive", f"{name}: {response.status_code}")
        except httpx.TimeoutException:
            return ("inconclusive", "timeout")
        except Exception as exc:
            return ("inconclusive", str(exc)[:80])
