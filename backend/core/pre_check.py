"""Session bootstrap helpers for platform probes."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any


class _SelectorParser(HTMLParser):
    def __init__(self, selector: str) -> None:
        super().__init__()
        self.selector = selector.strip().lower()
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.value is not None:
            return
        attributes = {key.lower(): value or "" for key, value in attrs}
        if self.selector == "meta[name='csrf-token']" or self.selector == 'meta[name="csrf-token"]':
            if tag.lower() == "meta" and attributes.get("name", "").lower() == "csrf-token":
                self.value = attributes.get("content") or None
        elif self.selector in {
            "input[name='csrf-token']",
            'input[name="csrf-token"]',
        }:
            if tag.lower() == "input" and attributes.get("name", "").lower() == "csrf-token":
                self.value = attributes.get("value") or None


def _extract_selector_value(body: str, selector: Any) -> str | None:
    if not isinstance(selector, str) or not selector.strip():
        return None
    parser = _SelectorParser(selector)
    try:
        parser.feed(body)
    except Exception:
        return None
    return parser.value


def _cookie_dict(cookies: Any) -> dict[str, str]:
    try:
        return {str(key): str(value) for key, value in cookies.items()}
    except Exception:
        return {}


async def run_pre_check(client: Any, definition: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Run an optional pre-check and return cookies plus a CSRF token."""
    config = definition.get("pre_check")
    if not isinstance(config, dict):
        return {"cookies": {}, "csrf_token": None}

    url = config.get("url") or config.get("endpoint")
    if not isinstance(url, str) or not url:
        return {"cookies": {}, "csrf_token": None}
    method = str(config.get("method") or "GET").upper()
    headers = config.get("headers") if isinstance(config.get("headers"), dict) else None
    response = await client.request(
        method,
        url,
        headers=headers,
        content=config.get("body") or config.get("data"),
        timeout=timeout,
        follow_redirects=True,
    )
    cookies = _cookie_dict(getattr(response, "cookies", None))
    cookies.update(_cookie_dict(getattr(client, "cookies", None)))
    csrf_token = _extract_selector_value(getattr(response, "text", ""), config.get("extract_csrf"))
    cookie_name = config.get("cookie_name")
    if not csrf_token and isinstance(cookie_name, str):
        csrf_token = cookies.get(cookie_name)
    if not csrf_token:
        csrf_token = cookies.get("csrftoken")
    return {"cookies": cookies, "csrf_token": csrf_token}


def apply_pre_check_values(value: Any, cookies: dict[str, str], csrf_token: str | None) -> Any:
    """Substitute pre-check placeholders in strings, mappings, and lists."""
    if not isinstance(value, str):
        if isinstance(value, dict):
            return {
                key: apply_pre_check_values(item, cookies, csrf_token)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [apply_pre_check_values(item, cookies, csrf_token) for item in value]
        return value
    replacements = {"{csrftoken_value}": csrf_token or "", "{csrf_token}": csrf_token or ""}
    replacements.update({"{" + name + "_value}": token for name, token in cookies.items()})
    for marker, replacement in replacements.items():
        value = value.replace(marker, replacement)
    return value


def cookie_header(cookies: dict[str, str]) -> str | None:
    return "; ".join(f"{name}={value}" for name, value in cookies.items()) or None
