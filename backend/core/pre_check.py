"""Session bootstrap helpers for platform probes.

A ``pre_check`` runs one optional request before the main probe to collect the
session material a site needs: cookies, a CSRF token, and/or arbitrary tokens
scraped from the bootstrap page (a hidden form field, a ``<meta>`` tag, or a
regex over the raw HTML/JS). Extracted values are substituted into the main
request's URL, headers, and body via placeholders:

* ``{csrftoken_value}`` / ``{csrf_token}`` — the resolved CSRF token
* ``{<cookie_name>_value}`` — any cookie value
* ``{<token_name>}`` — any ``extract_regex`` / ``extract_fields`` named token

The literal ``meta[name='csrf-token']`` / ``input[name='csrf-token']`` selectors
are still special-cased for backward compatibility, but ``extract_csrf`` now
accepts an arbitrary ``meta[name='X']`` or ``input[name='X']`` selector.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

_SELECTOR_RE = re.compile(
    r"""^\s*(?P<tag>meta|input)\s*\[\s*name\s*=\s*['"](?P<name>[^'"]+)['"]\s*\]\s*$""",
    re.IGNORECASE,
)


class _SelectorParser(HTMLParser):
    """Extract the value of a single ``meta[name=X]`` / ``input[name=X]`` element."""

    def __init__(self, selector: str) -> None:
        super().__init__()
        match = _SELECTOR_RE.match(selector)
        if match:
            self._tag = match.group("tag").lower()
            self._name = match.group("name").lower()
        else:
            # Legacy behaviour: bare selectors default to name="csrf-token".
            self._tag = "meta" if "meta" in selector.lower() else "input"
            self._name = "csrf-token"
        # meta carries its value in `content`, input in `value`.
        self._value_attr = "content" if self._tag == "meta" else "value"
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.value is not None:
            return
        if tag.lower() != self._tag:
            return
        attributes = {key.lower(): value or "" for key, value in attrs}
        if attributes.get("name", "").lower() == self._name:
            self.value = attributes.get(self._value_attr) or None


def _extract_selector_value(body: str, selector: Any) -> str | None:
    if not isinstance(selector, str) or not selector.strip():
        return None
    parser = _SelectorParser(selector)
    try:
        parser.feed(body)
    except Exception:
        return None
    return parser.value


def _extract_regex_tokens(body: str, spec: Any) -> dict[str, str]:
    """Return ``{token_name: match}`` for each ``{name: pattern}`` in ``spec``."""
    if not isinstance(spec, dict):
        return {}
    tokens: dict[str, str] = {}
    for name, pattern in spec.items():
        if not isinstance(name, str) or not isinstance(pattern, str):
            continue
        try:
            match = re.search(pattern, body)
        except re.error:
            continue
        if not match:
            continue
        tokens[name] = match.group(1) if match.groups() else match.group(0)
    return tokens


def _cookie_dict(cookies: Any) -> dict[str, str]:
    try:
        return {str(key): str(value) for key, value in cookies.items()}
    except Exception:
        return {}


async def run_pre_check(client: Any, definition: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Run an optional pre-check and return cookies, a CSRF token, and named tokens."""
    config = definition.get("pre_check")
    if not isinstance(config, dict):
        return {"cookies": {}, "csrf_token": None, "tokens": {}}

    url = config.get("url") or config.get("endpoint")
    if not isinstance(url, str) or not url:
        return {"cookies": {}, "csrf_token": None, "tokens": {}}
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
    body = getattr(response, "text", "") or ""
    cookies = _cookie_dict(getattr(response, "cookies", None))
    cookies.update(_cookie_dict(getattr(client, "cookies", None)))

    csrf_token = _extract_selector_value(body, config.get("extract_csrf"))
    cookie_name = config.get("cookie_name")
    if not csrf_token and isinstance(cookie_name, str):
        csrf_token = cookies.get(cookie_name)
    if not csrf_token:
        csrf_token = cookies.get("csrftoken")

    tokens = _extract_regex_tokens(body, config.get("extract_regex"))
    return {"cookies": cookies, "csrf_token": csrf_token, "tokens": tokens}


def apply_pre_check_values(
    value: Any,
    cookies: dict[str, str],
    csrf_token: str | None,
    tokens: dict[str, str] | None = None,
) -> Any:
    """Substitute pre-check placeholders in strings, mappings, and lists."""
    if not isinstance(value, str):
        if isinstance(value, dict):
            return {
                key: apply_pre_check_values(item, cookies, csrf_token, tokens)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [apply_pre_check_values(item, cookies, csrf_token, tokens) for item in value]
        return value
    replacements = {"{csrftoken_value}": csrf_token or "", "{csrf_token}": csrf_token or ""}
    replacements.update({"{" + name + "_value}": token for name, token in cookies.items()})
    if tokens:
        # Named tokens are exposed as bare {name}; last-wins over any collision.
        replacements.update({"{" + name + "}": token for name, token in tokens.items()})
    for marker, replacement in replacements.items():
        value = value.replace(marker, replacement)
    return value


def cookie_header(cookies: dict[str, str]) -> str | None:
    return "; ".join(f"{name}={value}" for name, value in cookies.items()) or None
