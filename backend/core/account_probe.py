"""Native email-existence probe engine.

Data-driven engine over declarative per-site definitions. Sites are described in
``data/mailaccess_sites.json`` and probed by :func:`probe_site`,
which reuses the existing ``pre_check`` (session bootstrap / CSRF / token scrape)
and ``probe_detector.detect_hit`` (hit/miss/inconclusive) primitives — so no
parallel engine is introduced. Sites that need bespoke multi-request logic
(control-email disambiguation, multi-step recovery relays, JS-blob token
surgery) declare a ``handler`` and are dispatched to
:mod:`backend.core.account_probe_handlers`.

Each probe returns a stable record so the ``account_discovery``
finding shape is unchanged::

    {name, domain, method, exists, rateLimit, emailrecovery, phoneNumber, others}
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json as _json
import logging
import re
from typing import Any

import httpx

from .phone_extractor import mask_phone
from .pre_check import apply_pre_check_values, cookie_header, run_pre_check
from .probe_detector import detect_hit
from .user_agents import random_user_agent

_LOG = logging.getLogger(__name__)

# Statuses that signal "slow down / blocked" rather than a definitive answer.
_RATE_LIMIT_STATUSES = {429, 503, 599}


def default_health_key(defn: dict[str, Any]) -> str:
    return str(defn.get("health_key") or f"account_discovery:{defn.get('id') or defn.get('name')}")


def _empty_record(defn: dict[str, Any], *, rate_limited: bool = False,
                  exists: bool | None = None) -> dict[str, Any]:
    return {
        "name": defn.get("name") or defn.get("id"),
        "domain": defn.get("domain") or "",
        "method": defn.get("flow") or "other",
        "exists": exists,
        "rateLimit": rate_limited,
        "emailrecovery": None,
        "phoneNumber": None,
        "others": None,
    }


def _mask_email(value: str) -> str:
    """Mask a recovery email; pass through values the provider already masked."""
    value = value.strip()
    if not value or "*" in value:
        return value
    local, _, domain = value.partition("@")
    if not domain:
        return "***"
    head = local[0] if local else ""
    return f"{head}***@{domain}"


def _json_path(data: Any, path: str) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (IndexError, ValueError, TypeError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _coerce_str(value: Any, join: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [str(item) for item in value if item not in (None, "")]
        return join.join(parts) if parts else None
    text = str(value).strip()
    return text or None


def apply_extract_fields(
    defn: dict[str, Any], response: httpx.Response, text: str
) -> dict[str, Any]:
    """Return ``{emailrecovery, phoneNumber, others}`` per the site's extract_fields."""
    spec = defn.get("extract_fields")
    out: dict[str, Any] = {"emailrecovery": None, "phoneNumber": None, "others": None}
    if not isinstance(spec, dict):
        return out
    parsed_json: Any = None
    json_loaded = False
    extras: dict[str, Any] = {}
    for field, rule in spec.items():
        if not isinstance(rule, dict):
            continue
        source = str(rule.get("source") or "json")
        raw: Any = None
        if source == "json":
            if not json_loaded:
                json_loaded = True
                try:
                    parsed_json = response.json()
                except Exception:
                    try:
                        parsed_json = _json.loads(text)
                    except Exception:
                        parsed_json = None
            raw = _json_path(parsed_json, str(rule.get("path") or ""))
        elif source == "regex":
            try:
                match = re.search(str(rule.get("pattern") or ""), text)
            except re.error:
                match = None
            if match:
                group = rule.get("group", 1)
                try:
                    raw = match.group(group) if match.groups() else match.group(0)
                except (IndexError, TypeError):
                    raw = match.group(0)
        value = _coerce_str(raw, str(rule.get("join") or ", "))
        if value is None:
            continue
        mask = str(rule.get("mask") or "none")
        if mask == "phone":
            value = mask_phone(value)
        elif mask == "email":
            value = _mask_email(value)
        if field in ("email_recovery", "emailrecovery"):
            out["emailrecovery"] = value
        elif field in ("phone_hint", "phoneNumber", "phone"):
            out["phoneNumber"] = value
        else:
            extras[field] = value
    if extras:
        out["others"] = extras
    return out


def _build_request_kwargs(
    defn: dict[str, Any], email: str, precheck: dict[str, Any]
) -> dict[str, Any]:
    cookies = precheck.get("cookies") or {}
    csrf = precheck.get("csrf_token")
    tokens = precheck.get("tokens") or {}

    def _sub(value: Any) -> Any:
        value = _substitute_email(value, email)
        return apply_pre_check_values(value, cookies, csrf, tokens)

    url = _sub(defn.get("uri_check") or defn.get("url"))
    headers = dict(_sub(defn.get("headers") or {}))
    # Header-level fingerprint rotation (5B): give each request a rotating UA
    # unless the site pins its own.
    if not any(key.lower() == "user-agent" for key in headers):
        headers["User-Agent"] = random_user_agent()
    payload = _sub(defn.get("requestPayload"))
    if cookies and "Cookie" not in headers:
        header = cookie_header(cookies)
        if header:
            headers["Cookie"] = header
    return {"url": url, "headers": headers, "payload": payload, "cookies": cookies or None}


def _substitute_email(value: Any, email: str) -> Any:
    if isinstance(value, str):
        if "{md5}" in value:
            md5 = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
            value = value.replace("{md5}", md5)
        return value.replace("{email}", email).replace("{username}", email)
    if isinstance(value, dict):
        return {key: _substitute_email(item, email) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_email(item, email) for item in value]
    return value


async def _probe_declarative(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    try:
        precheck = await run_pre_check(client, defn, timeout)
    except (httpx.TimeoutException, httpx.RequestError):
        return _empty_record(defn, rate_limited=True)
    except Exception:
        return _empty_record(defn, rate_limited=True)

    req = _build_request_kwargs(defn, email, precheck)
    if not req["url"]:
        return _empty_record(defn)

    method = str(defn.get("requestMethod") or defn.get("method") or "GET").upper()
    payload = req["payload"]
    headers = req["headers"] or {}
    content_type = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            content_type = str(value).lower()
            break
    body_type = str(defn.get("body_type") or "").lower()
    as_form = body_type == "form" or "form-urlencoded" in content_type
    send_json = isinstance(payload, dict | list) and not as_form
    # Most probes follow redirects, but some sites signal existence *with* the
    # redirect itself (e.g. a 302 to /login means "account exists"). Those set
    # ``follow_redirects: false`` and classify on the 3xx status directly.
    follow_redirects = defn.get("follow_redirects", True)
    try:
        response = await client.request(
            method,
            req["url"],
            headers=headers or None,
            json=payload if send_json else None,
            data=payload if (payload is not None and not send_json) else None,
            cookies=req["cookies"],
            timeout=timeout,
            follow_redirects=bool(follow_redirects),
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _empty_record(defn, rate_limited=True)
    except Exception:
        return _empty_record(defn, rate_limited=True)

    text = response.text
    lowered = html.unescape(text).lower()
    for marker in defn.get("rate_limited_strings") or []:
        if str(marker).lower() in lowered:
            return _empty_record(defn, rate_limited=True)
    if response.status_code in _RATE_LIMIT_STATUSES:
        return _empty_record(defn, rate_limited=True)

    verdict = detect_hit(defn, text, response.status_code, str(response.url))
    # RC1 (Output-Trust): a bare-domain / search-URL 200 is not an existence
    # signal — such a page returns 200 for any input. Downgrade to inconclusive.
    from .probe_detector import is_non_discriminating_url

    local_part = email.split("@", 1)[0] if "@" in email else email
    if verdict == "hit" and is_non_discriminating_url(str(response.url), local_part):
        verdict = "inconclusive"
    record = _empty_record(defn)
    if verdict == "hit":
        record["exists"] = True
        extracted = apply_extract_fields(defn, response, text)
        record["emailrecovery"] = extracted["emailrecovery"]
        record["phoneNumber"] = extracted["phoneNumber"]
        record["others"] = extracted["others"]
    elif verdict == "miss":
        record["exists"] = False
    else:
        record["exists"] = None
    return record


async def probe_site(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    defn: dict[str, Any],
    email: str,
    *,
    timeout: float = 8.0,
    no_password_recovery: bool = False,
) -> dict[str, Any] | None:
    """Probe one site; never raises. Returns a probe record, or ``None``
    when the site is skipped (disabled, or recovery-only under
    ``no_password_recovery``)."""
    if defn.get("disabled"):
        return None
    if no_password_recovery and defn.get("recovery"):
        return None

    from .account_probe_handlers import HANDLERS  # local import avoids cycle

    handler_name = defn.get("handler")
    async with sem:
        if handler_name:
            handler = HANDLERS.get(str(handler_name))
            if handler is None:
                _LOG.warning("account_probe: unknown handler %r for %s", handler_name,
                             defn.get("id"))
                return _empty_record(defn)
            try:
                return await asyncio.wait_for(
                    handler(client, defn, email, timeout), timeout=timeout * 3
                )
            except (asyncio.TimeoutError, httpx.TimeoutException, httpx.RequestError):
                return _empty_record(defn, rate_limited=True)
            except Exception as exc:  # noqa: BLE001 - handler isolation
                _LOG.debug("account_probe: handler %s failed: %s", handler_name, exc)
                return _empty_record(defn, rate_limited=True)
        return await _probe_declarative(client, defn, email, timeout)
