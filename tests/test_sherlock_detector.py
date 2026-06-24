"""Unit tests for backend.core.sherlock_detector."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from backend.core.sherlock_detector import (
    WAFDetector,
    check_for_parameter,
    interpolate_string,
    multiple_usernames,
    probe_sherlock_site,
)


# ---------------------------------------------------------------------------
# Minimal mock transport for httpx.AsyncClient
# ---------------------------------------------------------------------------

class _MockTransport(httpx.AsyncBaseTransport):
    """Returns responses from a pre-loaded list in order; repeats last entry."""

    def __init__(self, responses: list[dict]) -> None:
        self._responses = responses
        self._idx = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = self._responses[min(self._idx, len(self._responses) - 1)]
        self._idx += 1
        status = resp.get("status", 200)
        body = resp.get("text", "")
        headers = resp.get("headers", {})
        return httpx.Response(status, text=body, headers=headers, request=request)


def _run_probe(defn: dict, username: str = "alice", status: int = 200, body: str = "") -> tuple[str, str | None]:
    """Synchronous wrapper to run probe_sherlock_site for unit tests."""
    async def _inner() -> tuple[str, str | None]:
        transport = _MockTransport([{"status": status, "text": body}])
        async with httpx.AsyncClient(transport=transport) as client:
            sem = asyncio.Semaphore(1)
            return await probe_sherlock_site(client, sem, "TestSite", defn, username)
    return asyncio.run(_inner())


# ---------------------------------------------------------------------------
# interpolate_string
# ---------------------------------------------------------------------------

def test_interpolate_string_simple_url() -> None:
    assert interpolate_string("https://github.com/{}", "alice") == "https://github.com/alice"


def test_interpolate_string_with_query_param() -> None:
    assert interpolate_string("https://api.example.com/user?id={}", "alice") == "https://api.example.com/user?id=alice"


def test_interpolate_string_recursive_dict() -> None:
    tmpl = {"url": "https://ex.com/{}", "label": "profile of {}"}
    result = interpolate_string(tmpl, "alice")
    assert result == {"url": "https://ex.com/alice", "label": "profile of alice"}


def test_interpolate_string_recursive_list() -> None:
    tmpl = ["https://ex.com/{}", "other_{}"]
    result = interpolate_string(tmpl, "alice")
    assert result == ["https://ex.com/alice", "other_alice"]


def test_interpolate_string_non_string_passthrough() -> None:
    assert interpolate_string(42, "alice") == 42
    assert interpolate_string(None, "alice") is None


# ---------------------------------------------------------------------------
# check_for_parameter / multiple_usernames
# ---------------------------------------------------------------------------

def test_check_for_parameter_present() -> None:
    assert check_for_parameter("user{?}") is True


def test_check_for_parameter_absent() -> None:
    assert check_for_parameter("alice") is False


def test_multiple_usernames_no_placeholder() -> None:
    assert multiple_usernames("alice") == ["alice"]


def test_multiple_usernames_with_placeholder() -> None:
    assert multiple_usernames("user{?}") == ["user_", "user-", "user."]


# ---------------------------------------------------------------------------
# WAFDetector
# ---------------------------------------------------------------------------

_WAF = WAFDetector()

_CF_WAF_BODY = (
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}"
    "body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}"
    "body.dark a:hover{color:#ee730a;text-decoration:underline}"
    "body.dark .lds-ring div{border-color:#999 transparent transparent}"
    "body.dark .font-red{color:#b20f03}body.dark rest of page"
)

_PX_WAF_BODY = (
    "some code {return l.onPageView}}),Object.defineProperty"
    '(r,"perimeterxIdentifiers",{enumerable: true, value: "px_abc"})'
)


def test_waf_detector_cloudflare_match() -> None:
    assert _WAF.is_waf_blocked(_CF_WAF_BODY) is True


def test_waf_detector_aws_waf_match() -> None:
    body = "<script>AwsWafIntegration.forceRefreshToken()</script>"
    assert _WAF.is_waf_blocked(body) is True


def test_waf_detector_perimeterx_match() -> None:
    assert _WAF.is_waf_blocked(_PX_WAF_BODY) is True


def test_waf_detector_cloudflare_error_page_match() -> None:
    body = '<html><body><span id="challenge-error-text">Please verify you are human</span></body></html>'
    assert _WAF.is_waf_blocked(body) is True


def test_waf_detector_clean_body() -> None:
    body = "<html><head><title>Profile</title></head><body><h1>Alice</h1></body></html>"
    assert _WAF.is_waf_blocked(body) is False


# ---------------------------------------------------------------------------
# probe_sherlock_site — status_code
# ---------------------------------------------------------------------------

def test_probe_status_code_hit() -> None:
    defn = {"url": "https://example.com/{}", "error_type": "status_code", "request_method": "GET"}
    outcome, detail = _run_probe(defn, status=200, body="<html>profile</html>")
    assert outcome == "hit"
    assert detail == "https://example.com/alice"


def test_probe_status_code_miss_404() -> None:
    defn = {"url": "https://example.com/{}", "error_type": "status_code"}
    outcome, detail = _run_probe(defn, status=404)
    assert outcome == "miss"
    assert detail is None


def test_probe_status_code_miss_custom_error_code() -> None:
    defn = {"url": "https://example.com/{}", "error_type": "status_code", "error_code": 403}
    outcome, detail = _run_probe(defn, status=403)
    assert outcome == "miss"


def test_probe_status_code_200_not_in_error_codes_is_hit() -> None:
    defn = {"url": "https://example.com/{}", "error_type": "status_code", "error_code": 404}
    outcome, detail = _run_probe(defn, status=200, body="<html>ok</html>")
    assert outcome == "hit"


# ---------------------------------------------------------------------------
# probe_sherlock_site — message
# ---------------------------------------------------------------------------

def test_probe_message_hit() -> None:
    defn = {
        "url": "https://example.com/users/{}",
        "error_type": "message",
        "error_msg": "User not found",
        "request_method": "GET",
    }
    outcome, detail = _run_probe(defn, status=200, body="<h1>Alice's profile</h1>")
    assert outcome == "hit"


def test_probe_message_miss() -> None:
    defn = {
        "url": "https://example.com/users/{}",
        "error_type": "message",
        "error_msg": "User not found",
        "request_method": "GET",
    }
    outcome, detail = _run_probe(defn, status=200, body="User not found")
    assert outcome == "miss"


def test_probe_message_list_error_msg_miss() -> None:
    defn = {
        "url": "https://example.com/users/{}",
        "error_type": "message",
        "error_msg": ["not found", "does not exist"],
        "request_method": "GET",
    }
    outcome, detail = _run_probe(defn, status=200, body="<p>does not exist</p>")
    assert outcome == "miss"


def test_probe_message_list_error_msg_hit() -> None:
    defn = {
        "url": "https://example.com/users/{}",
        "error_type": "message",
        "error_msg": ["not found", "does not exist"],
        "request_method": "GET",
    }
    outcome, detail = _run_probe(defn, status=200, body="<h1>Welcome, Alice!</h1>")
    assert outcome == "hit"


# ---------------------------------------------------------------------------
# probe_sherlock_site — response_url
# ---------------------------------------------------------------------------

def test_probe_response_url_hit() -> None:
    defn = {"url": "https://example.com/users/{}", "error_type": "response_url"}
    outcome, detail = _run_probe(defn, status=200)
    assert outcome == "hit"


def test_probe_response_url_miss() -> None:
    defn = {"url": "https://example.com/users/{}", "error_type": "response_url"}
    outcome, detail = _run_probe(defn, status=404)
    assert outcome == "miss"


def test_probe_response_url_miss_redirect_code() -> None:
    defn = {"url": "https://example.com/users/{}", "error_type": "response_url"}
    outcome, detail = _run_probe(defn, status=302)
    assert outcome == "miss"


# ---------------------------------------------------------------------------
# WAF blocking via probe
# ---------------------------------------------------------------------------

def test_probe_waf_block() -> None:
    defn = {
        "url": "https://example.com/users/{}",
        "error_type": "message",
        "error_msg": "Not found",
        "request_method": "GET",
    }
    outcome, detail = _run_probe(defn, status=200, body=_CF_WAF_BODY)
    assert outcome == "inconclusive"
    assert detail == "waf_blocked"


def test_probe_waf_block_aws() -> None:
    defn = {
        "url": "https://example.com/users/{}",
        "error_type": "message",
        "error_msg": "Not found",
        "request_method": "GET",
    }
    body = "<html>AwsWafIntegration.forceRefreshToken something</html>"
    outcome, detail = _run_probe(defn, status=200, body=body)
    assert outcome == "inconclusive"
    assert detail == "waf_blocked"


# ---------------------------------------------------------------------------
# Regex check (Sherlock uses re.search, not fullmatch)
# ---------------------------------------------------------------------------

def test_probe_illegal_regex() -> None:
    defn = {
        "url": "https://example.com/{}",
        "error_type": "status_code",
        "regex_check": r"^[A-Za-z0-9]{4,12}$",
    }
    outcome, detail = _run_probe(defn, username="Invalid User!", status=200)
    assert outcome == "illegal"
    assert detail is None


def test_probe_legal_regex_passes() -> None:
    defn = {
        "url": "https://example.com/{}",
        "error_type": "status_code",
        "regex_check": r"^[A-Za-z0-9]{4,12}$",
        "request_method": "GET",
    }
    outcome, detail = _run_probe(defn, username="alice123", status=200, body="ok")
    assert outcome == "hit"


# ---------------------------------------------------------------------------
# POST with payload interpolation
# ---------------------------------------------------------------------------

def test_probe_post_with_payload() -> None:
    async def _inner() -> None:
        seen: list[httpx.Request] = []

        class _CapturingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                seen.append(request)
                return httpx.Response(200, json={"data": {"user": {"id": 1}}}, request=request)

        defn = {
            "url": "https://example.com/users/{}",
            "url_probe": "https://graphql.example.com/",
            "error_type": "message",
            "error_msg": "errors",
            "request_method": "POST",
            "request_payload": {"query": "query($name:String){User(name:$name){id}}", "variables": {"name": "{}"}},
        }
        transport = _CapturingTransport()
        async with httpx.AsyncClient(transport=transport) as client:
            sem = asyncio.Semaphore(1)
            outcome, detail = await probe_sherlock_site(client, sem, "GraphQL", defn, "alice")

        assert len(seen) == 1
        req = seen[0]
        assert req.method == "POST"
        assert b"alice" in req.content
        assert outcome == "hit"

    asyncio.run(_inner())


# ---------------------------------------------------------------------------
# Per-site custom headers merged into request
# ---------------------------------------------------------------------------

def test_probe_per_site_headers() -> None:
    async def _inner() -> None:
        captured: dict[str, str] = {}

        class _HeaderCapture(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                captured.update(dict(request.headers))
                return httpx.Response(200, text="profile", request=request)

        defn = {
            "url": "https://api.example.com/users/{}",
            "error_type": "status_code",
            "headers": {"X-API-Version": "3", "Accept": "application/json"},
            "request_method": "GET",
        }
        async with httpx.AsyncClient(transport=_HeaderCapture()) as client:
            sem = asyncio.Semaphore(1)
            await probe_sherlock_site(client, sem, "ApiSite", defn, "alice")

        assert captured.get("x-api-version") == "3"
        assert captured.get("accept") == "application/json"
        assert "mailaccess" in captured.get("user-agent", "")

    asyncio.run(_inner())
