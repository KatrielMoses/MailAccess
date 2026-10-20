from __future__ import annotations

import asyncio
import json

import httpx

from backend.core import host_politeness
from backend.core.probe_detector import (
    detect_hit,
    is_non_discriminating_url,
    probe_response_snapshot,
)
from backend.core.site_validation import verdict
from backend.core.waf_fingerprints import is_challenge_response


def _json_defn(**extra):
    return {"checkType": "json", **extra}


def test_json_check_found_missing_and_inconclusive() -> None:
    defn = _json_defn(
        jsonFound=[{"path": "id"}],
        jsonMissing=[{"path": "error.type", "equals": "not_found"}],
        missingStatus=[404],
    )
    assert detect_hit(defn, json.dumps({"id": "x1", "country": "IN"}), 200, "") == "hit"
    assert detect_hit(defn, json.dumps({"error": {"type": "not_found"}}), 404, "") == "miss"
    assert detect_hit(defn, "<html>not json</html>", 404, "") == "miss"  # missingStatus
    assert detect_hit(defn, "<html>not json</html>", 200, "") == "inconclusive"
    assert detect_hit(defn, json.dumps({"other": 1}), 200, "") == "inconclusive"


def test_json_conditions_equals_null_nonempty_and_list_paths() -> None:
    leetcode = _json_defn(
        jsonFound=[{"path": "data.matchedUser.username"}],
        jsonMissing=[{"path": "data.matchedUser", "equals": None}],
    )
    assert detect_hit(leetcode, '{"data":{"matchedUser":{"username":"a"}}}', 200, "") == "hit"
    assert detect_hit(leetcode, '{"data":{"matchedUser":null}}', 200, "") == "miss"
    freelancer = _json_defn(
        jsonFound=[{"path": "result.users", "nonEmpty": True}],
        jsonMissing=[{"path": "result.users", "nonEmpty": False}],
    )
    assert detect_hit(freelancer, '{"result":{"users":{"1":{}}}}', 200, "") == "hit"
    assert detect_hit(freelancer, '{"result":{"users":{}}}', 200, "") == "miss"
    listy = _json_defn(jsonFound=[{"path": "items.0.name", "equals": "a"}])
    assert detect_hit(listy, '{"items":[{"name":"a"}]}', 200, "") == "hit"


def test_json_check_still_respects_rate_limit_gate() -> None:
    defn = _json_defn(jsonFound=[{"path": "taken", "equals": True}])
    assert detect_hit(defn, '{"taken":true}', 429, "") == "inconclusive"


def test_strict_message_found_marker_wins_and_neither_is_inconclusive() -> None:
    defn = {
        "checkType": "message",
        "messageStrict": True,
        "presenseStrs": ["(@someone)"],
        "absenceStrs": ["<title>Instagram</title>"],
    }
    found = "<title>Instagram (&#064;someone) x</title> ... <title>Instagram</title>"
    assert detect_hit(defn, found, 200, "") == "hit"
    assert detect_hit(defn, "<title>Instagram</title>", 200, "") == "miss"
    assert detect_hit(defn, "<title>Login</title>", 200, "") == "inconclusive"


def test_challenge_pages_are_detected() -> None:
    assert is_challenge_response(httpx.Headers({"x-vercel-mitigated": "challenge"}), "")
    assert is_challenge_response(httpx.Headers({"cf-mitigated": "challenge"}), "")
    assert is_challenge_response(httpx.Headers(), "<html><title>Just a moment...</title>")
    assert is_challenge_response(httpx.Headers(), "<head><title>Client Challenge</title>")
    assert not is_challenge_response(httpx.Headers(), "<title>Profile</title>")


def test_query_keys_are_matched_exactly() -> None:
    assert not is_non_discriminating_url("https://codeforces.com/api/user.info?handles=tourist")
    assert is_non_discriminating_url("https://x.example/members?s=tourist")
    assert is_non_discriminating_url("https://x.example/?q=tourist")


def test_snapshot_keeps_json_or_html_head() -> None:
    req = httpx.Request("GET", "https://api.example/u/a")
    resp = httpx.Response(200, headers={"content-type": "application/json"}, request=req,
                          text='{"id":"a","country":"IN"}')
    snap = probe_response_snapshot(resp, resp.text)
    assert snap["json"] == {"id": "a", "country": "IN"} and snap["status"] == 200
    html_resp = httpx.Response(200, headers={"content-type": "text/html"}, request=req,
                               text="<html><head><meta property='og:title' content='A'></head><body>x</body>")
    snap = probe_response_snapshot(html_resp, html_resp.text)
    assert snap["text"].endswith("</head>") and "body" not in snap["text"]


def test_validation_verdicts() -> None:
    ok = {"claimed": {"outcome": "hit"}, "unclaimed": {"outcome": "miss"}}
    flaky = {"claimed": {"outcome": "inconclusive"}, "unclaimed": {"outcome": "miss"}}
    always = {"claimed": {"outcome": "hit"}, "unclaimed": {"outcome": "hit"}}
    stale = {"claimed": {"outcome": "miss"}, "unclaimed": {"outcome": "miss"}}
    assert verdict([ok, flaky]) == "pass"
    assert verdict([flaky, flaky]) == "fail"
    assert verdict([ok, always]) == "alwaysHit"
    assert verdict([ok, stale]) == "fail"
    assert verdict([{"claimed": {"outcome": "untested"}, "unclaimed": {"outcome": "miss"}}]) == "untested"
    # a control hit is decisive even without a known-found handle (247CTF)
    assert verdict([{"claimed": {"outcome": "untested"}, "unclaimed": {"outcome": "hit"}}]) == "alwaysHit"


def test_one_request_in_flight_per_host_and_retry_after_once() -> None:
    from backend.core.http_client import build_client

    state = {"in_flight": 0, "peak": 0, "calls": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        state["in_flight"] += 1
        state["peak"] = max(state["peak"], state["in_flight"])
        await asyncio.sleep(0.01)
        state["in_flight"] -= 1
        if request.url.path == "/limited" and state["calls"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, text="ok")

    async def main() -> list[int]:
        host_politeness.activate()
        async with build_client(transport=httpx.MockTransport(handler)) as client:
            first = await client.get("https://a.example/limited")
            rest = await asyncio.gather(*(client.get(f"https://a.example/{i}") for i in range(5)))
        return [first.status_code, *(r.status_code for r in rest)]

    codes = asyncio.run(main())
    assert codes == [200] * 6  # the 429 with Retry-After 0 was retried once
    assert state["peak"] == 1


def test_retry_after_only_for_short_numeric_waits() -> None:
    assert host_politeness.retry_after_seconds(httpx.Headers({"retry-after": "3"})) == 3.0
    assert host_politeness.retry_after_seconds(httpx.Headers({"retry-after": "30"})) is None
    assert host_politeness.retry_after_seconds(
        httpx.Headers({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"})
    ) is None
