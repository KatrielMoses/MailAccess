"""darkeye module: HaveIBeenRansom + Breach House behind one result.

All HTTP is mocked with httpx.MockTransport; nothing here reaches the network.
Fixtures use fictional people and companies.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from backend.config import settings
from backend.core import http_client
from backend.core.phases import unavailable_reason
from backend.modules import darkeye as dk
from backend.modules import get_all_modules
from backend.modules.base import ModuleStatus

EMAIL = "bob@example.com"
HIBR_KEY = "hibr-test-key-1234"
BH_KEY = "bh-test-key-5678"
HIBR_HOST = "haveibeenransom.com"
BH_HOST = "breach.house"


class Net:
    """Collects the requests a test made and answers them through a handler."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    def to(self, host: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", None)
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", None)
    monkeypatch.setattr(http_client.rate_limiter, "_enabled", False)


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)


def install(monkeypatch, handler) -> Net:
    net = Net(handler)
    real = http_client.build_client

    def factory(**kwargs: Any):
        return real(transport=httpx.MockTransport(net), **kwargs)

    monkeypatch.setattr(dk, "build_client", factory)
    return net


def hibr_page(items: list[dict], has_next: bool = False) -> dict:
    return {"results": items, "pagination": {"current_page": 1, "has_next": has_next}}


def hibr_item(n: int = 1, **extra: Any) -> dict:
    item = {
        "id": n,
        "id_source": f"src-{n}",
        "post_title": f"Acme Corp {n}",
        "website": "acme.example",
        "group_name": "examplegroup",
        "country": "ES",
        "discovered": "2026-01-15T10:00:00",
    }
    item.update(extra)
    return item


def bh_body(**sections: Any) -> dict:
    body: dict[str, Any] = {"ransomware": [], "breaches": [], "leads": [], "stealers": []}
    body.update(sections)
    return body


def route(
    hibr: Callable[[httpx.Request], httpx.Response] | None = None,
    bh: Callable[[httpx.Request], httpx.Response] | None = None,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == HIBR_HOST and hibr:
            return hibr(request)
        if request.url.host == BH_HOST and bh:
            return bh(request)
        return httpx.Response(500, text="unrouted")

    return handler


def ok(body: Any) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(200, json=body)


def err(code: int, text: str = "") -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(code, text=text)


async def run(email: str = EMAIL):
    return await dk.DarkEyeModule().run(email)


# --- contract and key handling -------------------------------------------------


def test_module_contract_and_registration():
    cls = dk.DarkEyeModule
    assert cls.name == "darkeye"
    assert cls.requires_key is True
    assert cls.email_linked is True
    assert "darkeye" in {m.name for m in get_all_modules()}


async def test_no_keys_skips_without_any_request(monkeypatch):
    net = install(monkeypatch, route())
    result = await run()
    assert result.status is ModuleStatus.SKIPPED
    assert net.requests == []
    text = " ".join(result.errors)
    assert "DARKEYE_HIBR_API_KEY" in text and "DARKEYE_BREACHHOUSE_API_KEY" in text
    assert result.metadata["products"][dk.HIBR]["status"] == "skipped"
    assert result.metadata["products"][dk.BH]["status"] == "skipped"


@pytest.mark.parametrize("bad", ["", "   ", "two words", "key\nline", "clé-accentuée"])
async def test_unusable_keys_skip_without_request(monkeypatch, bad):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", bad)
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", bad)
    net = install(monkeypatch, route())
    result = await run()
    assert result.status is ModuleStatus.SKIPPED
    assert net.requests == []


async def test_key_with_surrounding_whitespace_is_trimmed(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", f"  {HIBR_KEY}\n")
    net = install(monkeypatch, route(hibr=ok(hibr_page([]))))
    result = await run()
    assert result.status is ModuleStatus.SUCCESS
    assert net.requests[0].headers["authorization"] == f"Bearer {HIBR_KEY}"


async def test_unusable_key_is_reported_but_other_product_still_runs(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", "bad key")
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    net = install(monkeypatch, route(bh=ok(bh_body())))
    result = await run()
    assert net.to(HIBR_HOST) == []
    assert len(net.to(BH_HOST)) == 1
    assert result.metadata["products"][dk.HIBR]["status"] == "skipped"
    assert result.status is ModuleStatus.SUCCESS


async def test_invalid_email_skips_without_request(monkeypatch, keys):
    net = install(monkeypatch, route())
    for bad in ("", "no-at-sign", "a b@example.com", "bob\n@example.com", "x" * 400 + "@a.io"):
        result = await run(bad)
        assert result.status is ModuleStatus.SKIPPED
    assert net.requests == []


def test_phase_preflight_uses_either_key(monkeypatch):
    assert unavailable_reason("darkeye", settings, EMAIL, None, set()) == "no_key"
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    assert unavailable_reason("darkeye", settings, EMAIL, None, set()) is None


# --- requests ------------------------------------------------------------------


async def test_only_hibr_key_queries_only_hibr(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    net = install(monkeypatch, route(hibr=ok(hibr_page([hibr_item()]))))
    result = await run()
    assert [r.url.host for r in net.requests] == [HIBR_HOST]
    request = net.requests[0]
    assert request.method == "GET"
    assert request.url.raw_path.decode() == "/api/metadata/email/bob%40example.com"
    assert request.headers["authorization"] == f"Bearer {HIBR_KEY}"
    assert result.status is ModuleStatus.SUCCESS
    assert result.metadata["products"][dk.BH]["status"] == "skipped"
    assert len(result.findings) == 1


async def test_only_bh_key_queries_only_bh(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    net = install(monkeypatch, route(bh=ok(bh_body())))
    result = await run()
    assert [r.url.host for r in net.requests] == [BH_HOST]
    request = net.requests[0]
    assert request.url.path == "/api/v1/search"
    assert dict(request.url.params) == {"q": EMAIL, "limit": str(dk._BH_LIMIT)}
    assert request.headers["authorization"] == f"Bearer {BH_KEY}"
    assert result.status is ModuleStatus.SUCCESS
    assert result.findings == []


async def test_each_key_goes_only_to_its_own_host(monkeypatch, keys):
    net = install(monkeypatch, route(hibr=ok(hibr_page([])), bh=ok(bh_body())))
    await run()
    for request in net.to(HIBR_HOST):
        assert request.headers["authorization"] == f"Bearer {HIBR_KEY}"
        assert BH_KEY not in str(request.headers) and BH_KEY not in str(request.url)
    for request in net.to(BH_HOST):
        assert request.headers["authorization"] == f"Bearer {BH_KEY}"
        assert HIBR_KEY not in str(request.headers) and HIBR_KEY not in str(request.url)


async def test_email_is_quoted_and_domain_is_never_a_pivot(monkeypatch, keys):
    email = "bob+x@example.com"
    net = install(monkeypatch, route(hibr=ok(hibr_page([])), bh=ok(bh_body())))
    await run(email)
    hibr_req, bh_req = net.to(HIBR_HOST)[0], net.to(BH_HOST)[0]
    assert hibr_req.url.raw_path.decode() == "/api/metadata/email/bob%2Bx%40example.com"
    assert dict(bh_req.url.params)["q"] == email
    for request in net.requests:
        assert "/domain/" not in request.url.path
        assert "/username/" not in request.url.path
        assert dict(request.url.params).get("q") in (None, email)


async def test_redirects_are_not_followed(monkeypatch, keys):
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    net = install(monkeypatch, redirect)
    result = await run()
    assert {r.url.host for r in net.requests} == {HIBR_HOST, BH_HOST}
    assert result.status is ModuleStatus.FAILED
    assert any("HTTP 302" in e for e in result.errors)


# --- HaveIBeenRansom -----------------------------------------------------------


async def test_hibr_findings_shape_and_categories(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    items = [
        hibr_item(1, leak_type="ransomware_leak"),
        hibr_item(2, leak_type="traditional_breach"),
        hibr_item(3),
    ]
    install(monkeypatch, route(hibr=ok(hibr_page(items))))
    result = await run()
    assert [f["category"] for f in result.findings] == ["ransomware", "breach", "leak"]
    finding = result.findings[0]
    assert finding["product"] == "haveibeenransom"
    assert finding["platform"] == "haveibeenransom"
    assert finding["source"] == "darkeye"
    assert finding["email_linked"] is True
    assert finding["metadata"]["title"] == "Acme Corp 1"
    assert finding["metadata"]["website"] == "acme.example"
    assert finding["metadata"]["group"] == "examplegroup"
    assert finding["metadata"]["country"] == "ES"
    assert finding["metadata"]["discovered"] == "2026-01-15"
    assert finding["metadata"]["record_id"] == "src-1"
    assert result.metadata["records_by_category"] == {"ransomware": 1, "breach": 1, "leak": 1}


async def test_hibr_accepts_sources_with_top_level_has_next(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    install(monkeypatch, route(hibr=ok({"sources": [hibr_item()], "has_next": False})))
    result = await run()
    assert result.status is ModuleStatus.SUCCESS
    assert len(result.findings) == 1


async def test_hibr_reads_following_pages(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)

    def pages(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/2"):
            return httpx.Response(200, json=hibr_page([hibr_item(2)], has_next=False))
        return httpx.Response(200, json=hibr_page([hibr_item(1)], has_next=True))

    net = install(monkeypatch, route(hibr=pages))
    result = await run()
    assert [r.url.raw_path.decode() for r in net.requests] == [
        "/api/metadata/email/bob%40example.com",
        "/api/metadata/email/bob%40example.com/2",
    ]
    assert result.status is ModuleStatus.SUCCESS
    assert len(result.findings) == 2


async def test_hibr_page_limit_gives_partial(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    counter = iter(range(1, 100))

    def endless(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=hibr_page([hibr_item(next(counter))], has_next=True))

    net = install(monkeypatch, route(hibr=endless))
    result = await run()
    assert len(net.requests) == dk._MAX_PAGES == 5
    assert result.status is ModuleStatus.PARTIAL
    assert len(result.findings) == 5
    assert any("limit" in e for e in result.errors)


async def test_hibr_later_page_failure_keeps_earlier_records(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)

    def pages(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/2"):
            return httpx.Response(500)
        return httpx.Response(200, json=hibr_page([hibr_item(1)], has_next=True))

    install(monkeypatch, route(hibr=pages))
    result = await run()
    assert len(result.findings) == 1
    # the only queried product errored but still produced a record: partial, not failed
    assert result.status is ModuleStatus.PARTIAL
    assert any("HaveIBeenRansom: HTTP 500" in e for e in result.errors)


async def test_hibr_duplicate_records_are_collapsed(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    install(monkeypatch, route(hibr=ok(hibr_page([hibr_item(1), hibr_item(1)]))))
    result = await run()
    assert len(result.findings) == 1


async def test_hibr_record_cap(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    items = [hibr_item(n) for n in range(dk._MAX_RECORDS + 5)]
    install(monkeypatch, route(hibr=ok(hibr_page(items))))
    result = await run()
    assert len(result.findings) == dk._MAX_RECORDS
    assert result.status is ModuleStatus.PARTIAL


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"results": []},  # no has_next anywhere
        {"results": [], "has_next": "yes"},
        {"results": "nope", "has_next": False},
        {"results": [1], "has_next": False},
        {"results": [{"unrelated": "x"}], "has_next": False},  # record with no id/title/site
        {"success": False, "results": [], "has_next": False},
        {"error": "boom", "results": [], "has_next": False},
    ],
)
async def test_hibr_malformed_responses_are_errors_not_clean(monkeypatch, body):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    install(monkeypatch, route(hibr=ok(body)))
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert result.findings == []
    assert result.errors


async def test_hibr_no_result_is_a_clean_success(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    install(monkeypatch, route(hibr=ok(hibr_page([]))))
    result = await run()
    assert result.status is ModuleStatus.SUCCESS
    assert result.findings == [] and result.errors == []


# --- Breach House --------------------------------------------------------------


async def test_bh_keeps_only_exact_address_matches(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    body = bh_body(
        ransomware=[
            {"id": 1, "post_title": "Contact bob@example.com for details"},
            {"id": 2, "post_title": "example.com"},  # the domain alone is not a match
            {"id": 3, "post_title": "abob@example.com"},  # longer local part
            {"id": 4, "post_title": "bob@example.com.au"},  # longer domain
            {"id": 5, "post_title": "bob@example.comx"},
            {"id": 6, "post_title": "someone-bob@example.com"},
            {"id": 7, "post_title": "bob@example.com2"},
        ],
        breaches=[{"id": 8, "name": "Leak", "meta_description": "has BOB@EXAMPLE.COM inside"}],
        leads=[{"id": 9, "website": "bob@example.com"}],
        stealers=[{"id": 10, "description": "log (bob@example.com)"}],
    )
    install(monkeypatch, route(bh=ok(body)))
    result = await run()
    got = [(f["category"], f["metadata"]["record_id"]) for f in result.findings]
    assert got == [("ransomware", "1"), ("breach", "8"), ("lead", "9"), ("stealer", "10")]
    assert all(f["product"] == "breach_house" for f in result.findings)
    assert result.findings[2]["severity"] == "low"
    assert result.findings[0]["severity"] == "medium"


async def test_bh_address_beyond_the_display_cap_still_matches(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    long_text = ("lorem " * 100) + EMAIL
    install(monkeypatch, route(bh=ok(bh_body(breaches=[{"id": 1, "description": long_text}]))))
    result = await run()
    assert len(result.findings) == 1


async def test_bh_total_above_returned_gives_partial(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    body = bh_body(breaches={"total": 40, "results": [{"id": 1, "post_title": EMAIL}]})
    install(monkeypatch, route(bh=ok(body)))
    result = await run()
    assert result.status is ModuleStatus.PARTIAL
    assert len(result.findings) == 1


async def test_bh_full_section_without_total_gives_partial(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    filler = [{"id": n, "post_title": "other"} for n in range(dk._BH_LIMIT)]
    install(monkeypatch, route(bh=ok(bh_body(leads=filler))))
    result = await run()
    assert result.status is ModuleStatus.PARTIAL


async def test_bh_record_cap(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    monkeypatch.setattr(dk, "_MAX_RECORDS", 2)
    items = [{"id": n, "post_title": EMAIL} for n in range(3)]
    install(monkeypatch, route(bh=ok(bh_body(breaches=items))))
    result = await run()
    assert len(result.findings) == 2
    assert result.status is ModuleStatus.PARTIAL


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"ransomware": [], "breaches": [], "leads": []},  # a source is missing
        bh_body(stealers="nope"),
        bh_body(leads=[1]),
        {"error": "invalid_token"},
    ],
)
async def test_bh_malformed_responses_are_errors_not_clean(monkeypatch, body):
    monkeypatch.setattr(settings, "darkeye_breachhouse_api_key", BH_KEY)
    install(monkeypatch, route(bh=ok(body)))
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert result.errors


# --- status mapping ------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "fragment"),
    [
        (401, "HTTP 401 (check the API key"),
        (403, "HTTP 403 (check the API key"),
        (429, "daily limit"),
        (404, "HTTP 404"),
        (500, "HTTP 500"),
        (302, "HTTP 302"),
    ],
)
async def test_http_errors_fail_the_only_queried_product(monkeypatch, code, fragment):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    install(monkeypatch, route(hibr=err(code)))
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert fragment in result.errors[0]


async def test_invalid_json_is_an_error(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    install(monkeypatch, route(hibr=err(200, "<html>not json</html>")))
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert "invalid JSON" in result.errors[0]


async def test_one_product_failing_gives_partial_with_the_other_findings(monkeypatch, keys):
    net = install(
        monkeypatch,
        route(hibr=err(429), bh=ok(bh_body(stealers=[{"id": 1, "post_title": EMAIL}]))),
    )
    result = await run()
    assert len(net.requests) == 2
    assert result.status is ModuleStatus.PARTIAL
    assert [f["product"] for f in result.findings] == ["breach_house"]
    assert result.metadata["products"][dk.HIBR]["status"] == "error"
    assert result.metadata["products"][dk.BH]["status"] == "ok"


async def test_both_products_failing_is_failed(monkeypatch, keys):
    install(monkeypatch, route(hibr=err(500), bh=err(401)))
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert len(result.errors) == 2


async def test_both_products_clean_is_success_with_one_result(monkeypatch, keys):
    install(monkeypatch, route(hibr=ok(hibr_page([hibr_item()])), bh=ok(bh_body())))
    result = await run()
    assert result.status is ModuleStatus.SUCCESS
    assert result.metadata["products"][dk.HIBR] == {
        "status": "ok",
        "records": 1,
        "truncated": False,
    }
    assert "darkeye.io" in result.metadata["source"]


async def test_both_products_contribute_to_one_result(monkeypatch, keys):
    bh = ok(bh_body(ransomware=[{"id": 7, "post_title": f"leak of {EMAIL}"}]))
    install(monkeypatch, route(hibr=ok(hibr_page([hibr_item()])), bh=bh))
    result = await run()
    assert {f["product"] for f in result.findings} == {"haveibeenransom", "breach_house"}
    assert all({"product", "category"} <= set(f) for f in result.findings)


# --- failure handling ----------------------------------------------------------


async def test_network_errors_do_not_leak_the_key(monkeypatch, keys):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect with {request.headers['authorization']}")

    install(monkeypatch, boom)
    result = await run()
    assert result.status is ModuleStatus.FAILED
    text = json.dumps(result.errors) + json.dumps(result.metadata)
    assert HIBR_KEY not in text and BH_KEY not in text
    assert "ConnectError" in text


async def test_timeout_is_an_error(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    install(monkeypatch, route(hibr=slow))
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert "timed out" in result.errors[0]


async def test_product_deadline_keeps_records_read_so_far(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    monkeypatch.setattr(dk, "_PRODUCT_DEADLINE", 0.2)
    state = {"calls": 0}

    class SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            if state["calls"] == 1:
                return httpx.Response(200, json=hibr_page([hibr_item(1)], has_next=True))
            await asyncio.sleep(5)
            return httpx.Response(200, json=hibr_page([], has_next=False))

    real = http_client.build_client
    monkeypatch.setattr(dk, "build_client", lambda **kw: real(transport=SlowTransport(), **kw))
    result = await run()
    assert result.status is ModuleStatus.PARTIAL
    assert len(result.findings) == 1
    assert any("timed out" in e for e in result.errors)


async def test_run_never_raises(monkeypatch, keys):
    def explode(**kwargs: Any):
        raise RuntimeError(f"client broke {HIBR_KEY}")

    monkeypatch.setattr(dk, "build_client", explode)
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert HIBR_KEY not in json.dumps(result.errors)

    monkeypatch.setattr(dk, "_valid_email", lambda email: 1 / 0)
    result = await run()
    assert result.status is ModuleStatus.FAILED
    assert "ZeroDivisionError" in result.errors[0]


# --- what is (not) read --------------------------------------------------------


async def test_no_credentials_or_unlisted_fields_reach_the_result(monkeypatch, keys):
    secret = "hunter2-SECRET-VALUE"
    leaky = {
        "password": secret,
        "credentials": [{"url": "https://x.example", "user": EMAIL, "pass": secret}],
        "Identities Found": [secret],
        "post_url": "http://leaksite.onion/x",
        "meta_description": secret,
    }
    install(
        monkeypatch,
        route(
            hibr=ok(hibr_page([hibr_item(1, **leaky)])),
            bh=ok(bh_body(stealers=[{"id": 2, "post_title": EMAIL, **leaky}])),
        ),
    )
    result = await run()
    assert len(result.findings) == 2
    dump = json.dumps([result.findings, result.metadata, result.errors])
    assert secret not in dump
    assert "onion" not in dump


async def test_error_text_never_echoes_the_response_body(monkeypatch, keys):
    install(monkeypatch, route(hibr=err(500, f"{HIBR_KEY} {BH_KEY}"), bh=err(500, BH_KEY)))
    result = await run()
    dump = json.dumps([result.errors, result.metadata])
    assert HIBR_KEY not in dump and BH_KEY not in dump


async def test_text_is_sanitised_and_truncated(monkeypatch):
    monkeypatch.setattr(settings, "darkeye_hibr_api_key", HIBR_KEY)
    item = hibr_item(
        1,
        post_title="Acme\x1b[31m RED\x00\n\tCorp " + "x" * 600,
        website={"nested": "object"},
        group_name=True,
        country=["ES"],
    )
    install(monkeypatch, route(hibr=ok(hibr_page([item]))))
    result = await run()
    meta = result.findings[0]["metadata"]
    assert "\x1b" not in meta["title"] and "\x00" not in meta["title"]
    assert "\n" not in meta["title"] and "\t" not in meta["title"]
    assert len(meta["title"]) == dk._MAX_TEXT
    assert "website" not in meta and "group" not in meta and "country" not in meta
