"""Phase JEV-4 — reach and selection: platform_select, query_generate.

Every JEV call runs through the real seam against an httpx.MockTransport fake model
routed by task. Network-free. Covers keyless byte-identity, the equal-count guard
(selection length <= cap, every id in the eligible set), the filter guard (a
non-eligible id from the model is dropped at the boundary), and the query-bound
guard (count/length capped, out-of-scope queries rejected, DEFER -> templates).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import jev, jev_reach
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.reach import PLATFORM_SELECT, QUERY_GENERATE


class FakeJev:
    _MARKERS = {
        PLATFORM_SELECT: "which online platforms a specific subject",
        QUERY_GENERATE: "focused web-search queries",
    }

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            PLATFORM_SELECT: answers.get("platform"),
            QUERY_GENERATE: answers.get("query"),
        }
        self.calls: dict[str, list[dict[str, Any]]] = {t: [] for t in self.answers}

    def _task(self, system: str) -> str:
        for task, marker in self._MARKERS.items():
            if marker in system:
                return task
        raise AssertionError("unrouted JEV prompt")

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        task = self._task(body["messages"][0]["content"])
        self.calls[task].append(json.loads(body["messages"][1]["content"]))
        answer = self.answers[task]
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            answer = answer(self.calls[task][-1])
        if answer is None:
            return httpx.Response(500, content=b"no answer")
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    def n(self, task: str) -> int:
        return len(self.calls[task])


@pytest.fixture(autouse=True)
def _jev_on(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    s = config_mod.settings
    for name, value in {
        "jev_provider": "openai", "jev_enabled": True,
        "jev_api_key": "test-key-not-real", "jev_force_off": False,
        "jev_base_url": "https://jev.invalid/v1", "jev_model": "jev-test",
        "jev_timeout_ms": 2000, "jev_max_concurrency": 4, "jev_cache_ttl_seconds": 3600,
        "jev_cache_path": str(tmp_path / "jev-cache"), "jev_cache_refresh": False,
        "jev_min_confidence": 0.7, "jev_run_ceiling_seconds": 20.0, "jev_metrics_dir": "",
        "jev_breaker_failure_threshold": 3, "jev_breaker_cooldown_seconds": 120.0,
    }.items():
        monkeypatch.setattr(s, name, value)
    jev_metrics.reset()
    jev_breaker.reset()


def _install(monkeypatch: pytest.MonkeyPatch, fake: FakeJev) -> FakeJev:
    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(fake))
    return fake


def _no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_api_key", None)

    async def _boom(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("jev.judge called on a keyless install")

    monkeypatch.setattr(jev, "judge", _boom)


_ELIGIBLE = ["github", "reddit", "mastodon", "weibo", "vk"]
_CANDS = [{"id": pid, "category": "social", "region": None, "rank": i}
          for i, pid in enumerate(_ELIGIBLE)]


# ---------------------------------------------------------------------------
# Task 1 — platform_select
# ---------------------------------------------------------------------------
async def test_platform_select_orders_and_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(platform={
        "ordered_platform_ids": ["mastodon", "github", "reddit"], "confidence": 0.9}))
    chosen = await jev_reach.select_platforms(
        eligible_ids=_ELIGIBLE, candidates=_CANDS, wave_cap=2, email_localpart="alice")
    assert chosen == ["mastodon", "github"]  # ordered, capped to 2


async def test_platform_select_drops_non_eligible_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    # The model returns a disabled/invented id + a duplicate; both are dropped.
    _install(monkeypatch, FakeJev(platform={
        "ordered_platform_ids": ["evilcorp", "github", "github", "reddit"], "confidence": 0.9}))
    chosen = await jev_reach.select_platforms(
        eligible_ids=_ELIGIBLE, candidates=_CANDS, wave_cap=5, email_localpart="alice")
    assert chosen == ["github", "reddit"]  # evilcorp not in eligible; dedup applied
    assert all(pid in set(_ELIGIBLE) for pid in chosen)


@pytest.mark.parametrize("answer", [
    {"ordered_platform_ids": ["github"], "confidence": 0.5},   # low conf → DEFER
    {"ordered_platform_ids": ["evilcorp"], "confidence": 0.9},  # nothing eligible → None
    {"ordered_platform_ids": "notalist", "confidence": 0.9},    # schema fail
    httpx.ConnectError("down"),
])
async def test_platform_select_defers(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(platform=answer))
    assert await jev_reach.select_platforms(
        eligible_ids=_ELIGIBLE, candidates=_CANDS, wave_cap=3, email_localpart="a") is None


async def test_platform_select_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_reach.select_platforms(
        eligible_ids=_ELIGIBLE, candidates=_CANDS, wave_cap=3) is None


# ---------------------------------------------------------------------------
# Task 2 — query_generate
# ---------------------------------------------------------------------------
async def test_query_generate_scoped_and_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(query={"queries": [
        '"@acme.com" filetype:pdf',
        'site:linkedin.com/in/ "acme.com"',
        'unrelated third party query',   # no anchor → dropped
        '"@acme.com" resume',
    ], "confidence": 0.9}))
    out = await jev_reach.generate_queries(engine="ddg", max_queries=2, domain="acme.com")
    assert out == ['"@acme.com" filetype:pdf', 'site:linkedin.com/in/ "acme.com"']  # capped, scoped


async def test_query_generate_rejects_all_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(query={"queries": [
        "cats", "totally unrelated", "other-company.com leads"], "confidence": 0.9}))
    assert await jev_reach.generate_queries(
        engine="ddg", max_queries=5, domain="acme.com") is None


async def test_query_generate_drops_over_length(monkeypatch: pytest.MonkeyPatch) -> None:
    long_q = '"@acme.com" ' + "x" * 400   # over the 300-char op cap → dropped
    _install(monkeypatch, FakeJev(query={"queries": [long_q, '"@acme.com" ok'],
                                         "confidence": 0.9}))
    out = await jev_reach.generate_queries(engine="ddg", max_queries=3, domain="acme.com")
    assert out == ['"@acme.com" ok']  # the over-length query is dropped, the rest kept
    assert all(len(q) <= 300 for q in out)


@pytest.mark.parametrize("answer", [
    {"queries": ['"@acme.com"'], "confidence": 0.5},  # low conf → DEFER
    {"queries": [], "confidence": 0.9},                # empty → None
    httpx.ConnectError("down"),
])
async def test_query_generate_defers(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(query=answer))
    assert await jev_reach.generate_queries(
        engine="ddg", max_queries=3, domain="acme.com") is None


async def test_query_generate_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_reach.generate_queries(engine="ddg", max_queries=3, domain="acme.com") is None


# ---------------------------------------------------------------------------
# Integration: username wave selection preserves count
# ---------------------------------------------------------------------------
async def test_wave_select_equal_count_and_eligible(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules import username_platforms as up

    # 4 high-precision platforms (all ranked → high precision), cap 2 → JEV picks 2.
    def defn(rank: int) -> dict[str, Any]:
        return {"alexaRank": rank, "check_type": "username-url", "tags": ["social"]}

    queue = [(name, defn(i), name) for i, name in enumerate(["github", "reddit", "vk", "weibo"])]
    _install(monkeypatch, FakeJev(platform={
        "ordered_platform_ids": ["weibo", "vk"], "confidence": 0.9}))

    result, assisted = await up._jev_select_wave1(queue, cap=2, email="li@example.cn")
    kept = {name for name, _d, _v in result}
    assert assisted is True
    assert kept == {"weibo", "vk"} and len(kept) == 2  # equal to cap, JEV's choice


async def test_wave_select_tops_up_to_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules import username_platforms as up

    def defn(rank: int) -> dict[str, Any]:
        return {"alexaRank": rank, "check_type": "username-url", "tags": ["social"]}

    queue = [(name, defn(i), name) for i, name in enumerate(["github", "reddit", "vk", "weibo"])]
    # JEV returns only ONE id; the wave must still fill to cap=3 via static rank.
    _install(monkeypatch, FakeJev(platform={"ordered_platform_ids": ["weibo"], "confidence": 0.9}))
    result, assisted = await up._jev_select_wave1(queue, cap=3, email="a@b.com")
    kept = {name for name, _d, _v in result}
    assert assisted is True and len(kept) == 3 and "weibo" in kept


async def test_wave_select_no_jev_when_cap_not_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules import username_platforms as up

    def defn(rank: int) -> dict[str, Any]:
        return {"alexaRank": rank, "check_type": "username-url", "tags": ["social"]}

    queue = [(name, defn(i), name) for i, name in enumerate(["github", "reddit"])]
    fake = _install(monkeypatch, FakeJev(platform={
        "ordered_platform_ids": ["reddit"], "confidence": 0.9}))
    # cap 5 >= 2 distinct → every eligible platform is probed anyway; JEV not called.
    result, assisted = await up._jev_select_wave1(queue, cap=5, email="a@b.com")
    assert assisted is False and fake.n(PLATFORM_SELECT) == 0
    assert {name for name, _d, _v in result} == {"github", "reddit"}


async def test_wave_select_keyless_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules import username_platforms as up

    _no_key(monkeypatch)

    def defn(rank: int) -> dict[str, Any]:
        return {"alexaRank": rank, "check_type": "username-url", "tags": ["social"]}

    queue = [(name, defn(i), name) for i, name in enumerate(["github", "reddit", "vk", "weibo"])]
    result, assisted = await up._jev_select_wave1(queue, cap=2, email="a@b.com")
    baseline = up._cap_queue_by_rank(up._drop_low_precision(queue), 2)
    assert assisted is False and result == baseline


# ---------------------------------------------------------------------------
# Integration: email_search_dork query swap
# ---------------------------------------------------------------------------
async def test_email_dork_jev_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules.email_search_dork import EmailSearchDorkModule

    _install(monkeypatch, FakeJev(query={"queries": [
        '"@acme.com" (resume OR cv)', 'site:acme.com "@acme.com"'], "confidence": 0.9}))
    mod = EmailSearchDorkModule()
    out = await mod._jev_queries("acme.com", cap=5)
    assert out is not None and len(out) == 2
    assert out[0].query == '"@acme.com" (resume OR cv)'
    assert all(q.description == "jev_generated" for q in out)


async def test_email_dork_jev_queries_keyless(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules.email_search_dork import EmailSearchDorkModule

    _no_key(monkeypatch)
    assert await EmailSearchDorkModule()._jev_queries("acme.com", cap=5) is None
