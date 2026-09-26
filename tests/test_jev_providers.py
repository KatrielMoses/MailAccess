"""Phase JEV-0.2 — provider adapters + activation.

Both adapters mocked via httpx.MockTransport. Covers: chat JSON parse (openai),
typed-decision schema→questions translation + nested-answer mapping (shared by the
local ``ollaya`` and hosted ``jev`` / TypeSafe System One providers), provider
routing, every DEFER path (no provider / not enabled / unreachable /
model-not-loaded / auth / credits / circuit-open), the legacy key shortcut, and the
force-off override.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import jev
from backend.core.jev import adapters, breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.demo import TASK_NAME

DEMO = TASK_NAME


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    s = config_mod.settings
    for name, value in {
        "jev_provider": "", "jev_enabled": False, "jev_api_key": None,
        "jev_force_off": False, "jev_base_url": "", "jev_model": "",
        "jev_timeout_ms": 2000, "jev_max_concurrency": 4, "jev_cache_ttl_seconds": 3600,
        "jev_cache_path": str(tmp_path / "cache"), "jev_cache_refresh": False,
        "jev_min_confidence": 0.7, "jev_run_ceiling_seconds": 20.0, "jev_metrics_dir": "",
        "jev_breaker_failure_threshold": 3, "jev_breaker_cooldown_seconds": 120.0,
    }.items():
        monkeypatch.setattr(s, name, value)
    monkeypatch.setattr(jev_client, "_TRANSPORT", None)
    jev_metrics.reset()
    breaker.reset()


def _set(monkeypatch: pytest.MonkeyPatch, **kw: Any) -> None:
    for k, v in kw.items():
        monkeypatch.setattr(config_mod.settings, k, v)


def _transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(handler))


def _defers(reason: str) -> int:
    return jev_metrics.snapshot().get(DEMO, {}).get("defer_reasons", {}).get(reason, 0)


# ---------------------------------------------------------------------------
# Activation
# ---------------------------------------------------------------------------
async def test_no_provider_defers_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("network touched with no provider")

    monkeypatch.setattr(jev_client.httpx, "AsyncClient", _boom)
    assert jev.is_active() is False
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("no_provider") == 1


async def test_configured_but_not_enabled_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=False,
         jev_base_url="http://localhost:11435", jev_model="m")
    assert jev.is_active() is False
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("not_enabled") == 1


async def test_force_off_overrides_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True, jev_force_off=True,
         jev_base_url="http://localhost:11435", jev_model="m")
    assert jev.is_active() is False
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("forced_off") == 1


def test_legacy_key_shortcut_is_active(monkeypatch: pytest.MonkeyPatch) -> None:
    # A bare JEV_API_KEY with no explicit provider = enabled hosted jev (JEV-0.1 compat).
    _set(monkeypatch, jev_api_key="k", jev_base_url="https://jev/v1", jev_model="m")
    prof = adapters.resolve_profile(config_mod.settings)
    assert prof is not None and prof.provider == "jev"
    assert adapters.is_enabled(config_mod.settings) is True
    assert jev.is_active() is True


def test_config_ok_rules() -> None:
    assert adapters.Profile("jev", "https://j/v1", "m", "k").config_ok() is True
    assert adapters.Profile("jev", "https://j/v1", "m", "").config_ok() is False  # jev needs key
    assert adapters.Profile("openai", "http://localhost:8080/v1", "m", "").config_ok() is True
    assert adapters.Profile("ollaya", "http://localhost:11435", "m", "").config_ok() is True
    assert adapters.Profile("ollaya", "", "m", "").config_ok() is False


# ---------------------------------------------------------------------------
# Chat adapter (openai-compatible)
# ---------------------------------------------------------------------------
def _chat_ok(content: dict[str, Any]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        return httpx.Response(200, json={"choices": [{"message": {
            "content": json.dumps(content)}}]})
    return handler


async def test_chat_provider_returns_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="openai", jev_enabled=True,
         jev_base_url="http://localhost:8080/v1", jev_model="local")
    _transport(monkeypatch, _chat_ok({"is_personal_name": True, "confidence": 0.9}))
    verdict = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert isinstance(verdict, jev.Verdict) and verdict.output.is_personal_name is True


async def test_chat_local_unreachable_defers_and_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="openai", jev_enabled=True,
         jev_base_url="http://localhost:8080/v1", jev_model="local",
         jev_breaker_failure_threshold=2)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    _transport(monkeypatch, refused)
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("provider_unreachable") == 1
    assert await jev.judge(DEMO, {"text": "Grace Hopper"}) is jev.DEFER  # 2nd trip → open
    assert breaker.snapshot()["state"] == "open"


async def test_jev_credit_failure_trips_breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    # jev is a typed-decisions provider (System One): it routes to /v1/systemone and
    # signals credit exhaustion with 402 payment-required (a hard breaker trip).
    _set(monkeypatch, jev_provider="jev", jev_enabled=True,
         jev_base_url="https://api.typesafe.ai", jev_model="jev-latest", jev_api_key="k")
    paths: list = []

    def quota(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(402, json={"detail": "out of credits"})

    _transport(monkeypatch, quota)
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert paths[0] == "/v1/systemone"  # typed endpoint, not /chat/completions
    assert _defers("credits_exhausted") == 1 and breaker.snapshot()["state"] == "open"


# ---------------------------------------------------------------------------
# Typed-decision adapter (ollaya / jev — System One protocol)
# ---------------------------------------------------------------------------
def _ollaya(status: int = 200, body: Any = None, capture: list | None = None,
            exc: Exception | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if exc is not None:
            raise exc
        if capture is not None:
            capture.append((request.url.path, json.loads(request.content)))
        return httpx.Response(status, json=body if body is not None else {})
    return handler


async def test_ollaya_routes_to_systemone_and_maps_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    captured: list = []
    _transport(monkeypatch, _ollaya(
        body={"answers": {"is_personal_name": True}, "confidence": 0.95}, capture=captured))
    verdict = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert isinstance(verdict, jev.Verdict) and verdict.output.is_personal_name is True
    path, sent = captured[0]
    assert path == "/v1/systemone"
    assert sent["model"] == "llama3" and sent["state"]["text"] == "Ada Lovelace"
    # A boolean field is a yes/no probability question — System One ``noul``.
    assert sent["questions"]["is_personal_name"]["type"] == "noul"
    assert "instructions" in sent["questions"]["is_personal_name"]


async def test_ollaya_choice_question_for_enum(monkeypatch: pytest.MonkeyPatch) -> None:
    # A Literal-output task translates to a choice question with criteria.
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    captured: list = []
    _transport(monkeypatch, _ollaya(
        body={"same_person": "no", "confidence": 0.95}, capture=captured))
    verdict = await jev.judge("identity.same_person", {
        "a": {"platform": "reddit"}, "b": {"platform": "mastodon"},
        "avatar_match": False, "heuristic_signals": [],
    })
    assert isinstance(verdict, jev.Verdict) and verdict.output.same_person == "no"
    _path, sent = captured[0]
    q = sent["questions"]["same_person"]
    # A Literal enum → a choice with a DICT ``criteria`` ({label: guidance}) plus
    # per-question ``instructions`` (both backends reject a bare-list criteria).
    assert q["type"] == "choice"
    assert set(q["criteria"]) == {"yes", "no", "unclear"}
    assert "instructions" in q
    # The free-text ``reason`` field is not required → skipped, not asked.
    assert set(sent["questions"]) == {"same_person"}


async def test_ollaya_falls_back_to_api_decide_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    paths: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/v1/systemone":
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json={"is_personal_name": True, "confidence": 0.9})

    _transport(monkeypatch, handler)
    verdict = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert isinstance(verdict, jev.Verdict)
    assert paths == ["/v1/systemone", "/api/decide"]


async def test_ollaya_unreachable_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    _transport(monkeypatch, _ollaya(exc=httpx.ConnectError("refused")))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("provider_unreachable") == 1


async def test_ollaya_model_not_loaded_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    # Both paths 404 → the model/endpoint is absent → model_not_loaded, no verdict.
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="ghost")
    _transport(monkeypatch, _ollaya(status=404, body={"error": "model not found"}))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("model_not_loaded") == 1


async def test_ollaya_auth_failure_off_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="https://ollaya.remote", jev_model="llama3", jev_api_key="k")
    sent_headers: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_headers.append(request.headers.get("authorization"))
        return httpx.Response(401, json={"error": "unauthorized"})

    _transport(monkeypatch, handler)
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("auth_failed") == 1
    assert sent_headers[0] == "Bearer k"  # bearer sent when a key is configured


def test_ollaya_default_base_url() -> None:
    prof = adapters.resolve_profile(
        type("S", (), {"jev_provider": "ollaya", "jev_api_key": "",
                       "jev_base_url": "", "jev_model": "m"})()
    )
    assert prof is not None and prof.base_url == adapters.DEFAULT_OLLAYA_BASE


def test_schema_to_questions_covers_types() -> None:
    from typing import Literal

    from pydantic import BaseModel, ConfigDict, Field

    class Out(BaseModel):
        model_config = ConfigDict(extra="forbid")
        flag: bool = Field(description="is it so")
        kind: Literal["a", "b"]
        note: str = Field(default="", max_length=20)      # optional free-text → skipped
        alias: str | None = Field(default=None, max_length=20)  # optional → skipped

    q = adapters.schema_to_questions(Out)
    # boolean → noul; enum → choice with DICT criteria; both carry instructions.
    assert q["flag"] == {"type": "noul", "instructions": "is it so"}
    assert q["kind"]["type"] == "choice"
    assert q["kind"]["criteria"] == {"a": "a", "b": "b"}
    assert "instructions" in q["kind"]
    # Non-required free-text fields are not questions (typed core validates without them).
    assert "note" not in q and "alias" not in q


def test_required_free_text_and_int_are_unsupported() -> None:
    from pydantic import BaseModel, ConfigDict, Field

    class ReqText(BaseModel):
        model_config = ConfigDict(extra="forbid")
        text: str = Field(max_length=20)  # required free-text → no typed decision

    class HasInt(BaseModel):
        model_config = ConfigDict(extra="forbid")
        idx: int | None = None  # System One has no integer type

    for model in (ReqText, HasInt):
        with pytest.raises(adapters.UnsupportedForOllaya):
            adapters.schema_to_questions(model)


# ---------------------------------------------------------------------------
# JEV-0.3 — Custom-JSON idiom, unsupported-schema DEFER, versioned cache key
# ---------------------------------------------------------------------------
def test_no_task_questions_reference_a_preset_name() -> None:
    # The idiom is choice/typed only — never one of Ollaya's built-in preset names.
    presets = {"triage", "email", "guard", "moderation", "router", "agent"}
    for name in jev.registered_tasks():
        out_model = jev.get_task(name).output_model
        try:
            questions = adapters.schema_to_questions(out_model)
        except adapters.UnsupportedForOllaya:
            continue  # list/nested task — never sent to Ollaya
        blob = json.dumps(questions).lower()
        assert not (presets & set(blob.split())), name
        for q in questions.values():
            assert q["type"] in {"choice", "noul", "score"}


def test_boolean_field_is_noul_and_maps_back() -> None:
    from backend.core.jev.tasks.demo import NameOutput
    q = adapters.schema_to_questions(NameOutput)
    assert q["is_personal_name"]["type"] == "noul"
    assert "instructions" in q["is_personal_name"]
    # A nested noul answer (a yes-probability) maps back to a real bool.
    assert adapters._answers_to_output(
        NameOutput, {"is_personal_name": {"type": "noul", "noul": 0.93}}
    )["is_personal_name"] is True
    assert adapters._answers_to_output(
        NameOutput, {"is_personal_name": {"type": "noul", "noul": 0.07}}
    )["is_personal_name"] is False
    # Bare "yes"/"no" strings still coerce (mock/legacy paths).
    assert adapters._answers_to_output(NameOutput, {"is_personal_name": "yes"})[
        "is_personal_name"] is True


async def test_list_output_task_defers_on_ollaya(monkeypatch: pytest.MonkeyPatch) -> None:
    # A task whose schema has a list/nested field is out of distribution → DEFER,
    # no request sent, existing logic runs.
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    sent: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        return httpx.Response(200, json={"leads": []})

    _transport(monkeypatch, handler)
    verdict = await jev.judge("narrative.finding_correlation", {
        "subject_email": "a@x.com", "findings": [{"id": "f0", "type": "t", "summary": "s"}],
        "max_leads": 3,
    })
    assert verdict is jev.DEFER
    assert sent == []  # translation failed before any network call
    assert jev_metrics.snapshot()["narrative.finding_correlation"][
        "defer_reasons"].get("schema_fail") == 1


async def test_ollaya_partial_answer_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    # A missing required field → schema validation fails → DEFER (existing logic).
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    _transport(monkeypatch, _ollaya(body={"answers": {}, "confidence": 0.95}))
    verdict = await jev.judge("identity.same_person", {
        "a": {"platform": "reddit"}, "b": {"platform": "mastodon"},
        "avatar_match": False, "heuristic_signals": [],
    })
    assert verdict is jev.DEFER


async def test_cache_key_includes_questions_version(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    calls: list = []
    _transport(monkeypatch, _ollaya(
        body={"is_personal_name": True, "confidence": 0.95}, capture=calls))
    assert isinstance(await jev.judge(DEMO, {"text": "Ada Lovelace"}), jev.Verdict)
    assert len(calls) == 1
    # Same payload again → served from cache (the version tag is stable within a run).
    assert isinstance(await jev.judge(DEMO, {"text": "Ada Lovelace"}), jev.Verdict)
    assert len(calls) == 1
    # Bumping the questions version invalidates the entry → a fresh call.
    monkeypatch.setattr(adapters, "QUESTIONS_VERSION", "qX")
    assert isinstance(await jev.judge(DEMO, {"text": "Ada Lovelace"}), jev.Verdict)
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# JEV-0.4 — per-item typed-decision form (name_reconcile, platform_select)
# ---------------------------------------------------------------------------
def _ollaya_per_item(route: Any) -> Any:
    """A per-item Ollaya handler: `route(field, state) -> choice string`."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        (field, question), = body["questions"].items()
        choice = route(field, body["state"])
        return httpx.Response(200, json={"answers": {field: choice}, "confidence": 0.95})
    return handler


async def test_name_reconcile_decomposes_into_pair_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")

    def route(field: str, state: dict[str, Any]) -> str:
        if field == "is_personal_name":
            return "no" if "Pipeline" in state["candidate"] else "yes"
        # same_person: Bob/Robert are the same; anything else no
        names = {state["name_a"], state["name_b"]}
        return "yes" if names == {"Bob Smith", "Robert Smith"} else "no"

    _transport(monkeypatch, _ollaya_per_item(route))
    verdict = await jev.judge("identity.name_reconcile", {
        "email_localpart": "rsmith",
        "candidates": [
            {"name": "Bob Smith", "sources": ["github_profile"], "weight": 0.6},
            {"name": "Robert Smith", "sources": ["gravatar"], "weight": 0.5},
            {"name": "Deploy Pipeline", "sources": ["hackernews"], "weight": 0.35},
        ],
    })
    assert isinstance(verdict, jev.Verdict)
    assert verdict.output.drop == [2]                       # junk dropped
    assert verdict.output.equivalence_groups == [[0, 1]]    # Bob≡Robert via union-find
    assert verdict.output.canonical_index == 0              # highest weight in the group


async def test_platform_select_decomposes_into_per_platform_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")

    def route(field: str, state: dict[str, Any]) -> str:
        return "likely" if state["platform"] in {"weibo", "vk"} else "unlikely"

    _transport(monkeypatch, _ollaya_per_item(route))
    verdict = await jev.judge("reach.platform_select", {
        "name": "Li Wei", "email_localpart": "liwei", "wave_cap": 2,
        "candidates": [
            {"id": "github", "rank": 1}, {"id": "weibo", "region": "cn", "rank": 2},
            {"id": "vk", "region": "ru", "rank": 3},
        ],
    })
    assert isinstance(verdict, jev.Verdict)
    assert verdict.output.ordered_platform_ids == ["weibo", "vk"]  # likely, within cap


async def test_platform_select_fills_to_wave_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    _transport(monkeypatch, _ollaya_per_item(lambda f, s: "likely"))  # all likely
    verdict = await jev.judge("reach.platform_select", {
        "name": "x", "email_localpart": "x", "wave_cap": 2,
        "candidates": [{"id": "a", "rank": 1}, {"id": "b", "rank": 2}, {"id": "c", "rank": 3}],
    })
    assert isinstance(verdict, jev.Verdict)
    assert verdict.output.ordered_platform_ids == ["a", "b"]  # capped to wave_cap (not 3)


async def test_decompose_partial_answer_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")

    def handler(request: httpx.Request) -> httpx.Response:
        # Return an empty answers block → the field is missing → partial → DEFER.
        return httpx.Response(200, json={"answers": {}, "confidence": 0.95})

    _transport(monkeypatch, handler)
    assert await jev.judge("reach.platform_select", {
        "name": "x", "email_localpart": "x", "wave_cap": 1,
        "candidates": [{"id": "a", "rank": 1}],
    }) is jev.DEFER


async def test_generative_tasks_still_defer_on_ollaya(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="llama3")
    sent: list = []
    _transport(monkeypatch, _ollaya(body={"queries": []}, capture=sent))
    # query_generate has no decomposer → still DEFERs (schema), no request.
    assert await jev.judge("reach.query_generate", {
        "engine": "ddg", "max_queries": 2, "domain": "acme.com"}) is jev.DEFER
    assert sent == []
    assert "reach.query_generate" not in adapters._DECOMPOSERS


def test_only_two_tasks_are_decomposable() -> None:
    assert set(adapters._DECOMPOSERS) == {"identity.name_reconcile", "reach.platform_select"}


# ---------------------------------------------------------------------------
# Real Ollaya answer shape: {"type":"choice","choice":"yes","confidence":0.68,...}
# ---------------------------------------------------------------------------
async def test_ollaya_real_nested_answer_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="laya:typed-decisions",
         jev_min_confidence=0.5)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "laya:typed-decisions", "answers": {
            "is_personal_name": {"type": "choice", "choice": "yes", "confidence": 0.68,
                                 "probabilities": {"yes": 0.84, "no": 0.16}}},
            "usage": {"input_tokens": 40}})

    _transport(monkeypatch, handler)
    verdict = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert isinstance(verdict, jev.Verdict)
    assert verdict.output.is_personal_name is True
    assert verdict.confidence == pytest.approx(0.68)  # per-answer confidence used


async def test_ollaya_nested_answer_below_floor_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="ollaya", jev_enabled=True,
         jev_base_url="http://localhost:11435", jev_model="laya:typed-decisions",
         jev_min_confidence=0.7)
    _transport(monkeypatch, lambda r: httpx.Response(200, json={"answers": {
        "is_personal_name": {"type": "choice", "choice": "yes", "confidence": 0.6}}}))
    # Real per-answer confidence 0.6 < 0.7 floor → DEFER (existing logic runs).
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER


def test_answer_value_and_confidence_helpers() -> None:
    nested = {"type": "choice", "choice": "no", "confidence": 0.42}
    assert adapters.answer_value(nested) == "no"
    assert adapters.answer_confidence(nested) == 0.42
    assert adapters.answer_value(True) is True           # flat value still supported
    assert adapters.answer_confidence("no") is None
    # noul: a yes-probability. value = p>=0.5; confidence = distance from a coin flip.
    yes = {"type": "noul", "noul": 0.93}
    no = {"type": "noul", "noul": 0.07}
    assert adapters.answer_value(yes) is True and adapters.answer_value(no) is False
    assert adapters.answer_confidence(yes) == pytest.approx(0.93)
    assert adapters.answer_confidence(no) == pytest.approx(0.93)
    # score: a numeric answer with its own confidence.
    score = {"type": "score", "score": 1.0, "confidence": 0.8}
    assert adapters.answer_value(score) == 1.0
    assert adapters.answer_confidence(score) == 0.8


# ---------------------------------------------------------------------------
# JEV-0.5 — jev is a typed-decisions (TypeSafe System One) provider
# ---------------------------------------------------------------------------
def test_jev_defaults_to_typesafe_endpoint() -> None:
    prof = adapters.resolve_profile(
        type("S", (), {"jev_provider": "jev", "jev_api_key": "k",
                       "jev_base_url": "", "jev_model": ""})()
    )
    assert prof is not None
    assert prof.base_url == adapters.DEFAULT_JEV_BASE == "https://api.typesafe.ai"
    assert prof.model == adapters.DEFAULT_JEV_MODEL == "jev-latest"
    assert prof.config_ok() is True
    assert "jev" in adapters.TYPED_PROVIDERS and "jev" not in adapters.CHAT_PROVIDERS


async def test_jev_routes_to_systemone_not_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, jev_provider="jev", jev_enabled=True,
         jev_base_url="https://api.typesafe.ai", jev_model="jev-latest", jev_api_key="k")
    captured: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append((request.url.path, request.headers.get("authorization")))
        return httpx.Response(200, json={"answers": {
            "is_personal_name": {"type": "noul", "noul": 0.93}}})

    _transport(monkeypatch, handler)
    verdict = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert isinstance(verdict, jev.Verdict) and verdict.output.is_personal_name is True
    path, auth = captured[0]
    assert path == "/v1/systemone"      # typed endpoint, not /chat/completions
    assert auth == "Bearer k"           # hosted jev sends the key


async def test_bio_extract_is_generative_and_defers_on_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # bio_extract extracts free-text (employer/role/location) → it needs a generative
    # provider. On a typed-decisions provider it DEFERs without a request.
    _set(monkeypatch, jev_provider="jev", jev_enabled=True,
         jev_base_url="https://api.typesafe.ai", jev_model="jev-latest", jev_api_key="k")
    sent: list = []
    _transport(monkeypatch, _ollaya(body={"answers": {}}, capture=sent))
    assert await jev.judge("identity.bio_extract", {
        "bio": "Staff engineer at Northwind Labs, based in Leeds."}) is jev.DEFER
    assert sent == []  # generative task never issues a typed request
    assert "identity.bio_extract" in adapters._GENERATIVE_TASKS


async def test_typed_decision_task_produces_verdict_on_jev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A decision task (reply_classify) validates on a typed provider: the free-text
    # ``reason`` is skipped, only the ``verdict`` choice is asked and answered.
    _set(monkeypatch, jev_provider="jev", jev_enabled=True,
         jev_base_url="https://api.typesafe.ai", jev_model="jev-latest", jev_api_key="k",
         jev_min_confidence=0.5)
    captured: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"answers": {"verdict": {
            "type": "choice", "choice": "no_such_user", "confidence": 0.99}}})

    _transport(monkeypatch, handler)
    verdict = await jev.judge("verify.reply_classify", {
        "protocol": "smtp_rcpt", "code": 550, "text": "5.1.1 no mailbox"})
    assert isinstance(verdict, jev.Verdict)
    assert verdict.output.verdict == "no_such_user"
    assert verdict.output.reason == ""  # skipped free-text → schema default
    assert set(captured[0]["questions"]) == {"verdict"}
