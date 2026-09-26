"""Phase JEV-0.2 — provider adapters + activation.

Both adapters mocked via httpx.MockTransport. Covers: chat JSON parse (jev/openai),
Ollaya schema→questions translation + typed-answer mapping, provider routing, every
DEFER path (no provider / not enabled / unreachable / model-not-loaded / auth /
credits / circuit-open), the legacy key shortcut, and the force-off override.
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
# Chat adapter (jev / openai)
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
    _set(monkeypatch, jev_provider="jev", jev_enabled=True,
         jev_base_url="https://jev/v1", jev_model="m", jev_api_key="k")

    def quota(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"code": "insufficient_quota"}})

    _transport(monkeypatch, quota)
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("credits_exhausted") == 1 and breaker.snapshot()["state"] == "open"


# ---------------------------------------------------------------------------
# Ollaya adapter
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
    assert sent["questions"] == {"is_personal_name": {"type": "boolean"}}


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
    assert sent["questions"]["same_person"] == {
        "type": "choice", "criteria": ["yes", "no", "unclear"]}


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
    from pydantic import BaseModel, ConfigDict, Field

    class Out(BaseModel):
        model_config = ConfigDict(extra="forbid")
        flag: bool
        count: int | None = None
        label: str = Field(max_length=20)

    q = adapters.schema_to_questions(Out)
    assert q["flag"] == {"type": "boolean"}
    assert q["count"]["type"] == "integer" and q["count"]["required"] is False
    assert q["label"] == {"type": "string"}
