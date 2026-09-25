"""Phase JEV-0 — the reasoning seam: guards, verdicts, cache, limits, metrics.

Network-free: the model is an ``httpx.MockTransport`` installed on the client's
test seam, and the no-key test additionally proves no ``AsyncClient`` is ever
constructed. Settings are patched per test; the cache lives in ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, Field

import backend.config as config_mod
from backend.core import jev
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import cache as jev_cache
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.contract import TaskSpecError, unregister
from backend.core.jev.tasks import demo

DEMO = demo.TASK_NAME


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _jev_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    s = config_mod.settings
    monkeypatch.setattr(s, "jev_api_key", "test-key-not-real")
    monkeypatch.setattr(s, "jev_force_off", False)
    monkeypatch.setattr(s, "jev_breaker_failure_threshold", 3)
    monkeypatch.setattr(s, "jev_breaker_cooldown_seconds", 120.0)
    monkeypatch.setattr(s, "jev_base_url", "https://jev.invalid/v1")
    monkeypatch.setattr(s, "jev_model", "jev-test")
    monkeypatch.setattr(s, "jev_timeout_ms", 2000)
    monkeypatch.setattr(s, "jev_max_concurrency", 4)
    monkeypatch.setattr(s, "jev_cache_ttl_seconds", 3600)
    monkeypatch.setattr(s, "jev_cache_path", str(tmp_path / "jev-cache"))
    monkeypatch.setattr(s, "jev_cache_refresh", False)
    monkeypatch.setattr(s, "jev_min_confidence", 0.7)
    monkeypatch.setattr(s, "jev_run_ceiling_seconds", 20.0)
    monkeypatch.setattr(s, "jev_metrics_dir", "")
    monkeypatch.setattr(jev_client, "_TRANSPORT", None)
    jev_metrics.reset()
    jev_breaker.reset()


def _completion(content: Any) -> dict[str, Any]:
    text = content if isinstance(content, str) else json.dumps(content)
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


class FakeModel:
    """Scripted OpenAI-compatible endpoint; records every request it receives."""

    def __init__(self, content: Any = None, *, status: int = 200, delay: float = 0.0,
                 raw: bytes | None = None, exc: Exception | None = None) -> None:
        self.content = content
        self.status = status
        self.delay = delay
        self.raw = raw
        self.exc = exc
        self.requests: list[dict[str, Any]] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if self.exc is not None:
            raise self.exc
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raw is not None:
            return httpx.Response(self.status, content=self.raw)
        return httpx.Response(self.status, json=_completion(self.content))


def _install(monkeypatch: pytest.MonkeyPatch, model: FakeModel) -> FakeModel:
    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(model))
    return model


def _defers(reason: str) -> int:
    return jev_metrics.snapshot()[DEMO]["defer_reasons"].get(reason, 0)


# ---------------------------------------------------------------------------
# Active iff a key is configured; no key → zero network, DEFER
# ---------------------------------------------------------------------------
def test_jev_is_off_by_default() -> None:
    fields = config_mod.Settings.model_fields
    assert fields["jev_api_key"].default is None
    assert fields["jev_force_off"].default is False
    assert "jev_enabled" not in fields  # activation is key presence, not a flag


@pytest.mark.parametrize("key", [None, "", "   "])
async def test_no_key_makes_no_network_call_and_defers(
    monkeypatch: pytest.MonkeyPatch, key: str | None
) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_api_key", key)

    def _boom(*_a: Any, **_kw: Any) -> None:
        raise AssertionError("AsyncClient constructed while JEV is disabled")

    monkeypatch.setattr(jev_client.httpx, "AsyncClient", _boom)
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.99}))

    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert await jev.judge("no.such.task", {"x": 1}) is jev.DEFER
    assert model.requests == []
    assert _defers("no_key") == 1
    # No key resolves before anything else — the cache dir is never created.
    assert not jev_cache.cache_dir(config_mod.settings.jev_cache_path).exists()


# ---------------------------------------------------------------------------
# Each DEFER guard
# ---------------------------------------------------------------------------
async def test_force_off_override_defers_even_with_a_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_force_off", True)
    monkeypatch.setattr(config_mod.settings, "jev_metrics_dir", str(tmp_path / "m"))
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert model.requests == []
    assert _defers("forced_off") == 1
    assert not (tmp_path / "m").exists()  # inert exactly like a no-key install
    assert await demo.is_plausible_personal_name("Ada Lovelace") == (True, "rule")


async def test_key_without_endpoint_defers_as_missing_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    monkeypatch.setattr(config_mod.settings, "jev_base_url", "")
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert model.requests == []
    assert _defers("missing_config") == 1


async def test_timeout_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_timeout_ms", 50)
    _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}, delay=1.0))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("timeout") == 1


@pytest.mark.parametrize(
    ("model", "reason"),
    [
        (FakeModel("definitely not json"), "non_json"),
        (FakeModel(raw=b"<html>gateway</html>"), "non_json"),
        (FakeModel('["a", "list"]'), "non_json"),
        (FakeModel({"is_personal_name": True}, status=500), "server_error"),
        (FakeModel({"is_personal_name": True}, status=404), "http_status"),
        (FakeModel({"is_personal_name": True}, status=429), "rate_limited"),
        (FakeModel(exc=httpx.ConnectError("refused")), "transport"),
        (FakeModel(raw=b"x" * (jev_client._MAX_RESPONSE_BYTES + 10)), "oversize"),
    ],
)
async def test_transport_and_decode_failures_defer(
    monkeypatch: pytest.MonkeyPatch, model: FakeModel, reason: str
) -> None:
    _install(monkeypatch, model)
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers(reason) == 1


@pytest.mark.parametrize(
    "content",
    [
        {"is_personal_name": "yes", "confidence": 0.9},  # wrong type, no coercion
        {"is_personal_name": "true", "confidence": 0.9},  # strict: no str→bool
        {"is_personal_name": True},  # missing confidence
        {"is_personal_name": True, "confidence": 1.7},  # out of range
        {"is_personal_name": True, "confidence": True},  # bool is not a number
        {"is_personal_name": True, "confidence": 0.9, "why": "free text"},  # extra key
        {"confidence": 0.9},  # missing field
    ],
)
async def test_schema_failure_defers(monkeypatch: pytest.MonkeyPatch, content: Any) -> None:
    _install(monkeypatch, FakeModel(content))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("schema_fail") == 1


async def test_low_confidence_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.4}))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert _defers("low_confidence") == 1


async def test_invalid_input_and_unknown_task_defer(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    assert await jev.judge(DEMO, {"text": ""}) is jev.DEFER
    assert await jev.judge(DEMO, "not a mapping") is jev.DEFER  # type: ignore[arg-type]
    assert await jev.judge("no.such.task", {"text": "x"}) is jev.DEFER
    assert model.requests == []
    assert _defers("invalid_input") == 2
    assert jev_metrics.snapshot()["no.such.task"]["defer_reasons"] == {"unknown_task": 1}


async def test_prompt_builder_crash_defers_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _bad_prompt(_inp: Any) -> tuple[str, str]:
        raise RuntimeError("bug in a task spec")

    task = jev.register(jev.JevTask(
        name="test.crashing_prompt", input_model=demo.NameInput,
        output_model=demo.NameOutput, prompt_version="t1", build_prompt=_bad_prompt,
    ))
    try:
        _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
        assert await jev.judge(task.name, {"text": "Ada"}) is jev.DEFER
        assert jev_metrics.snapshot()[task.name]["defer_reasons"] == {"internal": 1}
    finally:
        unregister(task.name)


# ---------------------------------------------------------------------------
# Valid verdict, request shape, cache
# ---------------------------------------------------------------------------
async def test_valid_verdict_carries_output_confidence_and_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.93}))
    verdict = await jev.judge(DEMO, {"text": "  Ada   Lovelace "})

    assert isinstance(verdict, jev.Verdict)
    assert verdict.output.is_personal_name is True
    assert verdict.confidence == pytest.approx(0.93)
    assert verdict.provenance == jev.Provenance(
        task=DEMO, prompt_version="demo-name-v1", model="jev-test", cached=False
    )
    assert verdict.provenance.source == "jev"

    [req] = model.requests
    assert req["model"] == "jev-test"
    assert req["temperature"] == 0
    assert req["response_format"] == {"type": "json_object"}
    assert req["max_tokens"] <= 256
    assert "'Ada Lovelace'" in req["messages"][1]["content"]  # normalized input
    assert '"confidence"' in req["messages"][0]["content"]  # seam contract footer


async def test_fenced_json_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    fenced = '```json\n{"is_personal_name": false, "confidence": 0.8}\n```'
    _install(monkeypatch, FakeModel(fenced))
    verdict = await jev.judge(DEMO, {"text": "acme-support"})
    assert isinstance(verdict, jev.Verdict) and verdict.output.is_personal_name is False


async def test_repeat_call_is_served_from_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    first = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    # Whitespace-different spelling normalizes to the same key.
    second = await jev.judge(DEMO, {"text": "Ada  Lovelace"})

    assert len(model.requests) == 1
    assert isinstance(second, jev.Verdict)
    assert second.output == first.output  # type: ignore[union-attr]
    assert second.provenance.cached is True
    snap = jev_metrics.snapshot()[DEMO]
    assert snap["model_calls"] == 1 and snap["cache_hits"] == 1
    assert snap["cache_hit_rate"] == 0.5


async def test_cache_key_covers_model_and_refresh_bypasses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    monkeypatch.setattr(config_mod.settings, "jev_model", "jev-other")
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert len(model.requests) == 2  # a different model never replays another's verdict

    monkeypatch.setattr(config_mod.settings, "jev_cache_refresh", True)
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert len(model.requests) == 3


async def test_cache_ttl_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    monkeypatch.setattr(jev_cache.time, "time", lambda: 10**12)
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert len(model.requests) == 2


async def test_low_confidence_answer_is_cached_but_still_gated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.6}))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert len(model.requests) == 1
    # Lowering the floor needs no purge: the cached answer now clears it.
    monkeypatch.setattr(config_mod.settings, "jev_min_confidence", 0.5)
    verdict = await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert isinstance(verdict, jev.Verdict) and verdict.provenance.cached


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
async def test_run_scope_ceiling_defers_once_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9},
                                            delay=0.2))
    async with jev.run_scope(0.3) as scope:
        assert isinstance(await jev.judge(DEMO, {"text": "Ada Lovelace"}), jev.Verdict)
        # ~0.2s spent of 0.3s: the next call is capped to the remainder and times out.
        assert await jev.judge(DEMO, {"text": "Grace Hopper"}) is jev.DEFER
        assert await jev.judge(DEMO, {"text": "Alan Turing"}) is jev.DEFER
        assert scope.remaining() == 0.0
    assert len(model.requests) == 2
    assert _defers("run_ceiling") == 1


async def test_run_scope_respects_investigation_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    class _SpentBudget:
        def remaining(self) -> float:
            return 0.0

    model = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    async with jev.run_scope(30.0, budget=_SpentBudget()):
        assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert model.requests == []


async def test_concurrency_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_max_concurrency", 2)
    in_flight = peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        return httpx.Response(200, json=_completion({"is_personal_name": True,
                                                     "confidence": 0.9}))

    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(handler))
    names = [f"Person Number{i}" for i in range(6)]
    results = await asyncio.gather(*(jev.judge(DEMO, {"text": n}) for n in names))
    assert all(isinstance(r, jev.Verdict) for r in results)
    assert peak == 2


# ---------------------------------------------------------------------------
# Demo task end to end (caller falls back on DEFER)
# ---------------------------------------------------------------------------
async def test_demo_caller_uses_jev_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    # The model overrules the rigid rule (lower-case single token → rule says False).
    _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.95}))
    assert demo.fallback_is_personal_name("cher") is False
    assert await demo.is_plausible_personal_name("cher") == (True, "jev")


@pytest.mark.parametrize(
    "model",
    [
        FakeModel({"is_personal_name": False, "confidence": 0.9}, delay=1.0),  # timeout
        FakeModel("garbage"),  # bad JSON
        FakeModel({"is_personal_name": "maybe", "confidence": 0.9}),  # schema fail
    ],
)
async def test_demo_caller_falls_back_on_defer(
    monkeypatch: pytest.MonkeyPatch, model: FakeModel
) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_timeout_ms", 50)
    _install(monkeypatch, model)
    assert await demo.is_plausible_personal_name("Ada Lovelace") == (True, "rule")
    assert await demo.is_plausible_personal_name("acme-support") == (False, "rule")


async def test_demo_caller_without_key_is_pure_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_api_key", None)
    assert await demo.is_plausible_personal_name("Ada Lovelace") == (True, "rule")


# ---------------------------------------------------------------------------
# Credit exhaustion / auth failure → circuit breaker
# ---------------------------------------------------------------------------
_CREDIT_ERRORS = [
    (429, {"error": {"type": "insufficient_quota", "message": "You exceeded your quota."}}),
    (402, {"error": {"message": "Payment required"}}),
    (403, {"error": {"message": "Your credit balance is too low."}}),
    (200, {"error": {"code": "insufficient_quota"}}),  # gateway reporting via 200
]


class ErrorModel(FakeModel):
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(status=status, raw=json.dumps(body).encode())


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(jev_breaker, "_clock", c)
    return c


@pytest.mark.parametrize(("status", "body"), _CREDIT_ERRORS)
async def test_credit_error_defers_opens_breaker_and_next_call_skips_network(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock, status: int, body: dict[str, Any]
) -> None:
    model = _install(monkeypatch, ErrorModel(status, body))
    # The caller completes on the existing logic.
    assert await demo.is_plausible_personal_name("Ada Lovelace") == (True, "rule")
    assert _defers("credits_exhausted") == 1
    assert jev_breaker.snapshot()["state"] == "open"

    for name in ("Grace Hopper", "Alan Turing", "acme-support"):
        assert await jev.judge(DEMO, {"text": name}) is jev.DEFER
    assert len(model.requests) == 1  # no further network while open
    assert _defers("circuit_open") == 3


async def test_auth_failure_trips_breaker(monkeypatch: pytest.MonkeyPatch, clock: _Clock) -> None:
    model = _install(monkeypatch, ErrorModel(401, {"error": {"message": "invalid api key"}}))
    assert await jev.judge(DEMO, {"text": "Ada Lovelace"}) is jev.DEFER
    assert await jev.judge(DEMO, {"text": "Grace Hopper"}) is jev.DEFER
    assert len(model.requests) == 1
    assert _defers("auth_failed") == 1 and _defers("circuit_open") == 1


async def test_breaker_half_opens_after_cooldown_and_closes_on_success(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    dead = _install(monkeypatch, ErrorModel(*_CREDIT_ERRORS[0]))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    clock.now += 119.0
    assert await jev.judge(DEMO, {"text": "Grace Hopper"}) is jev.DEFER
    assert len(dead.requests) == 1

    clock.now += 2.0  # cooldown elapsed → one probe; credits were topped up
    alive = _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    assert isinstance(await jev.judge(DEMO, {"text": "Grace Hopper"}), jev.Verdict)
    assert jev_breaker.snapshot()["state"] == "closed"
    assert isinstance(await jev.judge(DEMO, {"text": "Alan Turing"}), jev.Verdict)
    assert len(alive.requests) == 2


async def test_failed_probe_reopens_for_a_fresh_cooldown(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    model = _install(monkeypatch, ErrorModel(*_CREDIT_ERRORS[1]))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    clock.now += 121.0
    assert await jev.judge(DEMO, {"text": "Grace Hopper"}) is jev.DEFER  # the probe
    assert len(model.requests) == 2
    assert jev_breaker.snapshot()["state"] == "open"
    clock.now += 60.0
    assert await jev.judge(DEMO, {"text": "Alan Turing"}) is jev.DEFER
    assert len(model.requests) == 2
    assert jev_breaker.snapshot()["trips"] == 2


async def test_repeated_soft_failures_trip_after_threshold(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    model = _install(monkeypatch, FakeModel(exc=httpx.ConnectError("refused")))
    for i in range(5):
        assert await jev.judge(DEMO, {"text": f"Person Number{i}"}) is jev.DEFER
    assert len(model.requests) == 3  # threshold=3, then open
    assert _defers("transport") == 3 and _defers("circuit_open") == 2
    assert jev_breaker.snapshot()["last_trip_reason"] == "transport"


async def test_success_resets_the_soft_failure_count(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    flaky = _install(monkeypatch, FakeModel(status=503, raw=b"busy"))
    await jev.judge(DEMO, {"text": "Person One"})
    await jev.judge(DEMO, {"text": "Person Two"})
    _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    await jev.judge(DEMO, {"text": "Person Three"})
    _install(monkeypatch, flaky)
    await jev.judge(DEMO, {"text": "Person Four"})
    await jev.judge(DEMO, {"text": "Person Five"})
    assert jev_breaker.snapshot()["state"] == "closed"


async def test_quality_failures_do_not_trip_breaker(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    _install(monkeypatch, FakeModel("garbage"))
    for i in range(5):
        await jev.judge(DEMO, {"text": f"Person Number{i}"})
    assert jev_breaker.snapshot()["state"] == "closed"
    assert _defers("non_json") == 5


async def test_new_key_resets_an_open_breaker(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    _install(monkeypatch, ErrorModel(*_CREDIT_ERRORS[0]))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert jev_breaker.snapshot()["state"] == "open"
    monkeypatch.setattr(config_mod.settings, "jev_api_key", "a-fresh-key")
    _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    assert isinstance(await jev.judge(DEMO, {"text": "Ada Lovelace"}), jev.Verdict)


def test_classify_error_vocabulary() -> None:
    c = jev_client.classify_error
    R = jev.DeferReason
    assert c(429, b'{"error":{"code":"insufficient_quota"}}') is R.CREDITS_EXHAUSTED
    assert c(429, b'{"error":{"message":"slow down"}}') is R.RATE_LIMITED
    assert c(401, b"unauthorized") is R.AUTH_FAILED
    assert c(502, b"bad gateway") is R.SERVER_ERROR
    assert c(400, b"bad request") is R.HTTP_STATUS


# ---------------------------------------------------------------------------
# Metrics persistence + merge
# ---------------------------------------------------------------------------
async def test_metrics_persist_and_merge(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    mdir = tmp_path / "metrics"
    monkeypatch.setattr(config_mod.settings, "jev_metrics_dir", str(mdir))
    _install(monkeypatch, FakeModel({"is_personal_name": True, "confidence": 0.9}))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    await jev.judge(DEMO, {"text": "Ada Lovelace"})

    [path] = list(mdir.glob("jev-metrics-*.json"))
    snap = json.loads(path.read_text())
    merged = jev_metrics.merge_snapshots([snap, snap])
    assert merged[DEMO]["calls"] == 4
    assert merged[DEMO]["cache_hits"] == 2
    assert merged[DEMO]["defer_rate"] == 0.0
    assert merged[DEMO]["latency_mean_ms"] is not None


async def test_no_key_never_writes_metrics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_api_key", None)
    monkeypatch.setattr(config_mod.settings, "jev_metrics_dir", str(tmp_path / "m"))
    await jev.judge(DEMO, {"text": "Ada Lovelace"})
    assert not (tmp_path / "m").exists()


# ---------------------------------------------------------------------------
# Contract: output schemas are bounded at registration
# ---------------------------------------------------------------------------
class _In(BaseModel):
    text: str


def _spec(output: type[BaseModel], name: str = "test.spec") -> jev.JevTask[Any, Any]:
    return jev.JevTask(name=name, input_model=_In, output_model=output,
                       prompt_version="t1", build_prompt=lambda i: ("s", i.text))


def test_register_rejects_unbounded_outputs() -> None:
    class FloatOut(BaseModel):
        model_config = ConfigDict(extra="forbid")
        score: float

    class FreeTextOut(BaseModel):
        model_config = ConfigDict(extra="forbid")
        reasoning: str

    class LooseOut(BaseModel):
        flag: bool

    class ReservedOut(BaseModel):
        model_config = ConfigDict(extra="forbid")
        confidence: bool

    for bad in (FloatOut, FreeTextOut, LooseOut, ReservedOut):
        with pytest.raises(TaskSpecError):
            jev.register(_spec(bad))
    with pytest.raises(TaskSpecError):
        jev.register(_spec(demo.NameOutput, name="Bad Name!"))


def test_register_accepts_bounded_outputs_and_rejects_conflicts() -> None:
    import enum
    from typing import Literal

    class Kind(str, enum.Enum):
        A = "a"
        B = "b"

    class GoodOut(BaseModel):
        model_config = ConfigDict(extra="forbid")
        kind: Kind
        pick: int | None = None
        mode: Literal["x", "y"]
        label: str = Field(max_length=40)
        picks: list[int] = Field(default_factory=list, max_length=5)

    try:
        spec = _spec(GoodOut, name="test.good")
        jev.register(spec)
        jev.register(spec)  # identical re-register is fine
        assert "test.good" in jev.registered_tasks()
        with pytest.raises(TaskSpecError):
            jev.register(_spec(demo.NameOutput, name="test.good"))
    finally:
        unregister("test.good")
