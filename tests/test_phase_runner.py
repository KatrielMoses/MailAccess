from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from backend.core._phase_runner import (
    resolve_timeout,
    run_one_module,
    settings_override,
)
from backend.modules.base import BaseModule, ModuleResult, ModuleStatus


class StubModule(BaseModule):
    name = "stub"
    description = "test stub"

    def __init__(self, result: ModuleResult | None = None, error: Exception | None = None):
        self.result = result or ModuleResult(status=ModuleStatus.SUCCESS)
        self.error = error

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if self.error:
            raise self.error
        return self.result


async def test_run_one_module_returns_normal_result_on_success() -> None:
    expected = ModuleResult(status=ModuleStatus.SUCCESS, findings=[{"ok": True}])
    actual = await run_one_module(
        StubModule(expected),
        "person@example.com",
        default_timeout=1,
        overrides={},
        explicit_module=False,
    )
    assert actual is expected


async def test_run_one_module_passes_typed_email_to_modules_that_ask() -> None:
    seen: dict[str, object] = {}

    class TypedEmailModule(StubModule):
        async def run(
            self, email: str, force: bool = False, original_email: str | None = None
        ) -> ModuleResult:
            seen.update(email=email, original_email=original_email)
            return self.result

    await run_one_module(
        TypedEmailModule(),
        "jane.doe@example.com",
        default_timeout=1,
        overrides={},
        explicit_module=False,
        canonical_email="janedoe@example.com",
    )
    assert seen == {"email": "janedoe@example.com", "original_email": "jane.doe@example.com"}


async def test_run_one_module_catches_timeout() -> None:
    class HangingModule(StubModule):
        async def run(self, email: str, force: bool = False) -> ModuleResult:
            await asyncio.sleep(0.05)
            return self.result

    result = await run_one_module(
        HangingModule(),
        "person@example.com",
        default_timeout=0.001,
        overrides={},
        explicit_module=False,
    )
    assert result.status == ModuleStatus.PARTIAL
    assert result.errors == ["Module timed out after 0.001s"]


async def test_run_one_module_catches_exception() -> None:
    result = await run_one_module(
        StubModule(error=RuntimeError("boom")),
        "person@example.com",
        default_timeout=1,
        overrides={},
        explicit_module=False,
    )
    assert result.status == ModuleStatus.FAILED
    assert result.errors == ["boom"]


# ── Q4 invariant: cancellation preserves streamed hits ─────────────────────────


class StreamingHangModule(BaseModule):
    """Streams one hit into the run-owned sink, then hangs past the deadline."""

    name = "streaming_hang"
    description = "test stub"

    async def run(
        self, email: str, force: bool = False, sink: list | None = None
    ) -> ModuleResult:
        if sink is not None:
            sink.append({"platform": "early", "profile_url": "https://early.test/u"})
        await asyncio.sleep(5.0)  # never completes within the test timeout
        return ModuleResult(status=ModuleStatus.SUCCESS)


async def test_timeout_preserves_streamed_hits() -> None:
    # INVARIANT (cancellation-preservation): an early hit streamed into the sink
    # survives a later module timeout — the result is PARTIAL, not empty.
    result = await run_one_module(
        StreamingHangModule(),
        "person@example.com",
        default_timeout=0.02,
        overrides={},
        explicit_module=False,
    )
    assert result.status == ModuleStatus.PARTIAL
    assert result.findings == [{"platform": "early", "profile_url": "https://early.test/u"}]
    assert result.metadata.get("partial_snapshot") is True


class StreamingRaiseModule(BaseModule):
    """Streams one hit, then raises — the hit must still survive."""

    name = "streaming_raise"
    description = "test stub"

    async def run(
        self, email: str, force: bool = False, sink: list | None = None
    ) -> ModuleResult:
        if sink is not None:
            sink.append({"platform": "early", "profile_url": "https://early.test/u"})
        raise RuntimeError("boom after a hit")


async def test_exception_preserves_streamed_hits() -> None:
    result = await run_one_module(
        StreamingRaiseModule(),
        "person@example.com",
        default_timeout=1,
        overrides={},
        explicit_module=False,
    )
    assert result.status == ModuleStatus.PARTIAL
    assert result.findings == [{"platform": "early", "profile_url": "https://early.test/u"}]


def test_run_one_module_uses_floor_timeout() -> None:
    # account_discovery's floor was raised to 180s when it absorbed the native
    # 266-site email-existence corpus (backend/core/policy.py:_MODULE_TIMEOUT_FLOORS).
    assert resolve_timeout("account_discovery", 30, {}) == 180


def test_run_one_module_user_override_wins() -> None:
    assert resolve_timeout("account_discovery", 30, {"account_discovery": 240}) == 240


# ── L1 invariant: per-run opt-ins are task-local, never cross-contaminate ──────


async def test_run_opt_in_flags_are_task_local() -> None:
    # INVARIANT (identity/config-isolation): two overlapping runs must not see each
    # other's opt-in flags, and no global state leaks after either finishes.
    from backend.config import (
        opt_in_active,
        reset_run_opt_in_flags,
        set_run_opt_in_flags,
    )

    observed: dict[str, bool] = {}

    async def run_with_optin() -> None:
        token = set_run_opt_in_flags({"enable_breach_deep"})
        try:
            await asyncio.sleep(0.02)  # yield so the sibling interleaves
            observed["with_optin_sees_own"] = opt_in_active("enable_breach_deep", False)
        finally:
            reset_run_opt_in_flags(token)

    async def run_without_optin() -> None:
        await asyncio.sleep(0.01)
        # This run never opted in — it must NOT see the sibling's flag.
        observed["without_optin_sees_sibling"] = opt_in_active("enable_breach_deep", False)

    await asyncio.gather(run_with_optin(), run_without_optin())

    assert observed["with_optin_sees_own"] is True
    assert observed["without_optin_sees_sibling"] is False
    # No leak into the parent context after both tasks complete.
    assert opt_in_active("enable_breach_deep", False) is False


def test_settings_override_restores_attribute_on_exit() -> None:
    settings = SimpleNamespace(enabled=False)
    with settings_override(settings, enabled=True):
        assert settings.enabled is True
    assert settings.enabled is False


def test_settings_override_restores_multiple_attrs() -> None:
    settings = SimpleNamespace(first=1, second=2)
    with settings_override(settings, first=10, second=20):
        assert (settings.first, settings.second) == (10, 20)
    assert (settings.first, settings.second) == (1, 2)


def test_settings_override_handles_missing_attribute() -> None:
    settings = SimpleNamespace()
    with settings_override(settings, temporary=True):
        assert settings.temporary is True
    assert settings.temporary is None


def test_settings_override_is_reentrant() -> None:
    settings = SimpleNamespace(value="original")
    with settings_override(settings, value="outer"):
        with settings_override(settings, value="inner"):
            assert settings.value == "inner"
        assert settings.value == "outer"
    assert settings.value == "original"


def test_settings_override_restores_on_exception() -> None:
    settings = SimpleNamespace(value="original")
    with pytest.raises(RuntimeError, match="inside"):
        with settings_override(settings, value="changed"):
            raise RuntimeError("inside")
    assert settings.value == "original"
