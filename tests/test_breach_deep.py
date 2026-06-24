from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from backend.config import settings
from backend.core.breach_corpus import BreachSite
from backend.modules import breach_deep as breach_deep_module
from backend.modules.base import ModuleStatus


def _site(
    domain: str,
    *,
    name: str | None = None,
    score: float = 100,
    pwn_count: int = 10,
) -> BreachSite:
    return BreachSite(
        domain=domain,
        breach_name=name or domain,
        breach_date="2024-01-02",
        pwn_count=pwn_count,
        data_classes=["Email addresses"],
        severity_score=score,
        severity_label="high" if score >= 10_000_000 else "medium",
    )


class StubCorpus:
    def __init__(self, sites: list[BreachSite], error: Exception | None = None) -> None:
        self.sites = sites
        self.error = error
        self.get_top_calls = 0
        self.get_all_calls = 0

    def get_top(self, limit: int) -> list[BreachSite]:
        self.get_top_calls += 1
        if self.error:
            raise self.error
        return self.sites[:limit]

    def get_all(self) -> list[BreachSite]:
        self.get_all_calls += 1
        if self.error:
            raise self.error
        return self.sites


def _install(
    monkeypatch: pytest.MonkeyPatch,
    sites: list[BreachSite],
    *,
    corpus_error: Exception | None = None,
    yaml_result: dict[str, Any] | None = None,
    yaml_error: Exception | None = None,
    reset_result: bool | None = False,
    platforms: list[Any] | None = None,
) -> SimpleNamespace:
    corpus = StubCorpus(sites, corpus_error)
    check = AsyncMock(return_value=yaml_result or {})
    if yaml_error is not None:
        check.side_effect = yaml_error
    reset = AsyncMock(return_value=reset_result)
    platform_values = platforms if platforms is not None else [SimpleNamespace(slug="adobe")]

    class Loader:
        def load_all(self) -> list[Any]:
            return platform_values

    class Executor:
        async def check(self, platform: Any, email: str, client: Any) -> dict[str, Any]:
            return await check(platform, email, client)

    @asynccontextmanager
    async def client_context(**kwargs: Any):
        yield object()

    monkeypatch.setattr(settings, "enable_breach_deep", True)
    monkeypatch.setattr(settings, "breach_deep_full", False)
    monkeypatch.setattr(settings, "breach_deep_limit", 100)
    monkeypatch.setattr(breach_deep_module, "BreachCorpus", lambda: corpus)
    monkeypatch.setattr(breach_deep_module, "PlatformLoader", Loader)
    monkeypatch.setattr(breach_deep_module, "PlatformExecutor", Executor)
    monkeypatch.setattr(breach_deep_module, "reset_probe", reset)
    monkeypatch.setattr(breach_deep_module, "build_client", client_context)
    return SimpleNamespace(corpus=corpus, check=check, reset=reset)


async def test_run_skipped_when_disabled_no_force(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "enable_breach_deep", False)

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.status == ModuleStatus.SKIPPED
    assert "ENABLE_BREACH_DEEP" in result.errors[0]


async def test_run_force_bypasses_disabled_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _install(monkeypatch, [_site("unknown.example")])
    monkeypatch.setattr(settings, "enable_breach_deep", False)

    result = await breach_deep_module.BreachDeepModule().run(
        "person@example.com", force=True
    )

    assert result.status == ModuleStatus.SUCCESS
    state.reset.assert_awaited_once()


async def test_run_uses_yaml_path_when_slug_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install(
        monkeypatch,
        [_site("adobe.com")],
        yaml_result={"platform": "Adobe"},
    )

    await breach_deep_module.BreachDeepModule().run("person@example.com")

    state.check.assert_awaited_once()
    state.reset.assert_not_awaited()


async def test_run_uses_generic_reset_when_no_slug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install(monkeypatch, [_site("unknown-domain.com")], reset_result=True)

    await breach_deep_module.BreachDeepModule().run("person@example.com")

    state.reset.assert_awaited_once()
    state.check.assert_not_awaited()


async def test_run_yaml_finding_has_high_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, [_site("adobe.com")], yaml_result={"platform": "Adobe"})

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.findings[0]["confidence"] == "high"


async def test_run_generic_finding_has_medium_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, [_site("unknown.example")], reset_result=True)

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.findings[0]["confidence"] == "medium"


async def test_run_findings_sorted_by_severity_descending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        [
            _site("low.example", score=100),
            _site("high.example", score=30_000_000),
            _site("middle.example", score=5_000),
        ],
        reset_result=True,
    )

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")
    scores = [finding["metadata"]["severity_score"] for finding in result.findings]

    assert scores == sorted(scores, reverse=True)


async def test_run_handles_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, [_site("unknown.example")], reset_result=None)

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.metadata["sites_inconclusive"] == 1
    assert result.findings == []


async def test_run_handles_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, [_site("adobe.com")], yaml_result={"rate_limited": True})

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.metadata["sites_inconclusive"] == 1
    assert result.findings == []


async def test_run_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, [_site("adobe.com")], yaml_error=asyncio.TimeoutError())

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.metadata["sites_inconclusive"] == 1
    assert result.errors == []


async def test_run_handles_corpus_load_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, [], corpus_error=RuntimeError("corpus unavailable"))

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.status == ModuleStatus.FAILED
    assert result.errors == ["breach corpus load failed: corpus unavailable"]


async def test_run_metadata_top_breach_is_first_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        [
            _site("low.example", name="Low", score=10),
            _site("high.example", name="Highest", score=1_000),
        ],
        reset_result=True,
    )

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.metadata["top_breach"] == "Highest"


async def test_run_metadata_total_records_potentially_exposed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        [_site("one.example", pwn_count=20), _site("two.example", pwn_count=30)],
        reset_result=True,
    )

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.metadata["total_records_potentially_exposed"] == 50


async def test_run_breach_deep_full_uses_get_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install(monkeypatch, [_site("unknown.example")])
    monkeypatch.setattr(settings, "breach_deep_full", True)

    await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert state.corpus.get_all_calls >= 1
    assert state.corpus.get_top_calls == 0


async def test_run_metadata_status_partial_when_some_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install(
        monkeypatch,
        [_site("found.example"), _site("error.example")],
        reset_result=True,
    )

    async def reset_by_domain(domain: str, email: str, client: Any) -> bool:
        if domain == "error.example":
            raise RuntimeError("probe failed")
        return True

    state.reset.side_effect = reset_by_domain

    result = await breach_deep_module.BreachDeepModule().run("person@example.com")

    assert result.status == ModuleStatus.PARTIAL
    assert len(result.findings) == 1
    assert result.errors == ["error.example: probe failed"]
