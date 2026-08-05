from __future__ import annotations

from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import cli.main as cli_main

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


class _HealthResponse:
    def raise_for_status(self) -> None:
        return None


class _FakeAsyncClient:
    def __init__(self, responses: deque[object], calls: list[tuple[str, float]]) -> None:
        self._responses = responses
        self._calls = calls

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def get(self, url: str, *, timeout: float) -> _HealthResponse:
        self._calls.append((url, timeout))
        result = self._responses.popleft()
        if isinstance(result, BaseException):
            raise result
        return result  # type: ignore[return-value]


def test_harvest_dependency_is_in_base_and_pdf_is_optional() -> None:
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    base_dependencies = pyproject.split("[project.optional-dependencies]", 1)[0]
    optional_dependencies = pyproject.split("[project.optional-dependencies]", 1)[1]

    assert '"curl-cffi>=0.7"' in base_dependencies
    assert "weasyprint>=" not in base_dependencies
    assert "harvest =" not in optional_dependencies
    assert 'pdf = [' in optional_dependencies
    assert '"weasyprint>=60.0"' in optional_dependencies


def test_ml_remains_optional() -> None:
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    base_dependencies = pyproject.split("[project.optional-dependencies]", 1)[0]
    optional_dependencies = pyproject.split("[project.optional-dependencies]", 1)[1]

    assert "spacy" not in base_dependencies
    assert 'ml = [' in optional_dependencies
    assert '"spacy>=3.7,<4.0"' in optional_dependencies


def _patch_health_client(monkeypatch, responses: list[object]) -> list[tuple[str, float]]:
    pending = deque(responses)
    calls: list[tuple[str, float]] = []
    monkeypatch.setattr(
        cli_main.httpx,
        "AsyncClient",
        lambda **_kwargs: _FakeAsyncClient(pending, calls),
    )
    return calls


@pytest.mark.asyncio
async def test_server_auto_starts_when_not_running(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_health_client(monkeypatch, [RuntimeError("offline"), _HealthResponse()])
    proc = Mock()
    proc.poll.return_value = None
    popen = Mock(return_value=proc)
    monkeypatch.setattr(cli_main.subprocess, "Popen", popen)
    monotonic = iter([0.0, 1.0])
    monkeypatch.setattr(cli_main, "time", SimpleNamespace(monotonic=lambda: next(monotonic)))
    monkeypatch.setattr(cli_main.asyncio, "sleep", AsyncMock())

    result = await cli_main._ensure_server_running("http://localhost:8000", "user@example.com")

    assert result is proc
    popen.assert_called_once_with(
        [cli_main.sys.executable, "-m", "cli.main", "serve"],
        stdout=cli_main.subprocess.DEVNULL,
        stderr=cli_main.subprocess.DEVNULL,
    )
    assert calls == [
        ("http://localhost:8000/health", 3.0),
        ("http://localhost:8000/health", 2.0),
    ]


@pytest.mark.asyncio
async def test_existing_server_is_not_restarted(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_health_client(monkeypatch, [_HealthResponse()])
    popen = Mock()
    monkeypatch.setattr(cli_main.subprocess, "Popen", popen)

    result = await cli_main._ensure_server_running("http://localhost:8000", "user@example.com")

    assert result is None
    popen.assert_not_called()


@pytest.mark.asyncio
async def test_server_failed_to_start_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_health_client(monkeypatch, [RuntimeError("offline"), RuntimeError("still offline")])
    proc = Mock()
    proc.poll.return_value = 1
    monkeypatch.setattr(cli_main.subprocess, "Popen", Mock(return_value=proc))
    monkeypatch.setattr(
        cli_main,
        "time",
        SimpleNamespace(monotonic=iter([0.0, 1.0]).__next__),
    )
    monkeypatch.setattr(cli_main.asyncio, "sleep", AsyncMock())

    result = await cli_main._ensure_server_running("http://localhost:8000", "user@example.com")

    assert result is None


@pytest.mark.asyncio
async def test_server_start_timeout_terminates_process(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_health_client(monkeypatch, [RuntimeError("offline"), RuntimeError("still offline")])
    proc = Mock()
    proc.poll.return_value = None
    monkeypatch.setattr(cli_main.subprocess, "Popen", Mock(return_value=proc))
    monkeypatch.setattr(
        cli_main,
        "time",
        SimpleNamespace(monotonic=iter([0.0, 16.0]).__next__),
    )
    monkeypatch.setattr(cli_main.asyncio, "sleep", AsyncMock())

    result = await cli_main._ensure_server_running("http://localhost:8000", "user@example.com")

    assert result is None
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=5.0)


@pytest.mark.asyncio
async def test_ctrl_c_during_server_start_terminates_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_health_client(monkeypatch, [RuntimeError("offline")])
    proc = Mock()
    proc.poll.return_value = None
    monkeypatch.setattr(cli_main.subprocess, "Popen", Mock(return_value=proc))
    monkeypatch.setattr(cli_main, "time", SimpleNamespace(monotonic=lambda: 0.0))
    monkeypatch.setattr(cli_main.asyncio, "sleep", AsyncMock(side_effect=KeyboardInterrupt))

    with pytest.raises(KeyboardInterrupt):
        await cli_main._ensure_server_running("http://localhost:8000", "user@example.com")

    proc.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_managed_server_is_terminated_after_investigation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = Mock()
    monkeypatch.setattr(cli_main, "get_backend_url", lambda: "http://localhost:8000")
    monkeypatch.setattr(cli_main, "_ensure_server_running", AsyncMock(return_value=proc))
    run = AsyncMock(return_value=0)
    monkeypatch.setattr(cli_main, "_investigate_run", run)
    stop = Mock()
    monkeypatch.setattr(cli_main, "_stop_managed_server", stop)

    result = await cli_main._investigate("user@example.com", "json", None, 30, None)

    assert result == 0
    run.assert_awaited_once()
    stop.assert_called_once_with(proc)


@pytest.mark.asyncio
async def test_managed_server_is_terminated_on_investigation_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = Mock()
    monkeypatch.setattr(cli_main, "get_backend_url", lambda: "http://localhost:8000")
    monkeypatch.setattr(cli_main, "_ensure_server_running", AsyncMock(return_value=proc))
    monkeypatch.setattr(cli_main, "_investigate_run", AsyncMock(side_effect=RuntimeError("boom")))
    stop = Mock()
    monkeypatch.setattr(cli_main, "_stop_managed_server", stop)

    with pytest.raises(RuntimeError, match="boom"):
        await cli_main._investigate("user@example.com", "json", None, 30, None)

    stop.assert_called_once_with(proc)


@pytest.mark.asyncio
async def test_managed_server_is_terminated_on_ctrl_c(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = Mock()
    monkeypatch.setattr(cli_main, "get_backend_url", lambda: "http://localhost:8000")
    monkeypatch.setattr(cli_main, "_ensure_server_running", AsyncMock(return_value=proc))
    monkeypatch.setattr(cli_main, "_investigate_run", AsyncMock(side_effect=KeyboardInterrupt))
    stop = Mock()
    monkeypatch.setattr(cli_main, "_stop_managed_server", stop)

    with pytest.raises(KeyboardInterrupt):
        await cli_main._investigate("user@example.com", "json", None, 30, None)

    stop.assert_called_once_with(proc)


@pytest.mark.asyncio
async def test_failed_auto_start_returns_exit_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "get_backend_url", lambda: "http://localhost:8000")
    monkeypatch.setattr(cli_main, "_ensure_server_running", AsyncMock(return_value=None))
    _patch_health_client(monkeypatch, [RuntimeError("offline")])
    run = AsyncMock()
    monkeypatch.setattr(cli_main, "_investigate_run", run)

    result = await cli_main._investigate("user@example.com", "json", None, 30, None)

    assert result == 3
    run.assert_not_awaited()
