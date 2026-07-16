"""0.12.7 — ``mailaccess keys test {KEY_NAME}`` tests.

Covers the live API-call validation path: each supported key has
its own URL / header shape; invalid keys emit a dashboard link;
network errors emit an unreachable line; unsupported key names
exit with a clear error.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from cli.main import _run_key_test, app


# ---------------------------------------------------------------------------
# Test the _run_key_test helper directly (faster than the full CLI loop)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_github_token_valid_shows_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    fake_response = httpx.Response(
        200,
        json={
            "resources": {
                "core": {"limit": 5000, "remaining": 4987, "reset": 9999999999}
            }
        },
        request=httpx.Request("GET", "https://api.github.com/rate_limit"),
    )

    class _StubClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            return fake_response

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _StubClient)
    status, detail, dashboard = await _run_key_test("GITHUB_TOKEN")
    assert status == "valid"
    assert "4987" in detail
    assert "5000" in detail
    assert dashboard == "https://github.com/settings/tokens"


@pytest.mark.asyncio
async def test_github_token_invalid_shows_401_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_bad")
    fake_response = httpx.Response(
        401, request=httpx.Request("GET", "https://api.github.com/rate_limit")
    )

    class _StubClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            return fake_response

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _StubClient)
    status, detail, dashboard = await _run_key_test("GITHUB_TOKEN")
    assert status == "invalid"
    assert "401" in detail
    assert "github.com/settings/tokens" in dashboard


@pytest.mark.asyncio
async def test_hunter_key_valid_shows_credits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUNTER_IO_API_KEY", "hunter_test")
    fake_response = httpx.Response(
        200,
        json={"data": {"calls_used": 2, "calls_available": 23}},
        request=httpx.Request("GET", "https://api.hunter.io/v2/account"),
    )

    class _StubClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            return fake_response

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _StubClient)
    status, detail, dashboard = await _run_key_test("HUNTER_IO_API_KEY")
    assert status == "valid"
    assert "Credits" in detail
    assert "23" in detail
    assert dashboard == "https://hunter.io/api-keys"


@pytest.mark.asyncio
async def test_brave_key_invalid_shows_401_with_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "BSA_bad")
    fake_response = httpx.Response(
        401, request=httpx.Request("GET", "https://api.search.brave.com/res/v1/web/search?q=test")
    )

    class _StubClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            return fake_response

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _StubClient)
    status, detail, dashboard = await _run_key_test("BRAVE_SEARCH_API_KEY")
    assert status == "invalid"
    assert "401" in detail
    assert "brave" in dashboard.lower()


@pytest.mark.asyncio
async def test_unsupported_key_name_shows_error() -> None:
    status, detail, _ = await _run_key_test("NOT_A_REAL_KEY")
    assert status == "unsupported"
    assert detail == ""


@pytest.mark.asyncio
async def test_missing_key_shows_missing_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    # Also nuke the settings attribute to make sure the lookup
    # falls through to "missing".
    from backend.config import settings
    monkeypatch.setattr(settings, "github_token", None)
    status, detail, dashboard = await _run_key_test("GITHUB_TOKEN")
    assert status == "missing"
    assert "github.com/settings/tokens" in dashboard


@pytest.mark.asyncio
async def test_hibp_key_valid_for_404_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HIBP returns 404 for unknown accounts; 200 for known. Both = key works."""
    monkeypatch.setenv("HIBP_API_KEY", "hibp_test")
    fake_response = httpx.Response(
        404, request=httpx.Request("GET", "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com")
    )

    class _StubClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            return fake_response

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _StubClient)
    status, detail, dashboard = await _run_key_test("HIBP_API_KEY")
    assert status == "valid"
    assert dashboard == "https://haveibeenpwned.com/API/Key"


@pytest.mark.asyncio
async def test_hibp_key_invalid_for_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HIBP_API_KEY", "hibp_bad")
    fake_response = httpx.Response(
        401, request=httpx.Request("GET", "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com")
    )

    class _StubClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            return fake_response

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _StubClient)
    status, detail, dashboard = await _run_key_test("HIBP_API_KEY")
    assert status == "invalid"


@pytest.mark.asyncio
async def test_unreachable_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")

    class _BoomClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _BoomClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
            raise httpx.ConnectError("simulated network failure")

    monkeypatch.setattr("cli.main.httpx.AsyncClient", _BoomClient)
    status, detail, _ = await _run_key_test("GITHUB_TOKEN")
    assert status == "unreachable"
    assert "ConnectError" in detail or "simulated" in detail


# ---------------------------------------------------------------------------
# CLI integration: `mailaccess keys test` end-to-end
# ---------------------------------------------------------------------------
def test_keys_test_github_via_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")

    async def _fake(name: str) -> tuple[str, str, str]:
        return ("valid", "Rate limit: 4987/5000 remaining", "https://github.com/settings/tokens")

    monkeypatch.setattr("cli.main._run_key_test", _fake)
    result = CliRunner().invoke(app, ["keys", "test", "GITHUB_TOKEN"])
    assert result.exit_code == 0
    assert "Valid" in result.stdout
    assert "4987" in result.stdout


def test_keys_test_unsupported_exits_2() -> None:
    result = CliRunner().invoke(app, ["keys", "test", "NOT_A_REAL_KEY"])
    assert result.exit_code == 2
    assert "Unsupported" in result.stdout
