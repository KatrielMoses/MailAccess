from __future__ import annotations

from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from backend.core.brave_dorker import BraveSearchDorker
from backend.modules.email_search_dork import EmailSearchDorkModule


class _Response:
    def __init__(self, status_code: int, payload: dict[str, object] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict[str, object]:
        return self._payload


@pytest.mark.asyncio
async def test_brave_search_parses_json_results_and_sends_token() -> None:
    client = type("Client", (), {})()
    client.get = AsyncMock(return_value=_Response(200, {
        "web": {"results": [{
            "title": "Example",
            "description": "Contact alice@example.com",
            "url": "https://example.com/team",
        }]}
    }))

    results, error, blocked = await BraveSearchDorker("secret").search(
        client, '"@example.com"', count=50
    )

    assert error is None
    assert blocked is False
    assert results[0].snippet == "Contact alice@example.com"
    kwargs = client.get.await_args.kwargs
    assert kwargs["headers"]["X-Subscription-Token"] == "secret"
    assert kwargs["params"]["count"] == 20


@pytest.mark.asyncio
async def test_brave_search_classifies_auth_and_rate_limit() -> None:
    client = type("Client", (), {})()
    client.get = AsyncMock(side_effect=[_Response(401), _Response(429)])
    dorker = BraveSearchDorker("secret")

    _, auth_error, auth_blocked = await dorker.search(client, "one")
    _, rate_error, rate_blocked = await dorker.search(client, "two")

    assert "authentication" in str(auth_error).lower()
    assert auth_blocked is True
    assert "rate limit" in str(rate_error).lower()
    assert rate_blocked is True


@pytest.mark.asyncio
async def test_email_dork_uses_brave_provider_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Client:
        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str, **_kwargs: object) -> _Response:
            return _Response(200, {"web": {"results": [{
                "title": "Team",
                "description": "alice@acme.com",
                "url": "https://acme.com/team",
            }]}})

    monkeypatch.setattr("backend.modules.email_search_dork.build_client", lambda **_kwargs: _Client())
    monkeypatch.setattr(
        "backend.modules.email_search_dork.build_dork_queries",
        lambda *_args, **_kwargs: [SimpleNamespace(query='"@acme.com"')],
    )
    monkeypatch.setattr("backend.modules.email_search_dork.settings.search_provider", "brave")
    monkeypatch.setattr("backend.modules.email_search_dork.settings.brave_search_api_key", "secret")
    monkeypatch.setattr("backend.modules.email_search_dork.settings.enable_email_search_dork", True)

    result = await EmailSearchDorkModule().run("acme.com", fetch=object())

    assert result.status.value == "success"
    assert result.metadata["search_provider"] == "brave"
    assert result.metadata["brave_results_collected"] == 1
    assert result.findings[0]["metadata"]["found_via_brave"] is True
