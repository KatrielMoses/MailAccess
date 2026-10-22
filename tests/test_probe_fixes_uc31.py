from __future__ import annotations

import asyncio

import httpx

from backend.core.http_client import build_client
from backend.modules.username_platforms import _variant_allowed


def test_mastodon_instances_never_get_dotted_handles() -> None:
    tagged = {"tags": ["mastodon", "social"], "uri_check": "https://masto.example/@{username}"}
    by_host = {"tags": ["social"], "uri_check": "https://mstdn.example/@{username}"}
    other = {"tags": ["social"], "uri_check": "https://example.com/{username}"}
    assert not _variant_allowed(tagged, "jane.doe") and _variant_allowed(tagged, "janedoe")
    assert not _variant_allowed(by_host, "jane.doe")
    assert _variant_allowed(other, "jane.doe")
    assert not _variant_allowed({"regexCheck": "^[a-z]+$"}, "jane.doe")  # site rule still applies


def _headers_seen(monkeypatch, token, url, headers=None):
    import backend.config as config  # the live settings object (other tests may swap it)

    monkeypatch.setattr(config.settings, "github_token", token, raising=False)
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200, json={})

    async def go():
        async with build_client(transport=httpx.MockTransport(handler)) as client:
            await client.get(url, headers=headers or {})

    asyncio.run(go())
    return seen


def test_github_token_on_github_api_only(monkeypatch) -> None:
    seen = _headers_seen(monkeypatch, "ghp_test_token", "https://api.github.com/users/janedoe")
    assert seen.get("authorization") == "Bearer ghp_test_token"
    seen = _headers_seen(monkeypatch, "ghp_test_token", "https://example.com/api")
    assert "authorization" not in seen  # never sent to another host
    seen = _headers_seen(monkeypatch, None, "https://api.github.com/users/janedoe")
    assert "authorization" not in seen  # unauthenticated still works
    seen = _headers_seen(monkeypatch, "ghp_test_token", "https://api.github.com/x",
                         headers={"Authorization": "Bearer caller-own"})
    assert seen["authorization"] == "Bearer caller-own"  # a caller's own auth wins
