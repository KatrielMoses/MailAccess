from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from backend.modules.github_commits import GitHubDomainCommitsModule


class _Response:
    status_code = 200
    headers: dict[str, str] = {}

    def json(self) -> dict[str, object]:
        return {"items": [
            {"sha": "abcdef123456", "html_url": "https://github.com/acme/repo/commit/abcdef1", "commit": {"author": {"name": "Alice Smith", "email": "alice@acme.com", "date": "2026-01-01"}}, "repository": {"full_name": "acme/repo", "html_url": "https://github.com/acme/repo"}},
            {"sha": "duplicate", "commit": {"author": {"name": "Alice Smith", "email": "alice@acme.com"}}, "repository": {"full_name": "acme/other"}},
            {"sha": "offdomain", "commit": {"author": {"name": "Other", "email": "other@example.com"}}, "repository": {"full_name": "acme/other"}},
        ]}


class _ItemsResponse:
    status_code = 200
    headers: dict[str, str] = {}

    def __init__(self, items: list[dict[str, object]]) -> None:
        self._items = items

    def json(self) -> dict[str, object]:
        return {"items": self._items}


class _Client:
    def __init__(self) -> None:
        self.get = AsyncMock(return_value=_Response())

    async def __aenter__(self) -> "_Client":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None


@pytest.mark.asyncio
async def test_domain_commit_search_filters_and_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _Client()
    monkeypatch.setattr("backend.modules.github_commits.build_client", lambda **_kwargs: client)
    result = await GitHubDomainCommitsModule().run("acme.com")
    assert result.status.value == "success"
    assert len(result.findings) == 1
    assert result.findings[0]["metadata"]["email"] == "alice@acme.com"
    assert result.findings[0]["metadata"]["source_type"] == "github_commit_author"
    assert result.metadata["query"] == "author-email:@acme.com"
    client.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_domain_commit_search_pivots_from_signal_pool_names(monkeypatch: pytest.MonkeyPatch) -> None:
    matching_item = {
        "sha": "namepivot123",
        "html_url": "https://github.com/acme/repo/commit/namepivot",
        "commit": {"author": {"name": "Alice Smith", "email": "alice@acme.com"}},
        "repository": {"full_name": "acme/repo", "html_url": "https://github.com/acme/repo"},
    }
    client = _Client()
    client.get = AsyncMock(side_effect=[_ItemsResponse([]), _ItemsResponse([]), _ItemsResponse([matching_item])])
    monkeypatch.setattr("backend.modules.github_commits.build_client", lambda **_kwargs: client)

    class _SignalPool:
        def get_names_for_domain(self, domain: str) -> list[dict[str, object]]:
            assert domain == "acme.com"
            return [{"name": "Alice Smith"}, {"name": "Alice Smith"}, {"name": "SingleName"}]

    result = await GitHubDomainCommitsModule().run("acme.com", signal_pool=_SignalPool())

    assert result.status.value == "success"
    assert len(result.findings) == 1
    assert result.findings[0]["metadata"]["email"] == "alice@acme.com"
    assert result.metadata["name_queries"] == ['author:"Alice Smith"']
    assert result.metadata["names_considered"] == 1
    assert client.get.await_count == 3
