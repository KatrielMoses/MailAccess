from __future__ import annotations

from types import SimpleNamespace

import httpx

import backend.modules.email_search_dork as email_search_dork
from backend.config import settings
from backend.modules.email_search_dork import EmailSearchDorkModule


class _FakeDorker:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    async def search(self, query: str):
        return [], False


def _patch_fast_success_path(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enable_email_search_dork", True)
    monkeypatch.setattr(settings, "dork_lite_mode", True)
    monkeypatch.setattr(settings, "dork_max_queries_per_engine", 1)
    monkeypatch.setattr(settings, "dork_ddg_delay_seconds", 0.0)
    monkeypatch.setattr(settings, "dork_bing_delay_seconds", 0.0)
    monkeypatch.setattr(
        email_search_dork,
        "build_dork_queries",
        lambda domain, *, lite_mode: [SimpleNamespace(query=f'"@{domain}"')],
    )


async def test_email_search_dork_passes_dorking_zone_to_dorkers(
    monkeypatch,
) -> None:
    _patch_fast_success_path(monkeypatch)
    constructed: dict[str, list[dict[str, object]]] = {"ddg": [], "bing": []}

    class FakeDuckDuckGoDorker(_FakeDorker):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            constructed["ddg"].append(kwargs)

    class FakeBingDorker(_FakeDorker):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            constructed["bing"].append(kwargs)

    monkeypatch.setattr(email_search_dork, "DuckDuckGoDorker", FakeDuckDuckGoDorker)
    monkeypatch.setattr(email_search_dork, "BingDorker", FakeBingDorker)
    monkeypatch.setattr(
        email_search_dork,
        "build_client",
        lambda **_: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        ),
    )

    await EmailSearchDorkModule().run("example.com", lite_mode=True)

    assert constructed["ddg"][0]["scrapingant_zone"] == "dorking"
    assert constructed["bing"][0]["scrapingant_zone"] == "dorking"


async def test_email_search_dork_direct_client_uses_dorking_zone(
    monkeypatch,
) -> None:
    _patch_fast_success_path(monkeypatch)
    captured_kwargs: list[dict[str, object]] = []

    monkeypatch.setattr(email_search_dork, "DuckDuckGoDorker", _FakeDorker)
    monkeypatch.setattr(email_search_dork, "BingDorker", _FakeDorker)

    def fake_build_client(**kwargs):
        captured_kwargs.append(kwargs)
        return httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))

    monkeypatch.setattr(email_search_dork, "build_client", fake_build_client)

    await EmailSearchDorkModule().run("example.com", lite_mode=True)

    assert "scrapingant_zone" not in captured_kwargs[0]
