"""Tests for :mod:`backend.modules.email_search_dork`.

These tests cover the orchestrator-side wiring of the dork module:
* the ``scrapingant_zone`` kwarg threaded into the dorkers
* the ``aggressive`` keyword threading through ``build_dork_queries``
  (Phase 4 — see ``build_dork_queries(domain, lite_mode, aggressive)``)

We do NOT exercise the cache layer here — the dork module's own
dorkers are unit-tested in
:mod:`tests.core.test_bing_dorker` / :mod:`tests.core.test_duckduckgo_dorker`
with a real :class:`CachedFetch`.  Here we just need to prove the
kwarg routing is correct.
"""
from __future__ import annotations

from types import SimpleNamespace

import httpx

import backend.modules.email_search_dork as email_search_dork
from backend.config import settings
from backend.modules.email_search_dork import EmailSearchDorkModule


class _FakeDorker:
    """Minimal stand-in for DuckDuckGoDorker / BingDorker.

    Records constructor kwargs so the test can assert on the
    ``scrapingant_zone`` threading.  ``search`` returns an empty
    success tuple — the test doesn't care about result bodies here.
    """

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    async def search(self, query: str):
        return [], False


class _ErrorDorker(_FakeDorker):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.calls = 0
        self._last_error = None

    async def search(self, query: str):
        self.calls += 1
        self._last_error = "request timed out"
        return [], False


def _patch_fast_success_path(monkeypatch) -> None:
    """Patch the dork module's success-path knobs.

    The lambda for ``build_dork_queries`` accepts the same kwargs
    (``lite_mode``, ``aggressive``) that the production code passes
    — Phase 4 added ``aggressive`` and the test fixture must keep up.
    Without it, the dorker call site blows up with
    ``TypeError: ... got an unexpected keyword argument 'aggressive'``.
    """
    monkeypatch.setattr(settings, "enable_email_search_dork", True)
    monkeypatch.setattr(settings, "dork_lite_mode", True)
    monkeypatch.setattr(settings, "dork_max_queries_per_engine", 1)
    monkeypatch.setattr(settings, "dork_ddg_delay_seconds", 0.0)
    monkeypatch.setattr(settings, "dork_bing_delay_seconds", 0.0)
    monkeypatch.setattr(
        email_search_dork,
        "build_dork_queries",
        # NOTE: ``aggressive`` is part of the Phase-4 signature.
        lambda domain, *, lite_mode, aggressive=False: [  # noqa: ARG005
            SimpleNamespace(query=f'"@{domain}"')
        ],
    )


async def test_email_search_dork_passes_dorking_zone_to_dorkers(
    monkeypatch,
) -> None:
    """When ``use_proxies=True``, the dorkers must receive ``scrapingant_zone='dorking'``."""
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
    """When proxies are off, ``scrapingant_zone`` is NOT threaded into build_client.

    ``build_client`` is the httpx-side factory; the dorking zone belongs
    on the dorker constructor, not on the shared httpx client.  This
    test pins that boundary so a future refactor doesn't accidentally
    pull zone-routing up into the wrong layer.
    """
    _patch_fast_success_path(monkeypatch)
    captured_kwargs: list[dict[str, object]] = []

    monkeypatch.setattr(email_search_dork, "DuckDuckGoDorker", _FakeDorker)
    monkeypatch.setattr(email_search_dork, "BingDorker", _FakeDorker)

    def fake_build_client(**kwargs):
        captured_kwargs.append(kwargs)
        return httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        )

    monkeypatch.setattr(email_search_dork, "build_client", fake_build_client)

    await EmailSearchDorkModule().run("example.com", lite_mode=True)

    assert "scrapingant_zone" not in captured_kwargs[0]


async def test_email_search_dork_threaded_aggressive_kwarg(monkeypatch) -> None:
    """``aggressive=True`` must reach ``build_dork_queries`` without TypeError.

    Phase 4 added the ``aggressive`` keyword; this test guards against
    the regression where the production-side call site passes
    ``aggressive=effective_aggressive`` but the test's stub lambda
    doesn't accept it (which would crash with TypeError instead of
    producing the expected SKIPPED-with-no-queries path).
    """
    _patch_fast_success_path(monkeypatch)
    captured: list[dict[str, object]] = []

    def recording_build_dork_queries(domain, *, lite_mode, aggressive=False):
        captured.append(
            {"domain": domain, "lite_mode": lite_mode, "aggressive": aggressive}
        )
        return [SimpleNamespace(query=f'"@{domain}"')]

    monkeypatch.setattr(
        email_search_dork, "build_dork_queries", recording_build_dork_queries
    )
    monkeypatch.setattr(email_search_dork, "DuckDuckGoDorker", _FakeDorker)
    monkeypatch.setattr(email_search_dork, "BingDorker", _FakeDorker)
    monkeypatch.setattr(
        email_search_dork,
        "build_client",
        lambda **_: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        ),
    )

    await EmailSearchDorkModule().run(
        "example.com", lite_mode=True, aggressive=True
    )

    assert captured
    assert captured[0]["aggressive"] is True
    assert captured[0]["lite_mode"] is True
    assert captured[0]["domain"] == "example.com"


async def test_email_search_dork_skipped_when_master_disabled(monkeypatch) -> None:
    """When the master toggle is off, the module must short-circuit to SKIPPED."""
    monkeypatch.setattr(settings, "enable_email_search_dork", False)
    result = await EmailSearchDorkModule().run("example.com", lite_mode=True)
    assert result.status.value == "skipped"


async def test_email_search_dork_fast_fails_repeated_engine_errors(monkeypatch) -> None:
    _patch_fast_success_path(monkeypatch)
    monkeypatch.setattr(settings, "dork_max_queries_per_engine", 5)
    monkeypatch.setattr(
        email_search_dork,
        "build_dork_queries",
        lambda domain, *, lite_mode, aggressive=False: [  # noqa: ARG005
            SimpleNamespace(query=f'"@{domain}" {index}')
            for index in range(5)
        ],
    )
    dorkers = []

    class ErrorDorker(_ErrorDorker):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            dorkers.append(self)

    monkeypatch.setattr(email_search_dork, "DuckDuckGoDorker", ErrorDorker)
    monkeypatch.setattr(email_search_dork, "BingDorker", ErrorDorker)
    monkeypatch.setattr(
        email_search_dork,
        "build_client",
        lambda **_: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        ),
    )

    result = await EmailSearchDorkModule().run("example.com", lite_mode=True)

    assert len(dorkers) == 2
    assert {d.calls for d in dorkers} == {2}
    assert result.metadata["ddg_failed"] is True
    assert result.metadata["bing_failed"] is True
