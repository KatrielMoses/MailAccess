"""0.17.4 — contract tests for the keyless ``GET /v1/coverage`` count teaser.

Network-free: the corpus engine client is mocked. The endpoint returns ONLY an
integer count (never rows/PII), honors the lawful-basis gate, rejects consumer
domains, filters to on-domain contacts, fails CLOSED on suppression errors, and
caches per domain. Gate these (policy/contract suite; keep off eval/baseline/*).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.api.routes.enrich as enrich_mod
import backend.config as config_mod
from backend.core import mailaccess_pro_client as pro_client


def _engine_row(**over: Any) -> dict[str, Any]:
    row = {"full_name": "Jane Doe", "email": "jane@acme.com", "source": "linkedin"}
    row.update(over)
    return row


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(enrich_mod.router, prefix="/v1")
    return app


@pytest.fixture(autouse=True)
def _clear_coverage_cache() -> Iterator[None]:
    enrich_mod._COVERAGE_CACHE.clear()
    yield
    enrich_mod._COVERAGE_CACHE.clear()


@pytest.fixture
def lawful_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        config_mod.settings, "mailaccess_pro_lawful_basis_established", True
    )
    yield


def _mock_pool(monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Mock the engine as a single-page domain pool; return a call counter."""
    calls = {"n": 0}

    async def _search(query, *, mode, limit, offset, verified_only=False):
        calls["n"] += 1
        page = rows[offset : offset + limit]
        return {
            "rows": page,
            "organizations": [],
            "total": len(rows),
            "mode": mode,
            "has_more": offset + len(page) < len(rows),
        }

    monkeypatch.setattr(pro_client, "search", _search)
    return calls


def test_lawful_basis_off_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        config_mod.settings, "mailaccess_pro_lawful_basis_established", False
    )
    resp = TestClient(_make_app()).get("/v1/coverage", params={"domain": "acme.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
    assert body["reason"] == "lead_tier_not_yet_available"


def test_invalid_domain_is_unavailable(lawful_on: None) -> None:
    resp = TestClient(_make_app()).get("/v1/coverage", params={"domain": "not a domain"})
    assert resp.json() == {"available": False, "reason": "invalid_domain"}


def test_consumer_domain_counts_zero(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    _mock_pool(monkeypatch, [_engine_row(email="x@gmail.com")])
    resp = TestClient(_make_app()).get("/v1/coverage", params={"domain": "gmail.com"})
    body = resp.json()
    assert body["available"] is True
    assert body["count"] == 0


def test_counts_only_on_domain_contacts(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    _mock_pool(
        monkeypatch,
        [
            _engine_row(email="jane@acme.com"),
            _engine_row(email="bob@acme.com"),
            _engine_row(email="off@other.com"),  # off-domain → excluded
            _engine_row(email="jane@acme.com"),  # duplicate → collapsed
        ],
    )
    resp = TestClient(_make_app()).get("/v1/coverage", params={"domain": "acme.com"})
    body = resp.json()
    assert body["available"] is True
    assert body["domain"] == "acme.com"
    assert body["count"] == 2


def test_response_never_contains_rows_or_pii(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    _mock_pool(monkeypatch, [_engine_row(phone="+1-555-0100", city="Austin")])
    body = TestClient(_make_app()).get(
        "/v1/coverage", params={"domain": "acme.com"}
    ).json()
    assert set(body) == {"available", "domain", "count"}
    text = str(body)
    for leaked in ("jane@acme.com", "Jane Doe", "555", "Austin"):
        assert leaked not in text


def test_result_is_cached_per_domain(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    calls = _mock_pool(monkeypatch, [_engine_row(email="jane@acme.com")])
    client = TestClient(_make_app())
    first = client.get("/v1/coverage", params={"domain": "acme.com"}).json()
    after_first = calls["n"]
    second = client.get("/v1/coverage", params={"domain": "acme.com"}).json()
    assert first == second == {"available": True, "domain": "acme.com", "count": 1}
    # The second call is served from cache — no additional engine query.
    assert calls["n"] == after_first


def test_engine_unavailable_fails_open(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    async def _boom(*a: Any, **k: Any):
        raise enrich_mod.ProEngineUnavailable("dead")

    monkeypatch.setattr(pro_client, "search", _boom)
    body = TestClient(_make_app()).get(
        "/v1/coverage", params={"domain": "acme.com"}
    ).json()
    assert body["available"] is False
    assert body["reason"] == "engine_unavailable"
