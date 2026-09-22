"""0.17.6 — contract tests for the keyless ``GET /v1/founder`` seats counter.

Network-free: the entitlement count is mocked. The endpoint returns only integers
+ a price label (never key material), honors the lawful-basis gate, derives
``seats_left`` live (total − provisioned keys, floored at 0), caches briefly, and
fails closed to ``available: false`` on a store error. Gate these (policy/contract
suite; keep off eval/baseline/*).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.api.routes.enrich as enrich_mod
import backend.config as config_mod


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(enrich_mod.router, prefix="/v1")
    return app


@pytest.fixture(autouse=True)
def _clear_founder_cache() -> Iterator[None]:
    enrich_mod._FOUNDER_CACHE.clear()
    yield
    enrich_mod._FOUNDER_CACHE.clear()


@pytest.fixture
def lawful_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        config_mod.settings, "mailaccess_pro_lawful_basis_established", True
    )
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_founder_seats_total", 100)
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_founder_price_label", "$19/mo")
    yield


def _mock_count(monkeypatch: pytest.MonkeyPatch, n: int) -> dict[str, int]:
    calls = {"n": 0}

    async def _count() -> int:
        calls["n"] += 1
        return n

    monkeypatch.setattr(enrich_mod, "count_pro_keys", _count)
    return calls


def test_lawful_basis_off_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        config_mod.settings, "mailaccess_pro_lawful_basis_established", False
    )
    body = TestClient(_make_app()).get("/v1/founder").json()
    assert body["available"] is False
    assert body["reason"] == "lead_tier_not_yet_available"


def test_seats_left_is_total_minus_used(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    _mock_count(monkeypatch, 37)
    body = TestClient(_make_app()).get("/v1/founder").json()
    assert body == {
        "available": True,
        "seats_total": 100,
        "seats_left": 63,
        "price_label": "$19/mo",
    }


def test_seats_left_never_negative(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    _mock_count(monkeypatch, 140)  # oversubscribed
    body = TestClient(_make_app()).get("/v1/founder").json()
    assert body["seats_left"] == 0


def test_response_has_no_key_material(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    _mock_count(monkeypatch, 1)
    body = TestClient(_make_app()).get("/v1/founder").json()
    assert set(body) == {"available", "seats_total", "seats_left", "price_label"}


def test_count_is_cached(monkeypatch: pytest.MonkeyPatch, lawful_on: None) -> None:
    calls = _mock_count(monkeypatch, 10)
    client = TestClient(_make_app())
    first = client.get("/v1/founder").json()
    second = client.get("/v1/founder").json()
    assert first == second
    assert calls["n"] == 1  # second served from the 60s cache


def test_store_error_fails_closed(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None
) -> None:
    async def _boom() -> int:
        raise RuntimeError("db down")

    monkeypatch.setattr(enrich_mod, "count_pro_keys", _boom)
    body = TestClient(_make_app()).get("/v1/founder").json()
    assert body["available"] is False
    assert body["reason"] == "engine_unavailable"
