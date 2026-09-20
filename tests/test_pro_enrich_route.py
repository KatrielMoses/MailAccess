"""0.17.0 Phase 1 — contract tests for ``POST /v1/enrich`` and the Pro entitlement
store.

Gate these (policy/contract suite; keep off eval/baseline/*). Network-free: the
corpus engine client is mocked, the entitlement store uses a self-managed temp
SQLite DB. Covers the frozen §2 contract + the honesty invariant.
"""

from __future__ import annotations

import asyncio
import importlib
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.api.routes.enrich as enrich_mod
import backend.config as config_mod
from backend.core import mailaccess_pro_client as pro_client
from backend.core.pro_query_queue import ProQueryQueue, reset_queue_for_tests

_VALID_KEY = "map_test_valid_key"


# ---------------------------------------------------------------------------
# Engine-row fixtures (the full engine shape, incl. the PII that must be dropped)
# ---------------------------------------------------------------------------
def _engine_row(**over: Any) -> dict[str, Any]:
    row = {
        "full_name": "Jane Doe",
        "title": "VP Engineering",
        "email": "jane@acme.com",
        "domain": "acme.com",
        "phone": "+1-555-0100",
        "website": "https://acme.com",
        "city": "Austin",
        "state": "TX",
        "country": "US",
        "industry": "Software",
        "seniority": "vp",
        "linkedin_url": "https://www.linkedin.com/in/janedoe",
        "email_status": "valid",
        "is_verified": True,
        "source": "linkedin",
    }
    row.update(over)
    return row


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(enrich_mod.router, prefix="/v1")
    return app


@pytest.fixture(autouse=True)
def _reset_queue() -> Iterator[None]:
    reset_queue_for_tests()
    yield
    reset_queue_for_tests()


@pytest.fixture
def lawful_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        config_mod.settings, "mailaccess_pro_lawful_basis_established", True
    )
    yield


@pytest.fixture
def valid_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    async def _validate(key: str | None) -> bool:
        return key == _VALID_KEY

    monkeypatch.setattr(enrich_mod, "validate_pro_key", _validate)
    yield _VALID_KEY


def _mock_search(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    async def _search(query, *, mode, limit, offset, verified_only=False):
        return handler(query, mode, limit, offset)

    monkeypatch.setattr(pro_client, "search", _search)


def _mock_domain_pool(monkeypatch: pytest.MonkeyPatch, all_rows, verified_rows) -> None:
    """Mock the engine as a paginating domain corpus with verified filtering.

    ``total`` reflects the pool being queried (verified vs all), so the route's
    500-cap depth logic branches correctly. Pages honor limit/offset/has_more."""

    async def _search(query, *, mode, limit, offset, verified_only=False):
        pool = verified_rows if verified_only else all_rows
        page = pool[offset : offset + limit]
        return {
            "rows": page,
            "organizations": [],
            "total": len(pool),
            "mode": mode,
            "has_more": offset + len(page) < len(pool),
        }

    monkeypatch.setattr(pro_client, "search", _search)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {_VALID_KEY}"}


# ---------------------------------------------------------------------------
# 1. Domain query → projected leads, PII fields absent.
# ---------------------------------------------------------------------------
def test_domain_query_projects_and_drops_pii(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    _mock_search(
        monkeypatch,
        lambda q, mode, limit, offset: {
            "rows": [_engine_row(), _engine_row(email="bob@acme.com", full_name="Bob")],
            "organizations": [],
            "total": 2,
            "mode": mode,
            "has_more": False,
        },
    )
    client = TestClient(_make_app())
    resp = client.post(
        "/v1/enrich", json={"query": "acme.com", "type": "domain"}, headers=_auth()
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["provenance"] == "MailAccess Pro corpus"
    assert len(body["leads"]) == 2
    for lead in body["leads"]:
        assert set(lead) == {
            "name",
            "title",
            "email",
            "linkedin_slug",
            "linkedin_url",
            "source",
            "corpus_verified",
        }
        for pii in ("phone", "city", "state", "country", "website", "industry", "seniority"):
            assert pii not in lead
    assert body["leads"][0]["name"] == "Jane Doe"
    assert body["leads"][0]["corpus_verified"] is True


# ---------------------------------------------------------------------------
# 2. Company resolution: one org → domain+leads; 2+ → disambiguation; 0 → empty.
# ---------------------------------------------------------------------------
def test_company_ranked_resolves(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    # Item A — a company name ranks the actual org records; a unique exact match
    # resolves without disambiguation (no domain is ever fabricated from the token).
    def handler(query, mode, limit, offset):
        if mode == "company":
            return {
                "rows": [],
                "organizations": [
                    {"company": "Acme Corp", "domain": "acme.com", "employees": 500},
                    {"company": "Restacme Holdings", "domain": "restacme.com", "employees": 9},
                ],
                "total": 2, "mode": mode, "has_more": False,
            }
        assert query == "acme.com"  # the resolved (exact-match) domain drives leads
        return {"rows": [_engine_row()], "organizations": [], "total": 1,
                "mode": mode, "has_more": False}

    _mock_search(monkeypatch, handler)
    client = TestClient(_make_app())
    body = client.post(
        "/v1/enrich", json={"query": "Acme Corp", "type": "company"}, headers=_auth()
    ).json()
    assert body["status"] == "ok"
    assert body["company"] == {"name": "Acme Corp", "domain": "acme.com", "employees": 500}
    assert len(body["leads"]) == 1


def test_company_multiple_orgs_disambiguation(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    # Genuine near-tie: two exact-name matches with close employee counts → the
    # employee tie-break is not decisive → disambiguation. (Multi-word query so
    # domain-first is skipped and ranking runs.)
    _mock_search(
        monkeypatch,
        lambda q, mode, limit, offset: {
            "rows": [],
            "organizations": [
                {"company": "Acme Group", "domain": "acme.com", "employees": 100},
                {"company": "Acme Group", "domain": "acme.io", "employees": 90},
            ],
            "total": 2,
            "mode": mode,
            "has_more": False,
        },
    )
    client = TestClient(_make_app())
    resp = client.post(
        "/v1/enrich", json={"query": "Acme Group", "type": "company"}, headers=_auth()
    )
    body = resp.json()
    assert body["status"] == "disambiguation"
    assert body["leads"] == []
    assert len(body["candidates"]) == 2
    assert {c["domain"] for c in body["candidates"]} == {"acme.com", "acme.io"}


def test_company_zero_orgs_empty(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    _mock_search(
        monkeypatch,
        lambda q, mode, limit, offset: {
            "rows": [],
            "organizations": [],
            "total": 0,
            "mode": mode,
            "has_more": False,
        },
    )
    client = TestClient(_make_app())
    resp = client.post(
        "/v1/enrich", json={"query": "Nonexistent Co", "type": "company"}, headers=_auth()
    )
    assert resp.json()["status"] == "empty"


# ---------------------------------------------------------------------------
# Fix 1a — the live engine returns ``employees`` as a STRING ('3') or None. The
# route must never 500 (a raw int()/comparison in the org ranking would TypeError).
# ---------------------------------------------------------------------------
def test_string_employees_resolves_without_crash(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    def handler(query, mode, limit, offset):
        if mode == "company":
            return {
                "rows": [],
                "organizations": [
                    {"company": "Acme Corp", "domain": "acme.com", "employees": "500"},
                    {"company": "Acme Corporation", "domain": "acme.io", "employees": None},
                ],
                "total": 2, "mode": mode, "has_more": False,
            }
        assert query == "acme.com"  # resolved exact org drives the leads
        return {"rows": [_engine_row()], "organizations": [], "total": 1,
                "mode": mode, "has_more": False}

    _mock_search(monkeypatch, handler)
    client = TestClient(_make_app())
    resp = client.post(
        "/v1/enrich", json={"query": "Acme Corp", "type": "company"}, headers=_auth()
    )
    assert resp.status_code == 200  # never a 500 on a string employees field
    body = resp.json()
    assert body["status"] == "ok"
    assert body["company"]["domain"] == "acme.com"
    assert body["company"]["employees"] == 500  # coerced from the string


def test_string_employees_disambiguation_sorts(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    # Two same-name orgs with STRING employees → disambiguation ranked employees-desc
    # (the sort key is the crash site; string/None must not break it).
    _mock_search(
        monkeypatch,
        lambda q, mode, limit, offset: {
            "rows": [],
            "organizations": [
                {"company": "Acme", "domain": "small.example", "employees": "10"},
                {"company": "Acme", "domain": "big.example", "employees": "500"},
                {"company": "Acme", "domain": "unknown.example", "employees": None},
            ],
            "total": 3, "mode": mode, "has_more": False,
        },
    )
    client = TestClient(_make_app())
    body = client.post(
        "/v1/enrich", json={"query": "Acme", "type": "company"}, headers=_auth()
    ).json()
    assert body["status"] == "disambiguation"
    assert [c["domain"] for c in body["candidates"]] == [
        "big.example", "small.example", "unknown.example",
    ]
    assert all(isinstance(c["employees"], int) for c in body["candidates"])


# ---------------------------------------------------------------------------
# 3. LinkedIn slug normalization across URL forms + the null case.
# ---------------------------------------------------------------------------
def test_linkedin_normalization(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    rows = [
        _engine_row(linkedin_url="http://www.linkedin.com/in/alice", email="a@x.com"),
        _engine_row(linkedin_url="linkedin.com/in/bob", email="b@x.com"),
        _engine_row(linkedin_url="https://linkedin.com/in/carol/", email="c@x.com"),
        _engine_row(linkedin_url="", email="d@x.com"),
        _engine_row(linkedin_url="https://twitter.com/eve", email="e@x.com"),
    ]
    _mock_search(
        monkeypatch,
        lambda q, mode, limit, offset: {
            "rows": rows,
            "organizations": [],
            "total": len(rows),
            "mode": mode,
            "has_more": False,
        },
    )
    client = TestClient(_make_app())
    leads = client.post(
        "/v1/enrich", json={"query": "x.com", "type": "domain"}, headers=_auth()
    ).json()["leads"]
    assert leads[0]["linkedin_slug"] == "alice"
    assert leads[0]["linkedin_url"] == "https://linkedin.com/in/alice"
    assert leads[1]["linkedin_slug"] == "bob"
    assert leads[2]["linkedin_slug"] == "carol"
    assert leads[2]["linkedin_url"] == "https://linkedin.com/in/carol"
    assert leads[3]["linkedin_slug"] is None and leads[3]["linkedin_url"] is None
    assert leads[4]["linkedin_slug"] is None and leads[4]["linkedin_url"] is None


# ---------------------------------------------------------------------------
# 4. Lawful-basis False → unavailable even with a valid key.
# ---------------------------------------------------------------------------
def test_lawful_basis_off_unavailable(
    monkeypatch: pytest.MonkeyPatch, valid_key: str
) -> None:
    monkeypatch.setattr(
        config_mod.settings, "mailaccess_pro_lawful_basis_established", False
    )

    def _boom(*a, **k):  # engine must NOT be called when the gate is closed
        raise AssertionError("engine called despite lawful-basis gate")

    monkeypatch.setattr(pro_client, "search", _boom)
    client = TestClient(_make_app())
    resp = client.post(
        "/v1/enrich", json={"query": "acme.com", "type": "domain"}, headers=_auth()
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["reason"] == "lead_tier_not_yet_available"


# ---------------------------------------------------------------------------
# 5. Invalid/absent key → 401; valid key → served.
# ---------------------------------------------------------------------------
def test_invalid_and_absent_key_401(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    _mock_search(
        monkeypatch,
        lambda q, mode, limit, offset: {
            "rows": [_engine_row()],
            "organizations": [],
            "total": 1,
            "mode": mode,
            "has_more": False,
        },
    )
    client = TestClient(_make_app())
    payload = {"query": "acme.com", "type": "domain"}
    # absent
    assert client.post("/v1/enrich", json=payload).status_code == 401
    # wrong
    assert (
        client.post(
            "/v1/enrich",
            json={"query": "acme.com", "type": "domain"},
            headers={"Authorization": "Bearer wrong"},
        ).status_code
        == 401
    )
    # valid via X-MailAccess-Pro-Key header too
    ok = client.post(
        "/v1/enrich",
        json={"query": "acme.com", "type": "domain"},
        headers={"X-MailAccess-Pro-Key": _VALID_KEY},
    )
    assert ok.status_code == 200 and ok.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 6. Engine raises → unavailable (fail-open), never 5xx.
# ---------------------------------------------------------------------------
def test_engine_error_fails_open(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    async def _raise(*a, **k):
        raise pro_client.ProEngineUnavailable("down")

    monkeypatch.setattr(pro_client, "search", _raise)
    client = TestClient(_make_app())
    resp = client.post(
        "/v1/enrich", json={"query": "acme.com", "type": "domain"}, headers=_auth()
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 7. Queue: two concurrent same-key requests serialize.
# ---------------------------------------------------------------------------
def test_queue_serializes_same_key(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    events: list[str] = []

    async def _search(query, *, mode, limit, offset, verified_only=False):
        events.append("start")
        await asyncio.sleep(0.05)
        events.append("end")
        return {
            "rows": [_engine_row()],
            "organizations": [],
            "total": 1,
            "mode": mode,
            "has_more": False,
        }

    monkeypatch.setattr(pro_client, "search", _search)
    app = _make_app()

    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
            payload = {"query": "acme.com", "type": "domain"}
            await asyncio.gather(
                ac.post("/v1/enrich", json=payload, headers=_auth()),
                ac.post("/v1/enrich", json=payload, headers=_auth()),
            )

    asyncio.run(_run())
    # Serialized: the second call's start comes only after the first's end.
    assert events == ["start", "end", "start", "end"]


def test_queue_unit_serializes_per_key() -> None:
    q = ProQueryQueue(global_concurrency=8)
    order: list[str] = []

    async def worker(tag: str) -> None:
        async with q.acquire("same-hash"):
            order.append(f"{tag}-in")
            await asyncio.sleep(0.02)
            order.append(f"{tag}-out")

    async def _run() -> None:
        await asyncio.gather(worker("a"), worker("b"))

    asyncio.run(_run())
    assert order in (
        ["a-in", "a-out", "b-in", "b-out"],
        ["b-in", "b-out", "a-in", "a-out"],
    )


# ---------------------------------------------------------------------------
# Round 2 Item A — company resolution quality.
# ---------------------------------------------------------------------------
def test_company_ranking_drops_substring_junk(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    # Multi-word query (domain-first skipped). A prefix match beats 10 unrelated
    # substring-only orgs — the junk never surfaces as candidates.
    junk = [
        {"company": f"Restripe {i} LLC", "domain": f"restripe{i}.com", "employees": 3}
        for i in range(10)
    ]
    real = {"company": "Stripe Payments", "domain": "stripe.com", "employees": 8000}

    def handler(query, mode, limit, offset):
        if mode == "company":
            return {"rows": [], "organizations": junk + [real], "total": 11,
                    "mode": mode, "has_more": False}
        return {"rows": [_engine_row(email="jane@stripe.com", domain="stripe.com")],
                "organizations": [], "total": 1, "mode": mode, "has_more": False}

    _mock_search(monkeypatch, handler)
    client = TestClient(_make_app())
    body = client.post(
        "/v1/enrich", json={"query": "Stripe Payments", "type": "company"}, headers=_auth()
    ).json()
    assert body["status"] == "ok"  # not disambiguation over 11 junk orgs
    assert body["company"]["domain"] == "stripe.com"


# ---------------------------------------------------------------------------
# Round 2 Item B — 500-cap depth policy.
# ---------------------------------------------------------------------------
def test_depth_under_cap_returns_all(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    rows = [
        _engine_row(email=f"u{i}@acme.io", is_verified=(i % 2 == 0)) for i in range(20)
    ]
    verified = [r for r in rows if r["is_verified"]]
    _mock_domain_pool(monkeypatch, rows, verified)
    client = TestClient(_make_app())
    body = client.post(
        "/v1/enrich", json={"query": "acme.io", "type": "domain", "limit": 500},
        headers=_auth(),
    ).json()
    assert body["status"] == "ok"
    assert len(body["leads"]) == 20  # all, incl. unverified
    assert any(lead["corpus_verified"] is False for lead in body["leads"])


def test_depth_over_cap_returns_500_verified(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    verified = [_engine_row(email=f"v{i}@acme.io", is_verified=True) for i in range(600)]
    unverified = [_engine_row(email=f"u{i}@acme.io", is_verified=False) for i in range(200)]
    _mock_domain_pool(monkeypatch, verified + unverified, verified)
    client = TestClient(_make_app())
    body = client.post(
        "/v1/enrich", json={"query": "acme.io", "type": "domain", "limit": 500},
        headers=_auth(),
    ).json()
    assert len(body["leads"]) == 500
    assert all(lead["corpus_verified"] is True for lead in body["leads"])


def test_depth_over_cap_fills_unverified(
    monkeypatch: pytest.MonkeyPatch, lawful_on: None, valid_key: str
) -> None:
    # total > 500 but verified < 500 → fill to 500 verified-first, then unverified.
    verified = [_engine_row(email=f"v{i}@acme.io", is_verified=True) for i in range(300)]
    unverified = [_engine_row(email=f"u{i}@acme.io", is_verified=False) for i in range(400)]
    _mock_domain_pool(monkeypatch, verified + unverified, verified)
    client = TestClient(_make_app())
    body = client.post(
        "/v1/enrich", json={"query": "acme.io", "type": "domain", "limit": 500},
        headers=_auth(),
    ).json()
    assert len(body["leads"]) == 500
    v = sum(1 for lead in body["leads"] if lead["corpus_verified"])
    u = sum(1 for lead in body["leads"] if not lead["corpus_verified"])
    assert v == 300 and u == 200  # verified-first, filled with unverified


# ---------------------------------------------------------------------------
# 8. Honesty regression — corpus_verified is provenance, never a confirmation.
# ---------------------------------------------------------------------------
def test_confirmed_verifications_unchanged() -> None:
    from backend.core.eligibility import _CONFIRMED_VERIFICATIONS

    assert _CONFIRMED_VERIFICATIONS == frozenset(
        {"verified", "confirmed", "smtp_verified", "provider_verified", "valid"}
    )
    assert "corpus_verified" not in _CONFIRMED_VERIFICATIONS


# ---------------------------------------------------------------------------
# Entitlement store — real temp DB (hashed storage, active-only validation).
# ---------------------------------------------------------------------------
@pytest.fixture
def pro_keys_db() -> Iterator[Any]:
    path = Path(tempfile.mkdtemp(prefix="prokeys-test-"))
    saved = config_mod.settings.database_url
    config_mod.settings.database_url = f"sqlite+aiosqlite:///{(path / 'k.db').as_posix()}"
    import backend.db.database as db

    importlib.reload(db)
    import backend.core.pro_keys as pk

    importlib.reload(pk)

    async def _setup() -> None:
        await db.init_db()
        await db.engine.dispose()

    asyncio.run(_setup())
    try:
        yield pk
    finally:
        config_mod.settings.database_url = saved
        shutil.rmtree(path, ignore_errors=True)


def test_entitlement_store_roundtrip(pro_keys_db: Any) -> None:
    pk = pro_keys_db

    async def _run() -> None:
        assert await pk.validate_pro_key("nope") is False
        assert await pk.add_pro_key("live-key", notes="acme") is True
        # Idempotent per hash.
        assert await pk.add_pro_key("live-key") is False
        assert await pk.validate_pro_key("live-key") is True
        # Stored hashed — raw key never present in the listing.
        listed = await pk.list_pro_keys()
        assert listed and all("live-key" not in str(r) for r in listed)
        # Deactivation revokes.
        assert await pk.deactivate_pro_key("live-key") is True
        assert await pk.validate_pro_key("live-key") is False

    asyncio.run(_run())
