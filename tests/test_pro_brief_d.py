"""0.17.0 Brief D — suppression wiring at the hosted tier + local injection.

D1: the hosted /v1/enrich route and the local `_inject_pro_leads` both run every
candidate through the suppression index before serving / injecting; a store that
can't be read fails CLOSED.

Network-free: the corpus engine client is mocked; suppression is exercised with a
real in-memory SuppressionIndex and monkeypatched loaders.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.routes import enrich as E
from backend.config import settings
from backend.core import mailaccess_pro_client as engine
from backend.core import suppression
from backend.core.domain_harvest_orchestrator import (
    HarvestedEmail,
    _inject_pro_leads,
)
from backend.core.product_mode import ProductMode
from backend.core.suppression import (
    SuppressionIndex,
    SuppressionScope,
    SuppressionUnavailable,
    match_key,
)

PUBLIC = ProductMode.PUBLIC_BUSINESS_CONTACT
_KEY = "map_test_key"


def _index_denying(*emails: str, domains: tuple[str, ...] = ()) -> SuppressionIndex:
    return SuppressionIndex(
        email_hashes=frozenset(match_key(SuppressionScope.EMAIL, e) for e in emails),
        domain_hashes=frozenset(match_key(SuppressionScope.DOMAIN, d) for d in domains),
        company_norms=frozenset(),
        _meta={},
    )


def _client(monkeypatch: pytest.MonkeyPatch, search, index_loader) -> TestClient:
    async def valid(key):
        return key == "brief-d"

    monkeypatch.setattr(E, "validate_pro_key", valid)
    monkeypatch.setattr(engine, "search", search)
    monkeypatch.setattr(settings, "mailaccess_pro_lawful_basis_established", True)
    monkeypatch.setattr(suppression, "load_index", index_loader)
    app = FastAPI()
    app.include_router(E.router, prefix="/v1")
    return TestClient(app, raise_server_exceptions=False)


def _post(client: TestClient, **body) -> dict[str, Any]:
    return client.post("/v1/enrich", headers={"Authorization": "Bearer brief-d"}, json=body).json()


# ===========================================================================
# D1 — hosted route consults suppression
# ===========================================================================
def test_d1_per_lead_business_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def search(query, *, mode, limit, offset, verified_only=False):
        return {
            "rows": [
                {"full_name": "Good", "email": "good@acme.com", "source": "linkedin"},
                {"full_name": "Bad", "email": "bad@acme.com", "source": "linkedin"},
            ],
            "organizations": [], "total": 2, "mode": mode, "has_more": False,
        }

    idx = _index_denying("bad@acme.com")

    async def loader():
        return idx

    client = _client(monkeypatch, search, loader)
    body = _post(client, query="acme.com", type="domain")
    emails = [ld["email"] for ld in body["leads"]]
    assert emails == ["good@acme.com"]  # the suppressed subject is filtered out


def test_d1_whole_domain_suppressed_serves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    async def search(query, *, mode, limit, offset, verified_only=False):
        return {"rows": [{"full_name": "A", "email": "a@acme.com", "source": "linkedin"}],
                "organizations": [], "total": 1, "mode": mode, "has_more": False}

    idx = _index_denying(domains=("acme.com",))

    async def loader():
        return idx

    client = _client(monkeypatch, search, loader)
    body = _post(client, query="acme.com", type="domain")
    assert body["status"] == "empty"
    assert body["leads"] == []


def test_d1_store_unreadable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def search(query, *, mode, limit, offset, verified_only=False):
        return {"rows": [{"full_name": "A", "email": "a@acme.com", "source": "linkedin"}],
                "organizations": [], "total": 1, "mode": mode, "has_more": False}

    async def loader():
        raise SuppressionUnavailable("store down")

    client = _client(monkeypatch, search, loader)
    body = _post(client, query="acme.com", type="domain")
    assert body["status"] == "unavailable"
    assert body["reason"] == "suppression_unavailable"
    assert body["leads"] == []


# ===========================================================================
# D1 — local injection consults suppression
# ===========================================================================
def test_d1_injection_filters_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    idx = _index_denying("bad@acme.com")
    monkeypatch.setattr(suppression, "load_index_sync", lambda: idx)
    channel: list[HarvestedEmail] = []
    _inject_pro_leads(
        [],
        [{"email": "good@acme.com", "name": "Good"}, {"email": "bad@acme.com", "name": "Bad"}],
        mode=PUBLIC,
        key=_KEY,
        domain="acme.com",
        corpus_leads_out=channel,
    )
    assert [e.email for e in channel] == ["good@acme.com"]


def test_d1_injection_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom():
        raise SuppressionUnavailable("store down")

    monkeypatch.setattr(suppression, "load_index_sync", boom)
    channel: list[HarvestedEmail] = []
    _inject_pro_leads(
        [],
        [{"email": "good@acme.com", "name": "Good"}],
        mode=PUBLIC,
        key=_KEY,
        domain="acme.com",
        corpus_leads_out=channel,
    )
    assert channel == []  # fail-closed: no corpus injected when the store is unreadable
