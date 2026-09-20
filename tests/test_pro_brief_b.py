"""0.17.0 Brief B — classification rigor (P1 #4/#5).

Acceptance tests: business is decided by positive on-domain validation and consumer
domains are not companies (B2), and company resolution verifies identity via ranked
actual org records rather than guessing a domain from the query token (B3).

Network-free: the corpus engine client is mocked; injection is exercised directly.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.routes import enrich as E
from backend.config import settings
from backend.core import mailaccess_pro_client as engine
from backend.core.domain_harvest_orchestrator import (
    HarvestedEmail,
    _inject_pro_leads,
)
from backend.core.product_mode import ProductMode

PUBLIC = ProductMode.PUBLIC_BUSINESS_CONTACT
_KEY = "map_test_key"


def _client(monkeypatch: pytest.MonkeyPatch, search) -> TestClient:
    async def valid(key):
        return key == "brief-b"

    monkeypatch.setattr(E, "validate_pro_key", valid)
    monkeypatch.setattr(engine, "search", search)
    monkeypatch.setattr(settings, "mailaccess_pro_lawful_basis_established", True)
    app = FastAPI()
    app.include_router(E.router, prefix="/v1")
    return TestClient(app, raise_server_exceptions=False)


def _post(client: TestClient, **body) -> dict[str, Any]:
    return client.post(
        "/v1/enrich", headers={"Authorization": "Bearer brief-b"}, json=body
    ).json()


# ===========================================================================
# B2 — business by positive on-domain validation; consumer domains not companies
# ===========================================================================
@pytest.mark.parametrize(
    "domain,expected",
    [
        ("yahoo.co.uk", True), ("gmail.com", True), ("hotmail.fr", True),
        ("gmx.de", True), ("outlook.de", True),
        ("acme.com", False), ("stripe.com", False), ("mail.acme.com", False),
    ],
)
def test_b2_consumer_domain_detection(domain: str, expected: bool) -> None:
    assert E._is_consumer_domain(domain) is expected


def test_b2_consumer_domain_query_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def search(*a, **k):
        return {"rows": [{"email": "x@yahoo.co.uk", "full_name": "X"}], "total": 1}

    client = _client(monkeypatch, search)
    body = _post(client, query="yahoo.co.uk", type="domain")
    assert body["status"] == "empty"
    assert body["leads"] == []


def test_b2_off_domain_never_business(monkeypatch: pytest.MonkeyPatch) -> None:
    async def search(query, *, mode, limit, offset, verified_only=False):
        # A polluted domain response with off-domain rows mixed in.
        return {
            "rows": [
                {"full_name": "On Dom", "email": "on@acme.com"},
                {"full_name": "Off Dom", "email": "off@gmail.com"},
                {"full_name": "Other Co", "email": "x@other.com"},
            ],
            "organizations": [], "total": 3, "mode": mode, "has_more": False,
        }

    client = _client(monkeypatch, search)
    body = _post(client, query="acme.com", type="domain")
    emails = [ld["email"] for ld in body["leads"]]
    assert emails == ["on@acme.com"]  # only the true on-domain address


def test_b2_injection_off_domain_business_dropped() -> None:
    # Re-audit: an off-domain corpus lead is DROPPED, not retained as a business row;
    # only the true on-domain address is injected into the serving-only channel.
    channel: list[HarvestedEmail] = []
    _inject_pro_leads(
        [],
        [{"email": "on@acme.com", "name": "On"}, {"email": "off@elsewhere.com", "name": "Off"}],
        mode=PUBLIC,
        key=_KEY,
        domain="acme.com",
        corpus_leads_out=channel,
    )
    by_email = {e.email: e for e in channel}
    assert set(by_email) == {"on@acme.com"}
    assert by_email["on@acme.com"].on_domain is True


# ===========================================================================
# B3 — company resolution verifies identity via ranked actual org records
# ===========================================================================
def test_b3_substring_org_does_not_auto_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    # Re-audit: "Acme" with only a prefix/substring org ("Acme Scam") must NOT
    # silently resolve — a non-exact match is not identity → disambiguation.
    async def search(q, **k):
        return {"rows": [], "organizations": [
            {"company": "Acme Scam", "domain": "scam.example", "employees": 5},
        ], "total": 0}

    monkeypatch.setattr(engine, "search", search)
    resolved = asyncio.run(E._resolve_company("Acme"))
    assert resolved["status"] == "disambiguation"
    assert resolved["candidates"][0]["domain"] == "scam.example"


def test_b3_single_exact_org_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    # A single exact-name org resolves via ranked records (no fabricated domain).
    async def search(q, **k):
        return {"rows": [], "organizations": [
            {"company": "Stripe", "domain": "stripe.com", "employees": 8000},
        ], "total": 0}

    monkeypatch.setattr(engine, "search", search)
    resolved = asyncio.run(E._resolve_company("Stripe"))
    assert resolved["status"] == "ok" and resolved["domain"] == "stripe.com"


def test_b3_no_org_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # No matching org record → empty. A domain is NEVER fabricated from the token.
    async def search(q, **k):
        return {"rows": [], "organizations": [], "total": 0}

    monkeypatch.setattr(engine, "search", search)
    resolved = asyncio.run(E._resolve_company("Audit"))
    assert resolved["status"] == "empty"
    assert "domain" not in resolved


def test_b3_same_name_orgs_disambiguate(monkeypatch: pytest.MonkeyPatch) -> None:
    async def search(*a, **k):
        return {"organizations": [
            {"company": "Acme", "domain": "big.example", "employees": 500},
            {"company": "Acme", "domain": "small.example", "employees": 10},
        ]}

    monkeypatch.setattr(engine, "search", search)
    # Two exact "Acme" orgs share the top score → genuinely ambiguous.
    resolved = asyncio.run(E._resolve_company("Acme"))
    assert resolved["status"] == "disambiguation"
    assert {c["domain"] for c in resolved["candidates"]} == {"big.example", "small.example"}
