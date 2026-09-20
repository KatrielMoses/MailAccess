"""0.17.0 Brief C — hard I/O typing & bounds at the hosted boundary.

C1 typed lead schema (projection + connector + evidence), C2 total deadline /
bounded queue / response cap / cancellation, C3 engine-shape validation →
unavailable (never 500), C4 distinct-lead depth, C5 401-timing work.

Network-free: httpx is exercised via MockTransport; the queue/schema helpers are
unit-tested directly.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.api.routes import enrich as E
from backend.core import mailaccess_pro_client as pro_client
from backend.core import mailaccess_pro_connector as connector
from backend.core.domain_harvest_orchestrator import _pro_evidence_entry
from backend.core.pro_query_queue import ProQueryQueue, ProQueueUnavailable


# ===========================================================================
# C1 — typed lead schema
# ===========================================================================
def _raw(**over: Any) -> dict[str, Any]:
    row = {
        "full_name": "Jane Doe",
        "title": "VP Engineering",
        "email": "jane@acme.com",
        "linkedin_url": "https://www.linkedin.com/in/janedoe",
        "source": "linkedin",
        "is_verified": True,
    }
    row.update(over)
    return row


def test_c1_nested_source_rejected() -> None:
    p = E._project_lead(_raw(source={"phone": "SECRET"}))
    assert p["source"] is None


def test_c1_nested_name_rejected() -> None:
    p = E._project_lead(_raw(full_name={"x": "y"}))
    assert p["name"] is None


def test_c1_overlong_strings_rejected() -> None:
    p = E._project_lead(_raw(full_name="a" * 5000, title="b" * 5000))
    assert p["name"] is None and p["title"] is None


def test_c1_corpus_verified_strict_bool() -> None:
    assert E._project_lead(_raw(is_verified="false"))["corpus_verified"] is False
    assert E._project_lead(_raw(is_verified=1))["corpus_verified"] is False
    assert E._project_lead(_raw(is_verified=True))["corpus_verified"] is True


def test_c1_unknown_source_dropped() -> None:
    assert E._project_lead(_raw(source="mystery"))["source"] is None
    assert E._project_lead(_raw(source="linkedin"))["source"] == "linkedin"


def test_c1_linkedin_origin_must_be_linkedin() -> None:
    ok = E._project_lead(_raw(linkedin_url="https://linkedin.com/in/alice"))
    assert ok["linkedin_slug"] == "alice"
    bad = E._project_lead(_raw(linkedin_url="https://evil.example/in/synthetic"))
    assert bad["linkedin_slug"] is None and bad["linkedin_url"] is None


def test_c1_connector_sanitizes_leads() -> None:
    dirty = {
        "name": {"x": 1},  # non-scalar → None
        "title": "Eng",
        "email": "bob@acme.com",
        "linkedin_slug": "bob",
        "source": "not-a-source",  # unknown → None
        "corpus_verified": "true",  # non-strict → False
    }
    out = connector._sanitize_leads([dirty, {"name": "No Email"}, "garbage"])
    assert len(out) == 1  # the emailless + non-dict dropped
    lead = out[0]
    assert lead["name"] is None
    assert lead["email"] == "bob@acme.com"
    assert lead["source"] is None
    assert lead["corpus_verified"] is False
    assert lead["linkedin_url"] == "https://linkedin.com/in/bob"


def test_c1_evidence_entry_only_scalars() -> None:
    ev = _pro_evidence_entry({"name": {"nested": "PII"}, "source": {"phone": "x"}})
    meta = ev["metadata"]
    assert meta["full_name"] is None
    assert meta["corpus_source"] is None
    assert not any(isinstance(v, dict | list) for v in meta.values())


# ===========================================================================
# C2 — bounded queue + cancellation
# ===========================================================================
def test_c2_queue_bounded_and_releasable() -> None:
    async def run() -> None:
        q = ProQueryQueue(global_concurrency=2, acquire_timeout=0.05)
        started = asyncio.Event()
        release = asyncio.Event()

        async def hold(k: str) -> None:
            async with q.acquire(k):
                started.set()
                await release.wait()

        holders = [asyncio.create_task(hold(str(i))) for i in range(2)]
        await started.wait()
        await asyncio.sleep(0)  # let both acquire
        # A third distinct key can't get a global slot within the bound → raises.
        with pytest.raises(ProQueueUnavailable):
            async with q.acquire("third"):
                pass
        release.set()
        await asyncio.gather(*holders)
        # Slots released → a fresh acquire succeeds immediately.
        async with q.acquire("later"):
            pass

    asyncio.run(run())


def test_c2_queue_releases_on_cancellation() -> None:
    async def run() -> None:
        q = ProQueryQueue(global_concurrency=1, acquire_timeout=5.0)
        holding = asyncio.Event()
        release = asyncio.Event()

        async def hold() -> None:
            async with q.acquire("k"):
                holding.set()
                await release.wait()

        t = asyncio.create_task(hold())
        await holding.wait()
        # Second waiter blocks on the single slot; cancel it → must not leak.
        waiter = asyncio.create_task(_acquire_once(q, "other"))
        await asyncio.sleep(0.02)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        await t
        # The global slot was freed by the holder; a new key acquires.
        async with q.acquire("fresh"):
            pass

    asyncio.run(run())


async def _acquire_once(q: ProQueryQueue, k: str) -> None:
    async with q.acquire(k):
        pass


# ===========================================================================
# C3 — engine shape validation → ProEngineUnavailable (route → unavailable, not 500)
# ===========================================================================
def _mock_pro_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    real_cls = httpx.AsyncClient

    def factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        return real_cls(transport=transport)

    monkeypatch.setattr(pro_client.httpx, "AsyncClient", factory)
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_base_url", "http://engine.test")


@pytest.mark.parametrize(
    "body",
    [{"rows": 42}, {"rows": [], "organizations": 42}, {"rows": [], "total": float("inf")}],
)
def test_c3_malformed_shape_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]
) -> None:
    import json

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(body))

    _mock_pro_client(monkeypatch, handler)
    with pytest.raises(pro_client.ProEngineUnavailable):
        asyncio.run(pro_client.search("acme.com", mode="domain", limit=1, offset=0))


def test_c3_well_formed_shape_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=json.dumps({"rows": [{"email": "a@acme.com"}], "total": 1})
        )

    _mock_pro_client(monkeypatch, handler)
    block = asyncio.run(pro_client.search("acme.com", mode="domain", limit=1, offset=0))
    assert block["rows"] == [{"email": "a@acme.com"}] and block["total"] == 1


def test_c3_route_helper_rejects_bad_blocks() -> None:
    for bad in ({"rows": 42}, {"organizations": 42}, {"total": float("nan")}, 5):
        with pytest.raises(pro_client.ProEngineUnavailable):
            E._validate_engine_block(bad)
    E._validate_engine_block({"rows": [], "organizations": [], "total": None})  # ok


# ===========================================================================
# C4 — distinct-lead depth (dedupe while filling, bounded)
# ===========================================================================
def test_c4_collect_dedupes_and_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    async def search(query, *, mode, limit, offset, verified_only=False):
        calls.append(limit)
        # Always the same address, always more → a duplicate flood.
        return {"rows": [{"email": "dup@acme.com"} for _ in range(limit)],
                "organizations": [], "total": 10 ** 9, "mode": mode, "has_more": True}

    monkeypatch.setattr(pro_client, "search", search)
    rows, total, _ = asyncio.run(E._collect("acme.com", cap=500))
    assert len(rows) == 1  # distinct
    assert len(calls) <= E._MAX_PAGES  # bounded, no unbounded loop


def test_c4_collect_distinct_across_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = [{"email": f"u{i}@acme.com"} for i in range(30)]

    async def search(query, *, mode, limit, offset, verified_only=False):
        page = pool[offset : offset + limit]
        return {"rows": page, "organizations": [], "total": len(pool),
                "mode": mode, "has_more": offset + len(page) < len(pool)}

    monkeypatch.setattr(pro_client, "search", search)
    rows, _total, _ = asyncio.run(E._collect("acme.com", cap=500))
    assert len(rows) == 30
    assert len({r["email"] for r in rows}) == 30
