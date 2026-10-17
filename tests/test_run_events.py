"""The run event log: ordering, replay, many viewers, resume, lifecycle, traces.

The engine runs for real (real phases, real database, real emitter); only the modules
are fakes that carry real module names, so labels and techniques are the real ones.
No network, no provider credits.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from backend.core import phases as phases_mod
from backend.core import run_events
from backend.core.engine import InvestigationEngine
from backend.db import database as _database
from backend.db.models import Finding, Investigation, ModuleRun, RunEvent
from backend.modules.base import BaseModule, ModuleResult, ModuleStatus

EMAIL = "alice@example.com"


# ------------------------------------------------------------------ fake modules
def _module(name: str, run, priority: int = 100) -> type[BaseModule]:
    # Plain classes, not BaseModule subclasses: subclasses would join the real module
    # registry and shadow the real modules in other tests.
    return type(
        f"Fake_{name}", (),
        {"name": name, "description": f"fake {name}", "priority": priority, "run": run},
    )


async def _account_discovery(self, email, **_):
    return ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[{
            "platform": "GitHub", "profile_url": "https://github.com", "confidence": "medium",
            "verification": "unverified", "source": "account_discovery",
            "metadata": {"verification": "unverified", "flow": "register"},
        }],
    )


async def _browser_probe(self, email, **_):
    return ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[{
            "platform": "github.com", "url": "https://github.com/login", "confidence": "medium",
            "verification": "unverified",
            "metadata": {"flow": "email_first", "method": "browser-oracle"},
        }],
    )


async def _username_sweep(self, email, sink=None, **_):
    from backend.core import run_events as ev

    total = 12
    hits = []
    for i in range(total):
        await asyncio.sleep(0.01)
        ev.module_progress("username_platforms", i + 1, total)
        if i % 3 == 0:
            hit = {
                "platform": f"Site{i}", "profile_url": f"https://site{i}.example/alice",
                "username": "alice", "confidence": "low",
                "metadata": {"source": "username_platforms", "verification": "unverified",
                             "speculative": True, "check_type": "status_code"},
            }
            hits.append(hit)
            if sink is not None:
                sink.append(hit)
    return ModuleResult(status=ModuleStatus.SUCCESS, findings=hits)


async def _slow(self, email, **_):
    await asyncio.sleep(0.3)
    return ModuleResult(status=ModuleStatus.SUCCESS_EMPTY)


async def _hibp(self, email, **_):
    return ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[{"platform": "Adobe", "metadata": {"breach_name": "Adobe"}}],
    )


async def _never(self, email, **_):  # pragma: no cover - must be budget-skipped
    return ModuleResult(status=ModuleStatus.SUCCESS_EMPTY)


async def _dns(self, email, **_):
    return ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[{"platform": "dns_mx", "confidence": "high",
                   "metadata": {"mx_provider": "Google Workspace"}}],
    )


async def _partial(self, email, **_):
    return ModuleResult(status=ModuleStatus.PARTIAL, errors=["timed out"])


FAKES = [
    _module("dns_lookup", _dns),
    _module("shodan", _never),  # no key in tests: listed as unavailable, never counted
    _module("account_discovery", _account_discovery),
    _module("browser_account_probe", _browser_probe),
    _module("username_platforms", _username_sweep),
    _module("hibp", _hibp),
]


@pytest.fixture
def fake_modules(monkeypatch: pytest.MonkeyPatch, isolated_db):
    import backend.modules as modules_pkg
    from backend.core import mx_resolver

    monkeypatch.setattr(modules_pkg, "get_all_modules", lambda: list(FAKES))
    monkeypatch.setattr(phases_mod, "PHASE_DAG", (phases_mod.PrimaryPhase(),))

    async def _resolved(domain):
        return SimpleNamespace(status=mx_resolver.MxStatus.RESOLVED)

    monkeypatch.setattr(mx_resolver, "resolve_mx_typed", _resolved)

    async def _no_webhooks(self, *a, **k):
        return None

    monkeypatch.setattr(InvestigationEngine, "_dispatch_webhooks", _no_webhooks)
    monkeypatch.setattr(InvestigationEngine, "_record_observations", _no_webhooks)
    return FAKES


async def _new_investigation(email: str = EMAIL) -> str:
    async with _database.AsyncSessionLocal() as db:
        inv = Investigation(email=email, canonical_email=email)
        db.add(inv)
        await db.commit()
        return inv.id


async def _run(engine: InvestigationEngine, inv_id: str):
    queue = await engine.investigate(EMAIL, inv_id)
    emitter = run_events.get(inv_id)
    assert emitter is not None
    while (await queue.get()) is not None:
        pass
    return emitter


async def _saved(inv_id: str) -> list[RunEvent]:
    async with _database.AsyncSessionLocal() as db:
        return list(
            (await db.execute(
                select(RunEvent).where(RunEvent.investigation_id == inv_id).order_by(RunEvent.id)
            )).scalars()
        )


def _types(events) -> list[str]:
    return [e["type"] if isinstance(e, dict) else e.type for e in events]


# ------------------------------------------------------------------------ ordering
async def test_seq_is_gap_free_and_events_are_saved_in_seq_order(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)

    seqs = [e["seq"] for e in emitter.events]
    assert seqs == list(range(1, len(seqs) + 1))
    rows = await _saved(inv_id)
    assert [r.seq for r in rows] == seqs  # on disk in seq order, nothing lost
    assert [r.type for r in rows] == _types(emitter.events)
    assert all(r.ts.endswith("Z") and "." in r.ts for r in rows)  # UTC with ms


async def test_run_started_comes_first_and_before_any_module_start(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    types = _types(emitter.events)
    assert types[0] == "run_started"
    assert types.index("run_started") < types.index("module_start")
    started = emitter.events[0]["payload"]
    planned = {m["module"] for m in started["planned_modules"]}
    assert {"account_discovery", "username_platforms"} <= planned
    assert started["total_sources"] == len(started["planned_modules"])
    assert all(m["technique_id"] for m in started["planned_modules"])
    assert types[-1] == "run_done"
    done = emitter.events[-1]["payload"]
    assert done["status"] == "complete" and done["sources_checked"] == len(emitter.modules_done)


async def test_every_module_gets_start_and_done_including_budget_skipped(
    fake_modules, monkeypatch: pytest.MonkeyPatch
) -> None:
    fakes = [_module("hackertarget_hosts", _slow, priority=1), _module("shodan", _never, priority=2)]
    import backend.modules as modules_pkg

    monkeypatch.setattr(modules_pkg, "get_all_modules", lambda: fakes)
    inv_id = await _new_investigation()
    engine = InvestigationEngine(max_concurrency=1, budget_seconds=0.1, min_module_seconds=0.0)
    emitter = await _run(engine, inv_id)

    starts = [e["payload"]["module"] for e in emitter.events if e["type"] == "module_start"]
    dones = {e["payload"]["module"]: e["payload"] for e in emitter.events if e["type"] == "module_done"}
    assert sorted(starts) == sorted(dones) == ["hackertarget_hosts", "shodan"]
    assert dones["shodan"]["status"] == "skipped"
    assert dones["shodan"]["skipped_reason"]
    assert dones["hackertarget_hosts"]["duration_ms"] >= 90  # capped by the 0.1 s budget


async def test_module_progress_never_exceeds_total_and_is_throttled(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    progress = [e for e in emitter.events if e["type"] == "module_progress"]
    assert progress, "the sweep reports progress"
    for e in progress:
        assert 0 <= e["payload"]["checked"] <= e["payload"]["total"]
    # at most 4 per second per module
    from datetime import datetime

    stamps = [datetime.fromisoformat(e["ts"].replace("Z", "+00:00")) for e in progress
              if e["payload"]["module"] == "username_platforms"]
    for i in range(len(stamps) - 4):
        assert (stamps[i + 4] - stamps[i]).total_seconds() >= 0.9


async def test_hits_stream_as_they_land_not_when_the_module_ends(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    types = _types(emitter.events)
    sweep_done = next(
        i for i, e in enumerate(emitter.events)
        if e["type"] == "module_done" and e["payload"]["module"] == "username_platforms"
    )
    sweep_findings = [
        i for i, e in enumerate(emitter.events)
        if e["type"] == "finding" and e["payload"]["module"] == "username_platforms"
    ]
    assert len(sweep_findings) == 4
    assert all(i < sweep_done for i in sweep_findings)
    assert "edge_added" in types
    first = emitter.events[sweep_findings[0]]["payload"]
    assert first["label"] == "username_match" and first["kind"] == "username_match"
    assert set(first) >= {"finding_id", "module", "kind", "title", "value", "label", "trace"}
    # Payloads stay small: one hit per event, never a whole module result.
    assert all(len(json.dumps(e["payload"])) < 4000 for e in emitter.events)


# --------------------------------------------------------------------- many viewers
async def test_viewer_joining_mid_run_gets_full_replay_then_live(fake_modules) -> None:
    inv_id = await _new_investigation()
    engine = InvestigationEngine()
    queue = await engine.investigate(EMAIL, inv_id)
    emitter = run_events.get(inv_id)

    early: list[dict] = []

    async def _viewer(into: list[dict]) -> None:
        async for event in emitter.follow(0):
            into.append(event)

    t_early = asyncio.create_task(_viewer(early))
    await asyncio.sleep(0.08)  # the run is under way
    assert emitter.events and not emitter.done
    late: list[dict] = []
    t_late = asyncio.create_task(_viewer(late))
    while (await queue.get()) is not None:
        pass
    await asyncio.gather(t_early, t_late)

    assert [e["seq"] for e in late] == [e["seq"] for e in early] == list(range(1, len(early) + 1))
    assert late == early  # replayed prefix + live tail, identical to the early viewer
    assert late[-1]["type"] == "run_done"


async def test_two_concurrent_viewers_get_identical_streams(fake_modules) -> None:
    inv_id = await _new_investigation()
    engine = InvestigationEngine()
    queue = await engine.investigate(EMAIL, inv_id)
    emitter = run_events.get(inv_id)
    a: list[dict] = []
    b: list[dict] = []

    async def _viewer(into: list[dict]) -> None:
        async for event in emitter.follow(0):
            into.append(event)

    await asyncio.gather(
        _viewer(a), _viewer(b),
        _drain(queue),
    )
    assert a == b and a[-1]["type"] == "run_done"


async def _drain(queue) -> None:
    while (await queue.get()) is not None:
        pass


async def test_legacy_ws_queue_has_no_one_viewer_limit(fake_modules) -> None:
    inv_id = await _new_investigation()
    queue = await InvestigationEngine().investigate(EMAIL, inv_id)
    emitter = run_events.get(inv_id)
    first: list[Any] = []
    second: list[Any] = []

    async def _viewer(into: list[Any]) -> None:
        async for item in emitter.follow_legacy():
            into.append(item)

    await asyncio.gather(_viewer(first), _viewer(second), _drain(queue))
    assert len(first) == len(second) > 0
    assert first[-1] is None
    kinds = {i.type for i in first if i is not None}
    assert kinds <= {"module_start", "module_result", "module_error"}  # existing frame types


# --------------------------------------------------------------- SSE: replay + resume
def _parse_sse(text: str) -> list[dict]:
    out = []
    for block in text.split("\n\n"):
        lines = [ln for ln in block.split("\n") if ln and not ln.startswith(":")]
        if not lines:
            continue
        fields = {ln.split(": ", 1)[0]: ln.split(": ", 1)[1] for ln in lines}
        out.append({"id": int(fields["id"]), "event": fields["event"], "data": json.loads(fields["data"])})
    return out


async def _get_events(inv_id: str, **kwargs: Any):
    import httpx

    from backend.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(f"/api/investigations/{inv_id}/events", **kwargs)


async def test_replay_after_the_run_has_finished_and_last_event_id_resumes(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    run_events._registry.pop(inv_id, None)  # as if served by another process / later

    full = await _get_events(inv_id)
    assert full.status_code == 200
    assert full.headers["content-type"].startswith("text/event-stream")
    events = _parse_sse(full.text)
    assert [e["id"] for e in events] == [e["seq"] for e in emitter.events]
    assert events[-1]["event"] == "run_done"
    from backend.api.routes.investigations import wire_event

    assert events == [
        {"id": e["seq"], "event": e["type"], "data": wire_event(e)} for e in emitter.events
    ]
    # Wire shape: fields at the top level plus seq and ts; no payload wrapper, no type key.
    for e in events:
        assert "payload" not in e["data"] and "type" not in e["data"] or e["event"] == "edge_added"
        assert e["data"]["seq"] == e["id"] and e["data"]["ts"].endswith("Z")
    assert events[0]["data"]["total_sources"] == len(events[0]["data"]["planned_modules"])
    done = events[-1]["data"]
    assert done["status"] == "complete" and "sources_checked" in done

    resumed = _parse_sse((await _get_events(inv_id, headers={"Last-Event-ID": "7"})).text)
    assert [e["id"] for e in resumed] == [e["seq"] for e in emitter.events if e["seq"] > 7]
    via_query = _parse_sse((await _get_events(inv_id, params={"since": 7})).text)
    assert via_query == resumed


async def test_sse_unknown_run_is_404_and_old_run_without_events_closes(fake_modules) -> None:
    assert (await _get_events("no-such-run")).status_code == 404
    old = await _new_investigation()
    from backend.db.models import InvestigationStatus

    async with _database.AsyncSessionLocal() as db:
        inv = await db.get(Investigation, old)
        inv.status = InvestigationStatus.COMPLETE
        await db.commit()
    response = await asyncio.wait_for(_get_events(old), timeout=5)
    assert response.status_code == 200 and _parse_sse(response.text) == []


async def test_heartbeat_is_a_quiet_tick() -> None:
    emitter = run_events.RunEventEmitter("hb", persist=False)
    ticks = []

    async def _watch() -> None:
        async for event in emitter.follow(0, heartbeat=0.05):
            ticks.append(event)
            if len(ticks) >= 2:
                return

    await asyncio.wait_for(_watch(), timeout=2)
    assert ticks == [None, None]


async def test_events_are_scrubbed_of_configured_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.config import settings

    monkeypatch.setattr(settings, "shodan_api_key", "SECRET-KEY-VALUE-123456", raising=False)
    emitter = run_events.RunEventEmitter("scrub", persist=False)
    emitter.emit("finding", {"value": "https://x.example/?k=SECRET-KEY-VALUE-123456"})
    assert "SECRET-KEY-VALUE" not in json.dumps(emitter.events)
    assert "[redacted]" in json.dumps(emitter.events)


# ----------------------------------------------------------- saved findings + timing
async def test_every_saved_finding_has_a_trace_label_and_matching_reason(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    async with _database.AsyncSessionLocal() as db:
        rows = list((await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars())
    assert rows
    labels = set()
    for row in rows:
        data = row.data
        trace = data["trace"]
        assert trace["technique"] and trace["signal"] and trace["reason"]
        assert data["label"] in ("username_match", "possible", "confirmed", None)
        labels.add(data["label"])
        reason = trace["reason"].lower()
        if data["label"] is None:
            assert row.module_name == "dns_lookup"
            assert trace["reason"] == "The domain's mail is handled by Google Workspace (MX record)."
        elif data["label"] == "username_match":
            assert "username" in reason
        elif data["label"] == "confirmed":
            assert "separate checks agree" in reason
        assert isinstance(data["finding_id"], int)
    # registration + sign-in probe on github.com -> confirmed; sweep hits -> username match
    assert {"confirmed", "username_match", "possible", None} <= labels
    by_module = {r.module_name: r.data for r in rows}
    assert by_module["account_discovery"]["confidence"] == "high"
    # The live stream ends matching the saved report.
    final_labels = {r.data["finding_id"]: r.data["label"] for r in rows}
    live: dict[int, str] = {}
    for e in emitter.events:
        p = e["payload"]
        if e["type"] == "finding":
            live[p["finding_id"]] = p["label"]
            assert p["kind"] in ("account", "username_match", "name", "domain", "breach",
                                 "email", "phone", "other")
            assert "url" in p
        elif e["type"] == "finding_updated" and "merged_into" not in p:
            live[p["finding_id"]] = p["label"]
    assert live == final_labels
    # finding_updated fired because corroboration promoted the registration finding
    assert "finding_updated" in _types(emitter.events)


async def test_module_runs_save_real_start_and_finish_times(fake_modules, monkeypatch) -> None:
    fakes = [_module("hackertarget_hosts", _slow, priority=1), _module("hibp", _hibp, priority=2)]
    import backend.modules as modules_pkg

    monkeypatch.setattr(modules_pkg, "get_all_modules", lambda: fakes)
    inv_id = await _new_investigation()
    await _run(InvestigationEngine(), inv_id)
    async with _database.AsyncSessionLocal() as db:
        runs = {r.module_name: r for r in (await db.execute(
            select(ModuleRun).where(ModuleRun.investigation_id == inv_id))).scalars()}
    slow = runs["hackertarget_hosts"]
    assert (slow.finished_at - slow.started_at).total_seconds() >= 0.25
    assert runs["hibp"].started_at != slow.started_at  # not one shared run-start time


NODE_TYPES = {"email", "username", "account", "name", "domain", "breach", "phone"}


async def test_edges_use_contract_types_and_the_graph_adds_no_unseen_endpoints(
    fake_modules,
) -> None:
    from backend.core.run_stream import contract_node

    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    async with _database.AsyncSessionLocal() as db:
        inv = await db.get(Investigation, inv_id)
    graph = inv.graph_data
    assert "cluster_confidence" in graph
    announced = set()
    types = set()
    for e in emitter.events:
        if e["type"] == "edge_added":
            p = e["payload"]
            for end in (p["source"], p["target"]):
                assert end["type"] in NODE_TYPES, end
                assert "_" not in end["label"] and end["label"], end  # human names only
                announced.add(end["id"])
                types.add(end["type"])
            assert {"source", "target", "type", "reason", "finding_id"} <= set(p)
            assert p["reason"]
    # No DNS record, host or infrastructure cluster ever becomes a node.
    labels = {n["label"].lower() for n in graph["nodes"]}
    assert not any(x.startswith(("dns", "host", "infra", "email_cred")) for x in labels), labels
    nodes = {n["id"]: n for n in graph["nodes"]}
    for link in graph["links"]:
        assert {"module", "finding_id", "reason"} <= set(link["metadata"])
        ends = [
            contract_node(nodes[link[k]]["type"], nodes[link[k]]["label"], nodes[link[k]]["value"],
                          str((nodes[link[k]].get("metadata") or {}).get("module") or ""))
            for k in ("source", "target")
        ]
        if all(ends):  # every graph edge the live chain can show was announced
            assert ends[0]["id"] in announced and ends[1]["id"] in announced, link
    assert {"email", "username", "account"} <= types
    first_finding = next(i for i, e in enumerate(emitter.events) if e["type"] == "finding")
    assert any(i > first_finding for i, e in enumerate(emitter.events) if e["type"] == "edge_added")


async def test_module_start_carries_the_technique_text(fake_modules) -> None:
    from backend.core.techniques import technique_for

    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    starts = [e["payload"] for e in emitter.events if e["type"] == "module_start"]
    assert starts
    for p in starts:
        assert p["technique"] == technique_for(p["module"])[1] and p["technique_id"]


async def test_total_sources_counts_only_modules_that_can_run(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    started = emitter.events[0]["payload"]
    planned = {m["module"] for m in started["planned_modules"]}
    assert "shodan" not in planned  # no key in tests
    assert {"module": "shodan", "reason": "no_key"} in started["unavailable"]
    assert started["total_sources"] == len(started["planned_modules"])
    assert all(u["reason"] in ("no_key", "disabled") for u in started["unavailable"])
    done = emitter.events[-1]["payload"]
    assert done["sources_checked"] <= done["total_sources"]
    dones = [e["payload"] for e in emitter.events if e["type"] == "module_done"]
    checked = sum(1 for d in dones if d["status"] in ("success", "empty", "partial", "failed"))
    assert done["sources_checked"] == checked
    assert all(d["status"] in ("success", "empty", "partial", "failed", "skipped") for d in dones)
    assert all("skipped_reason" in d for d in dones)


async def test_partial_and_empty_count_as_checked_but_budget_skips_do_not(
    fake_modules, monkeypatch
) -> None:
    fakes = [
        _module("dns_lookup", _partial, priority=1),
        _module("whois_lookup", _never, priority=2),
        _module("domain_intel", _never, priority=3),
    ]
    import backend.modules as modules_pkg

    monkeypatch.setattr(modules_pkg, "get_all_modules", lambda: fakes)
    inv_id = await _new_investigation()
    engine = InvestigationEngine(max_concurrency=1, budget_seconds=0.05, min_module_seconds=10.0)
    emitter = await _run(engine, inv_id)
    dones = {e["payload"]["module"]: e["payload"] for e in emitter.events if e["type"] == "module_done"}
    assert dones["dns_lookup"]["status"] == "skipped" and dones["dns_lookup"]["skipped_reason"] == "budget"
    done = emitter.events[-1]["payload"]
    assert done["sources_checked"] == 0 and done["total_sources"] >= 3  # skips stay in the total


async def test_empty_status_name_and_partial_are_checked(fake_modules, monkeypatch) -> None:
    fakes = [_module("dns_lookup", _partial), _module("hackertarget_hosts", _slow)]
    import backend.modules as modules_pkg

    monkeypatch.setattr(modules_pkg, "get_all_modules", lambda: fakes)
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    dones = {e["payload"]["module"]: e["payload"]["status"] for e in emitter.events if e["type"] == "module_done"}
    assert dones == {"dns_lookup": "partial", "hackertarget_hosts": "empty"}  # success_empty -> empty
    assert emitter.events[-1]["payload"]["sources_checked"] == 2


async def test_failed_run_still_ends_with_run_done(fake_modules, monkeypatch) -> None:
    async def _boom(self, *a, **k):
        raise RuntimeError("persist failed")

    monkeypatch.setattr(InvestigationEngine, "_persist", _boom)
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    assert emitter.events[-1]["type"] == "run_done"
    assert emitter.events[-1]["payload"]["status"] == "failed"
    assert emitter.events[-1]["payload"]["error"] == "persist failed"
    assert [e["seq"] for e in emitter.events] == list(range(1, len(emitter.events) + 1))
    assert len((await _saved(inv_id))) == len(emitter.events)


async def test_every_account_breach_and_name_finding_emits_an_edge(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    findings = [e["payload"] for e in emitter.events if e["type"] == "finding"]
    # Two findings about the same site share one email -> account edge.
    edged = {
        end["label"]
        for e in emitter.events if e["type"] == "edge_added"
        for end in (e["payload"]["source"], e["payload"]["target"])
    }
    wanted = [f for f in findings if f["kind"] in ("account", "breach", "name")]
    assert {f["module"] for f in wanted} >= {"account_discovery", "browser_account_probe", "hibp"}
    missing = [(f["module"], f["title"]) for f in wanted if f["title"] not in edged]
    assert missing == []
    probe = next(f for f in findings if f["module"] == "browser_account_probe")
    assert "email_first" not in probe["trace"]["reason"] + probe["trace"]["signal"]


async def test_username_match_value_is_the_username_and_the_url_is_kept(fake_modules) -> None:
    inv_id = await _new_investigation()
    emitter = await _run(InvestigationEngine(), inv_id)
    hits = [e["payload"] for e in emitter.events
            if e["type"] == "finding" and e["payload"]["kind"] == "username_match"]
    assert hits
    for h in hits:
        assert h["value"] == "alice" and h["url"].startswith("https://site")
