"""Paid providers (ipgeolocation, WhoisFreaks) exist only when the engine has the key,
and a per-run flag makes them fully off: no calls, no credits, no cached data, and no
trace in the event stream, report, graph or CLI output.

Local only: the provider HTTP layer is a recording mock; no credits are spent.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from backend.config import settings
from backend.core import enrichment_store as store
from backend.core import ipgeo_client as ipgeo
from backend.core import phases as phases_mod
from backend.core import run_events
from backend.core import whoisfreaks_client as wf
from backend.core import whoisfreaks_data as wf_data
from backend.core.engine import InvestigationEngine
from backend.db import database as _database
from backend.db.models import Finding, Investigation, ModuleRun
from backend.modules import get_all_modules as REAL_MODULES  # bound before any test patches it
from backend.modules.base import ModuleStatus
from tests.test_ipgeo_release import PAID
from tests.test_whoisfreaks_release import KEY as WF_KEY
from tests.test_whoisfreaks_release import _set, route

IPGEO_KEY = "ipgeo-secret-key-0987654321"
EMAIL = "someone@acme.io"
ON = {"ip_intel", "whoisfreaks_intel"}


@pytest.fixture
def providers(monkeypatch, isolated_db):
    """Both keys set; every provider HTTP call is recorded (and answered)."""
    monkeypatch.setattr(settings, "ipgeolocation_api_key", IPGEO_KEY)
    monkeypatch.setattr(settings, "ipgeo_disabled", False, raising=False)
    _set(monkeypatch, "whoisfreaks_api_key", WF_KEY)
    wf_route = route()
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if "ipgeolocation" in req.url.host:
            return httpx.Response(200, json=[PAID])
        return wf_route(req)

    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)})
    )
    wf._STATE = getattr(wf, "_STATE", None)
    return calls


async def _warm(calls: list) -> None:
    """Warm both caches the way earlier keyed runs would have."""
    await store.enrich_ips(["8.8.8.8"], refresh=True)
    await wf_data.lookup("history", "acme.io", max_pages=1)
    await wf_data.lookup("reverse_email", EMAIL, max_pages=1)
    assert calls  # the warm-up really called the providers


# ------------------------------------------------------------------ capabilities
async def _capabilities() -> httpx.Response:
    from backend.main import app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        return await client.get("/api/capabilities")


@pytest.mark.parametrize(
    "ip_key,wf_key,netlas_key,expected",
    [
        (IPGEO_KEY, WF_KEY, "netlas-secret-key-1122334455",
         {"ipgeolocation": True, "whoisfreaks": True, "netlas": True, "brightdata": False}),
        (None, WF_KEY, None,
         {"ipgeolocation": False, "whoisfreaks": True, "netlas": False, "brightdata": False}),
        (IPGEO_KEY, None, None,
         {"ipgeolocation": True, "whoisfreaks": False, "netlas": False, "brightdata": False}),
        (None, None, None,
         {"ipgeolocation": False, "whoisfreaks": False, "netlas": False, "brightdata": False}),
    ],
)
async def test_capabilities_are_booleans_per_key_with_no_key_material(
    monkeypatch, ip_key, wf_key, netlas_key, expected
) -> None:
    monkeypatch.setattr(settings, "ipgeolocation_api_key", ip_key)
    monkeypatch.setattr(settings, "netlas_api_key", netlas_key)
    _set(monkeypatch, "whoisfreaks_api_key", wf_key)
    _set(monkeypatch, "brightdata_api_key", None)
    response = await _capabilities()
    assert response.status_code == 200
    assert response.json() == {"providers": expected}
    body = response.text
    for secret in (IPGEO_KEY, WF_KEY, "netlas-secret-key-1122334455"):
        assert secret not in body and secret[:8] not in body and secret[-6:] not in body
    assert all(isinstance(v, bool) for v in response.json()["providers"].values())


async def test_capabilities_off_when_persistently_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "ipgeolocation_api_key", IPGEO_KEY)
    monkeypatch.setattr(settings, "ipgeo_disabled", True, raising=False)
    assert (await _capabilities()).json()["providers"]["ipgeolocation"] is False


async def test_capabilities_needs_the_api_key_like_the_rest_of_the_api(monkeypatch) -> None:
    from backend.main import app

    monkeypatch.setattr(settings, "mailaccess_api_key", "engine-key-abcdefgh")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        assert (await client.get("/api/capabilities")).status_code == 401
        ok = await client.get("/api/capabilities", headers={"X-API-Key": "engine-key-abcdefgh"})
        assert ok.status_code == 200


async def test_brightdata_capability_and_module_visibility(monkeypatch) -> None:
    from backend.main import app

    import backend.api.routes.modules as modules_route

    bd_key = "bd-secret-key-5566778899"
    _set(monkeypatch, "brightdata_api_key", bd_key)
    response = await _capabilities()
    assert response.json()["providers"]["brightdata"] is True
    assert bd_key not in response.text
    monkeypatch.setattr(modules_route, "get_all_modules", REAL_MODULES)
    _set(monkeypatch, "brightdata_api_key", None)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        names = {m["name"] for m in (await client.get("/api/modules/")).json()}
    assert "linkedin_brightdata" not in names


async def test_module_list_hides_a_provider_that_is_off(monkeypatch) -> None:
    from backend.main import app

    import backend.api.routes.modules as modules_route

    # Other tests patch the registry while the app first imports; pin the real one.
    monkeypatch.setattr(modules_route, "get_all_modules", REAL_MODULES)
    monkeypatch.setattr(settings, "ipgeolocation_api_key", None)
    _set(monkeypatch, "whoisfreaks_api_key", WF_KEY)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        names = {m["name"] for m in (await client.get("/api/modules/")).json()}
    assert "ip_intel" not in names and "whoisfreaks_intel" in names


# --------------------------------------------------------------------- engine runs
class _Dns:
    name = "dns_lookup"
    description = "fake dns"
    priority = 1
    requires_key = False

    async def run(self, email, **_):
        from backend.modules.base import ModuleResult

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[{"platform": "dns_a", "confidence": "high",
                       "metadata": {"ip_address": "8.8.8.8"}}],
        )


@pytest.fixture
def engine_env(monkeypatch, providers):
    import backend.modules as modules_pkg
    from backend.core import mx_resolver

    monkeypatch.setattr(modules_pkg, "get_all_modules", lambda: [_Dns])
    monkeypatch.setattr(
        phases_mod, "PHASE_DAG",
        (phases_mod.PrimaryPhase(), phases_mod.IpIntelPhase(), phases_mod.WhoisFreaksPhase()),
    )

    async def _resolved(domain):
        return SimpleNamespace(status=mx_resolver.MxStatus.RESOLVED)

    async def _noop(self, *a, **k):
        return None

    monkeypatch.setattr(mx_resolver, "resolve_mx_typed", _resolved)
    monkeypatch.setattr(InvestigationEngine, "_dispatch_webhooks", _noop)
    monkeypatch.setattr(InvestigationEngine, "_record_observations", _noop)
    return providers


async def _run(**flags) -> tuple[run_events.RunEventEmitter, str]:
    async with _database.AsyncSessionLocal() as db:
        inv = Investigation(email=EMAIL, canonical_email=EMAIL)
        db.add(inv)
        await db.commit()
        inv_id = inv.id
    queue = await InvestigationEngine(**flags).investigate(EMAIL, inv_id)
    emitter = run_events.get(inv_id)
    while (await queue.get()) is not None:
        pass
    return emitter, inv_id


async def _everything(emitter, inv_id) -> dict:
    async with _database.AsyncSessionLocal() as db:
        findings = list((await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars())
        runs = list((await db.execute(select(ModuleRun).where(ModuleRun.investigation_id == inv_id))).scalars())
        inv = await db.get(Investigation, inv_id)
    return {
        "events": json.dumps(emitter.events),
        "modules": {f.module_name for f in findings} | {r.module_name for r in runs},
        "findings": json.dumps([f.data for f in findings], default=str),
        "graph": json.dumps(inv.graph_data, default=str),
        "started": emitter.events[0]["payload"],
    }


def _present(blob: dict, module: str, word: str) -> bool:
    text = " ".join((blob["events"], blob["findings"], blob["graph"])).lower()
    return module in blob["modules"] or word in text


async def test_control_run_with_both_providers_on_uses_them(engine_env) -> None:
    await _warm(engine_env)
    emitter, inv_id = await _run()
    blob = await _everything(emitter, inv_id)
    assert ON <= blob["modules"]


@pytest.mark.parametrize(
    "flags,off,still_on",
    [
        ({"no_ipgeo": True}, "ip_intel", "whoisfreaks_intel"),
        ({"no_whoisfreaks": True}, "whoisfreaks_intel", "ip_intel"),
    ],
)
async def test_a_flag_makes_its_provider_fully_off_even_with_a_warm_cache(
    engine_env, flags, off, still_on
) -> None:
    await _warm(engine_env)
    engine_env.clear()
    emitter, inv_id = await _run(**flags)
    blob = await _everything(emitter, inv_id)
    word = "ipgeolocation" if off == "ip_intel" else "whoisfreaks"
    assert not _present(blob, off, word), f"{off} leaked into the run"
    assert still_on in blob["modules"]  # the other provider is untouched
    started = blob["started"]
    assert off not in {m["module"] for m in started["planned_modules"]}
    assert off not in {u["module"] for u in started["unavailable"]}
    host = "ipgeolocation" if off == "ip_intel" else "whoisfreaks"
    assert not [r for r in engine_env if host in r.url.host], "the off provider was called"


async def test_both_flags_mean_zero_provider_calls_and_no_trace(engine_env) -> None:
    await _warm(engine_env)
    engine_env.clear()
    emitter, inv_id = await _run(no_ipgeo=True, no_whoisfreaks=True)
    blob = await _everything(emitter, inv_id)
    assert engine_env == []  # 0 provider calls, so 0 credits
    assert not (ON & blob["modules"])
    for word in ("ip_intel", "whoisfreaks", "ipgeolocation"):
        assert word not in (blob["events"] + blob["findings"] + blob["graph"]).lower(), word
    started = blob["started"]
    assert not ({m["module"] for m in started["planned_modules"]} & ON)
    assert not ({u["module"] for u in started["unavailable"]} & ON)


@pytest.mark.parametrize("missing", ["ipgeolocation", "whoisfreaks", "both"])
async def test_a_keyless_engine_leaves_the_provider_out_of_the_stream(
    engine_env, monkeypatch, missing
) -> None:
    await _warm(engine_env)  # a warm cache from an earlier keyed run
    engine_env.clear()
    if missing in ("ipgeolocation", "both"):
        monkeypatch.setattr(settings, "ipgeolocation_api_key", None)
    if missing in ("whoisfreaks", "both"):
        _set(monkeypatch, "whoisfreaks_api_key", None)
    emitter, inv_id = await _run()
    blob = await _everything(emitter, inv_id)
    gone = {"ipgeolocation": {"ip_intel"}, "whoisfreaks": {"whoisfreaks_intel"}, "both": ON}[missing]
    assert not (gone & blob["modules"])
    started = blob["started"]
    assert not ({m["module"] for m in started["planned_modules"]} & gone)
    assert not ({u["module"] for u in started["unavailable"]} & gone)
    for module in gone:
        assert module not in blob["events"]
    assert not [r for r in engine_env if r.url.host.endswith(("ipgeolocation.io", "whoisfreaks.com"))]


async def test_a_stored_run_holding_provider_data_is_not_reused_when_that_provider_is_off(
    engine_env, monkeypatch
) -> None:
    from backend.core.service import InvestigationService

    monkeypatch.setattr(settings, "enable_investigation_cache", True)
    await _warm(engine_env)

    async def go(**flags):
        async with _database.AsyncSessionLocal() as db:
            inv_id, _t, queue, cached = await InvestigationService(db).create_investigation(
                EMAIL, **flags
            )
        if queue is not None:
            while (await queue.get()) is not None:
                pass
        return inv_id, cached

    first, cached = await go()
    assert not cached
    async with _database.AsyncSessionLocal() as db:
        runs = {r.module_name for r in (await db.execute(
            select(ModuleRun).where(ModuleRun.investigation_id == first))).scalars()}
    assert ON <= runs

    engine_env.clear()
    second, cached = await go(no_ipgeo=True, no_whoisfreaks=True)
    assert second != first and not cached  # not served from the stored report
    async with _database.AsyncSessionLocal() as db:
        runs = {r.module_name for r in (await db.execute(
            select(ModuleRun).where(ModuleRun.investigation_id == second))).scalars()}
    assert not (ON & runs) and engine_env == []


# ------------------------------------------------------------------- data layer
async def test_data_layer_serves_nothing_when_off(providers, monkeypatch) -> None:
    await _warm(providers)
    providers.clear()
    assert await store.enrich_ips(["8.8.8.8"], no_ipgeo=True) == {}
    off = await wf_data.lookup("history", "acme.io", max_pages=1, no_whoisfreaks=True)
    assert off.rows == [] and not off.from_cache
    off_cache_only = await wf_data.lookup(
        "history", "acme.io", max_pages=1, no_whoisfreaks=True, cache_only=True
    )
    assert off_cache_only.rows == []
    assert providers == []
    on = await wf_data.lookup("history", "acme.io", max_pages=1)
    assert on.rows and on.from_cache  # still served when the provider is on


# ------------------------------------------------------------------------ harvest
async def test_harvest_ip_enrichment_flag_drops_stale_rows_and_calls_nothing(providers) -> None:
    from backend.core.harvest_runner import enrich_harvest_ip_intel
    from backend.modules.base import ModuleResult

    await _warm(providers)
    providers.clear()
    results = {"ip_intel": ModuleResult(ModuleStatus.SUCCESS),
               "subdomain_intel": ModuleResult(ModuleStatus.SUCCESS,
                                               findings=[{"resolved_ips": ["8.8.8.8"]}])}
    await enrich_harvest_ip_intel(results, no_ipgeo=True)
    assert "ip_intel" not in results and providers == []
    await enrich_harvest_ip_intel(results, no_ipgeo=False)
    assert "ip_intel" in results


def test_a_stored_harvest_with_provider_data_is_detected() -> None:
    from backend.core.domain_harvest_orchestrator import _holds_provider_data
    from backend.modules.base import ModuleResult

    def result(modules=None, meta=None):
        return SimpleNamespace(module_results=modules or {}, metadata=meta or {})

    ok = ModuleResult(ModuleStatus.SUCCESS)
    assert _holds_provider_data(result({"ip_intel": ok}), ipgeo=True, whoisfreaks=False)
    assert not _holds_provider_data(result({"ip_intel": ok}), ipgeo=False, whoisfreaks=False)
    assert _holds_provider_data(result({"whoisfreaks_history": ok}), ipgeo=False, whoisfreaks=True)
    assert _holds_provider_data(result(meta={"whoisfreaks": {"status": "ok"}}), ipgeo=False, whoisfreaks=True)
    related = {"related_domains": {"domains": [{"evidence": [{"pivot": "whois_company"}]}]}}
    assert _holds_provider_data(result(meta=related), ipgeo=False, whoisfreaks=True)
    dated = ModuleResult(ModuleStatus.SUCCESS, findings=[{"subdomain": "a.x.io", "first_seen": "2020"}])
    assert _holds_provider_data(result({"subdomain_intel": dated}), ipgeo=False, whoisfreaks=True)
    clean = ModuleResult(ModuleStatus.SUCCESS, findings=[{"subdomain": "a.x.io"}])
    assert not _holds_provider_data(result({"subdomain_intel": clean}), ipgeo=True, whoisfreaks=True)


def test_harvest_accepts_both_flags() -> None:
    from typer.testing import CliRunner

    import cli.main as main

    out = CliRunner().invoke(main.app, ["harvest-emails", "--help"]).output
    assert "--no-ipgeo" in out and "--no-whoisfreaks" in out


async def test_cli_credit_lines_are_silent_when_the_flag_is_set(providers, monkeypatch) -> None:
    """The result footers (credit line and keyless nudge) are skipped for a flagged run."""
    import inspect

    import cli.harvest_emails as he
    import cli.main as main

    harvest_src = inspect.getsource(he.run_harvest_emails)
    assert "if not no_ipgeo:" in harvest_src and "if not no_whoisfreaks:" in harvest_src
    assert "if not no_ipgeo:" in inspect.getsource(main)
