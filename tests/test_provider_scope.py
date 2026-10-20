"""Provider facts must not outlive the run that was allowed to have them.

Observations are append-only and outlive runs, so a later run where a provider is off
(no key or a per-run flag) must not report that provider's earlier facts, in the
report, the field provenance, the graph, or any export (MD, STIX, Maltego, JSON, CSV,
PROV). The shape comes from a real case: a keyed run of someone.else@example.org
recorded WhoisFreaks facts (company "Internet Assigned Numbers Authority (IANA)") and a
later keyless run still reported that company. Local only; no credits are spent.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, update

from backend.config import settings
from backend.core import phases as phases_mod
from backend.core import run_events
from backend.core.capabilities import allowed_providers_for_run
from backend.core.engine import InvestigationEngine
from backend.db import database as _database
from backend.db.models import Investigation, Observation, RunManifest
from backend.modules.base import ModuleResult, ModuleStatus
from tests.test_ipgeo_release import PAID
from tests.test_whoisfreaks_release import KEY as WF_KEY
from tests.test_whoisfreaks_release import _set

REAL_CLIENT = httpx.AsyncClient  # the provider mock replaces httpx.AsyncClient during tests
IPGEO_KEY = "ipgeo-secret-key-0987654321"
EMAIL = "someone.else@example.org"
IANA = "Internet Assigned Numbers Authority (IANA)"

IANA_REVERSE = {
    "total_Result": 1, "total_Pages": 1, "current_Page": 1,
    "whois_domains_historical": [
        {"num": 1, "domain_name": "example.org", "company_name": IANA,
         "email": EMAIL, "name": "IANA Administrator"},
    ],
}
IANA_HISTORY = {
    "total_records": "1",
    "whois_domains_historical": [
        {"query_time": "2024-05-01",
         "registrant_contact": {"name": "IANA Administrator", "company": IANA,
                                "email_address": "iana@iana.org"}},
    ],
}


class _Dns:
    name = "dns_lookup"
    description = "fake dns"
    priority = 1
    requires_key = False

    async def run(self, email, **_):
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[{"platform": "dns_a", "confidence": "high",
                       "metadata": {"ip_address": "8.8.8.8"}}],
        )


@pytest.fixture
def env(monkeypatch, isolated_db):
    import backend.api.routes.modules  # noqa: F401  (import before patching the registry)
    import backend.modules as modules_pkg
    from backend.core import mx_resolver

    monkeypatch.setattr(settings, "ipgeolocation_api_key", IPGEO_KEY)
    monkeypatch.setattr(settings, "ipgeo_disabled", False, raising=False)
    _set(monkeypatch, "whoisfreaks_api_key", WF_KEY)
    # Bright Data (LinkedIn card) is not part of these runs; the repo .env may hold a key.
    _set(monkeypatch, "brightdata_api_key", None)
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if "ipgeolocation" in req.url.host:
            return httpx.Response(200, json=[PAID])
        if req.url.path.endswith("/history"):
            return httpx.Response(200, json=IANA_HISTORY)
        if req.url.path.endswith("/reverse"):
            return httpx.Response(200, json=IANA_REVERSE)
        return httpx.Response(404, json={"message": "Record not found."})

    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)}),
    )
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
    return calls


async def _run(**flags) -> str:
    async with _database.AsyncSessionLocal() as db:
        inv = Investigation(email=EMAIL, canonical_email=EMAIL)
        db.add(inv)
        await db.commit()
        inv_id = inv.id
    queue = await InvestigationEngine(**flags).investigate(EMAIL, inv_id)
    while (await queue.get()) is not None:
        pass
    run_events.unregister(run_events.get(inv_id)) if run_events.get(inv_id) else None
    return inv_id


async def _get(path: str, **kw) -> httpx.Response:
    from backend.main import app

    async with REAL_CLIENT(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        return await client.get(path, **kw)


async def _bundle(inv_id: str) -> dict[str, str]:
    from backend.core.run_manifest import read_run_manifest
    from backend.exporters.prov_exporter import prov_for_subject

    out = {"report": (await _get(f"/api/report/{inv_id}")).text}
    for fmt in ("json", "csv", "markdown", "stix", "maltego"):
        response = await _get(f"/api/report/{inv_id}/export", params={"format": fmt})
        assert response.status_code == 200, (fmt, response.text[:200])
        out[fmt] = response.text
    manifest = await read_run_manifest(inv_id)
    out["prov"] = json.dumps(await prov_for_subject(EMAIL, run_manifest=manifest), default=str)
    return out


def _has(bundle: dict[str, str], *needles: str) -> list[str]:
    hits = []
    for name, text in bundle.items():
        low = text.lower()
        hits += [f"{name}:{n}" for n in needles if n.lower() in low]
    return hits


async def _company(inv_id: str) -> str | None:
    report = (await _get(f"/api/report/{inv_id}")).json()
    return ((report.get("field_provenance") or {}).get("company") or {}).get("resolved_value")


# --------------------------------------------------------------------------- tests
async def test_a_keyed_run_still_shows_its_own_provider_facts(env) -> None:
    run = await _run()
    report = (await _get(f"/api/report/{run}")).json()
    modules = {f["module_name"] for f in report["findings"]}
    assert {"ip_intel", "whoisfreaks_intel"} <= modules
    assert IANA in json.dumps([f["data"] for f in report["findings"]])
    # ...and a later keyed run sees those facts through the ledger (the leak path).
    later = await _run()
    assert IANA in await _bundle_report_company(later)
    async with _database.AsyncSessionLocal() as db:
        providers = {o.provider for o in (await db.execute(select(Observation))).scalars()}
        manifest = (await db.execute(select(RunManifest).where(RunManifest.run_id == run))).scalar_one()
    assert {"whoisfreaks", "ipgeolocation"} <= providers
    assert manifest.providers == {
        "ipgeolocation": True, "whoisfreaks": True, "netlas": False, "brightdata": False,
    }


async def test_keyed_then_keyless_run_reports_no_provider_fact_anywhere(env, monkeypatch) -> None:
    await _run()
    control = await _run()  # still keyed: the earlier run's company shows through the ledger
    assert IANA in await _bundle_report_company(control)
    # Later: the engine has no keys at all.
    monkeypatch.setattr(settings, "ipgeolocation_api_key", None)
    _set(monkeypatch, "whoisfreaks_api_key", None)
    env.clear()
    second = await _run()
    assert env == []  # no provider calls
    assert IANA not in await _bundle_report_company(second)
    bundle = await _bundle(second)
    assert _has(bundle, "IANA", "Internet Assigned Numbers", "whoisfreaks", "ipgeolocation") == []
    async with _database.AsyncSessionLocal() as db:
        manifest = (await db.execute(select(RunManifest).where(RunManifest.run_id == second))).scalar_one()
    assert manifest.providers["whoisfreaks"] is False and manifest.providers["ipgeolocation"] is False


async def _bundle_report_company(inv_id: str) -> str:
    return json.dumps((await _get(f"/api/report/{inv_id}")).json().get("field_provenance"))


@pytest.mark.parametrize(
    "flags,gone,may_show",
    [
        ({"no_whoisfreaks": True}, ("IANA", "Internet Assigned Numbers", "whoisfreaks"), "ipgeolocation"),
        ({"no_ipgeo": True}, ("ipgeolocation", "ipgeo", "Mountain View", "ip_intel"), "whoisfreaks"),
    ],
)
async def test_a_flag_hides_only_its_own_provider_even_after_a_keyed_run(
    env, flags, gone, may_show
) -> None:
    await _run()  # keyed, both providers
    env.clear()
    second = await _run(**flags)
    bundle = await _bundle(second)
    assert _has(bundle, *gone) == []
    if may_show == "whoisfreaks":
        assert IANA.lower() in (await _bundle_report_company(second)).lower()
    assert not [r for r in env if gone[0].lower()[:5] in r.url.host]


async def test_old_run_without_providers_counts_what_its_own_findings_show(env, monkeypatch) -> None:
    await _run()
    keyed = await _run()  # sees the first run's facts through the ledger
    async with _database.AsyncSessionLocal() as db:
        await db.execute(update(RunManifest).values(providers=None))  # as if recorded pre-0017
        await db.commit()
    # The engine now has no keys: this run still counts as having had both providers,
    # because its OWN findings show them. Never inferred from today's keys.
    monkeypatch.setattr(settings, "ipgeolocation_api_key", None)
    _set(monkeypatch, "whoisfreaks_api_key", None)
    assert await allowed_providers_for_run(keyed) == {"ipgeolocation", "whoisfreaks"}
    assert IANA in await _bundle_report_company(keyed)

    # A keyless run (no provider data in its findings) with no recorded providers stays
    # provider-free even when the engine holds keys today.
    keyless = await _run()
    async with _database.AsyncSessionLocal() as db:
        await db.execute(update(RunManifest).where(RunManifest.run_id == keyless).values(providers=None))
        await db.commit()
    _set(monkeypatch, "whoisfreaks_api_key", WF_KEY)
    monkeypatch.setattr(settings, "ipgeolocation_api_key", IPGEO_KEY)
    assert await allowed_providers_for_run(keyless) == set()
    assert IANA not in await _bundle_report_company(keyless)
    assert _has(await _bundle(keyless), "IANA", "whoisfreaks", "ipgeolocation") == []


def test_observations_are_tagged_by_extraction_method_and_claim() -> None:
    from backend.core.observation_ledger import provider_for

    assert provider_for("ip_intel", {}) == "ipgeolocation"
    assert provider_for("whoisfreaks_intel", {}) == "whoisfreaks"
    assert provider_for("whoisfreaks_history", {}) == "whoisfreaks"
    assert provider_for("subdomain_intel", {"discovery_method": ["whoisfreaks"]}) == "whoisfreaks"
    assert provider_for("harvest", {"pivot": "whois_company"}) == "whoisfreaks"
    assert provider_for("ip_x", {"sources": ["ipgeolocation.io"]}) == "ipgeolocation"
    assert provider_for("hibp", {"platform": "Adobe"}) is None
    assert provider_for("github_commits", {"source": "github_profile"}) is None


async def test_migration_0017_backfills_provider_and_round_trips(tmp_path) -> None:
    import sqlalchemy as sa
    from alembic import command
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from backend.db.database import _alembic_config

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'm.db'}")

    def op(rev, direction):
        def fn(conn):
            getattr(command, direction)(_alembic_config(conn), rev)
        return fn

    try:
        async with engine.begin() as conn:
            await conn.run_sync(op("0016", "upgrade"))
            for i, (method, source) in enumerate(
                [("ip_intel", None), ("whoisfreaks_intel", None), ("whoisfreaks_history", None),
                 ("github_commits", None), ("custom", "ipgeolocation.io"), ("custom2", "whoisfreaks")]
            ):
                await conn.execute(
                    text("INSERT INTO observations (id,pipeline,activity_id,extraction_method,"
                         "module_version,subject_type,subject,claim,source_type,capture_time,"
                         "content_hash,mode,source_policy_status,created_at) VALUES "
                         "(:i,'investigate','a',:m,'1','email','x@y.z','{}',:s,'2026-01-01',"
                         ":h,'security-investigation','unreviewed','2026-01-01')"),
                    {"i": f"o{i}", "m": method, "s": source, "h": f"h{i}"},
                )
        async with engine.begin() as conn:
            await conn.run_sync(op("0017", "upgrade"))
        async with engine.connect() as conn:
            got = dict((await conn.execute(text("SELECT id, provider FROM observations"))).all())
            cols = await conn.run_sync(
                lambda c: {x["name"] for x in sa.inspect(c).get_columns("run_manifests")})
        assert got == {"o0": "ipgeolocation", "o1": "whoisfreaks", "o2": "whoisfreaks",
                       "o3": None, "o4": "ipgeolocation", "o5": "whoisfreaks"}
        assert "providers" in cols
        async with engine.begin() as conn:
            await conn.run_sync(op("0016", "downgrade"))
        async with engine.connect() as conn:
            cols = await conn.run_sync(
                lambda c: {x["name"] for x in sa.inspect(c).get_columns("observations")})
            kept = (await conn.execute(text("SELECT count(*) FROM observations"))).scalar_one()
        assert "provider" not in cols and kept == 6
        async with engine.begin() as conn:
            await conn.run_sync(op("0017", "upgrade"))
    finally:
        await engine.dispose()
