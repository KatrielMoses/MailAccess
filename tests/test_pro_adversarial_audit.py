"""Executable 0.17 audit reproductions. Assertions document observed defects.

Synthetic data only; no live corpus or production database writes.
Run: .venv/Scripts/python.exe -m pytest tests/test_pro_adversarial_audit.py -q
"""
import asyncio
import json
import subprocess
import types
import time
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.routes import enrich as E
from backend.config import settings
from backend.core import corpus_store as C, domain_harvest_report as R
from backend.core import mailaccess_pro_client as engine
from backend.core.domain_harvest_orchestrator import HarvestedEmail, DomainHarvestResult, _inject_pro_leads
from backend.core.lead_person import resolve_person_fields
from backend.core.product_mode import ProductMode

MODE = ProductMode.PUBLIC_BUSINESS_CONTACT

def lead(**kw):
    return dict(full_name="Steve Lee", email="steve@audit.example", title="Engineer", source="linkedin", **kw)

def result(rows, mode=MODE.value):
    now = datetime.now(timezone.utc).isoformat()
    return DomainHarvestResult(domain="audit.example", started_at=now, completed_at=now,
        duration_seconds=1, module_results={}, unique_emails=rows, total_unique_emails=len(rows),
        high_confidence_count=0, likely_confidence_count=0, medium_confidence_count=0,
        low_confidence_count=len(rows), role_account_count=0, personal_email_count=len(rows),
        metadata={"mode": mode})

def native():
    return HarvestedEmail(email="steve@audit.example", on_domain=True, is_role=False,
        role_match_type=None, confidence_score=.95, confidence_label="CONFIRMED",
        verification="smtp_verified", found_by_modules=["company_page"],
        evidence=[{"module":"company_page", "metadata":{"full_name":"Steve Native", "job_title":"Engineer"}}])

def app(monkeypatch, search):
    async def valid(key): return key == "audit-test"
    monkeypatch.setattr(E, "validate_pro_key", valid)
    monkeypatch.setattr(engine, "search", search)
    monkeypatch.setattr(settings, "mailaccess_pro_lawful_basis_established", True)
    a = FastAPI(); a.include_router(E.router, prefix="/v1")
    return TestClient(a, raise_server_exceptions=False)

def test_personal_provider_not_a_company(monkeypatch):
    # B2 (inverted repro) — a consumer-provider domain is not a company; the query
    # yields no business leak (empty), not on-provider addresses as "business".
    async def search(*a, **k):
        return {"rows":[{"email":"synthetic@yahoo.co.uk", "full_name":"Synthetic Person"}], "total":1}
    client = app(monkeypatch, search)
    body = client.post('/v1/enrich', headers={"Authorization":"Bearer audit-test"},
        json={"query":"yahoo.co.uk", "type":"domain"}).json()
    assert body['status'] == 'empty'
    assert body['leads'] == []

def test_no_domain_first_guess(monkeypatch):
    # B3 (P1c) — a company query resolves ONLY via ranked actual org records; no
    # domain is ever fabricated from the token. audit.com's org names "Unrelated
    # Owner" (not the query), and company-mode returns no match → empty, never a
    # guessed audit.com resolution.
    async def search(q, **k):
        return {"rows":[], "organizations":[], "total":0}  # company-mode: no match
    monkeypatch.setattr(engine, 'search', search)
    resolved = asyncio.run(E._resolve_company("Audit"))
    assert resolved['status'] == 'empty'
    assert 'domain' not in resolved

def test_company_size_heuristic_silently_selects_ambiguous_org(monkeypatch):
    # B3 (inverted repro) — two same-name orgs are a genuine ambiguity; employee
    # count is not identity evidence → disambiguation, never an auto-pick of the larger.
    async def search(*a, **k):
        return {'organizations':[{'company':'Audit Systems','domain':'large.example','employees':200},
            {'company':'Audit Systems','domain':'small.example','employees':100}]}
    monkeypatch.setattr(engine,'search',search)
    resolved=asyncio.run(E._resolve_company('Audit Systems'))
    assert resolved['status']=='disambiguation'
    assert {c['domain'] for c in resolved['candidates']} == {'large.example', 'small.example'}

def test_untrusted_provenance_bool_and_linkedin_origin():
    # C1 (inverted repro) — corpus_verified is a STRICT bool (the string "false" is
    # not True), and a /in/ path on an unrelated host is NOT a LinkedIn origin.
    raw=lead(is_verified='false', linkedin_url='https://unrelated.invalid/in/synthetic')
    projected=E._project_lead(raw)
    assert projected['corpus_verified'] is False
    assert projected['linkedin_url'] is None
    assert projected['linkedin_slug'] is None

def test_hosted_route_does_not_consult_local_suppression(monkeypatch):
    # D1 (inverted repro) — the hosted route DOES consult suppression: a deny-all
    # index yields no leads, and it is actually loaded.
    from backend.core import suppression
    calls = []
    class DenyAll:
        email_hashes = frozenset({'x'}); domain_hashes = frozenset(); company_norms = frozenset()
        _meta = {}
        def hit(self, **kwargs):
            return suppression.SuppressionHit(scope=suppression.SuppressionScope.EMAIL, reason=None, source=None)
        def is_suppressed(self, **kwargs): return True
    async def index(): calls.append(1); return DenyAll()
    monkeypatch.setattr(suppression, 'load_index', index)
    async def search(*a, **k): return {'rows':[lead()], 'total':1, 'organizations':[{'company':'Audit','domain':'audit.example'}]}
    client=app(monkeypatch,search)
    r=client.post('/v1/enrich',headers={'Authorization':'Bearer audit-test'},json={'query':'audit.example'}).json()
    assert r['status'] == 'empty'
    assert r['leads'] == []
    assert calls  # suppression was consulted

@pytest.mark.parametrize('payload', [{'rows':42}, {'rows':[], 'organizations':42}, {'rows':[], 'total':float('inf')}])
def test_malformed_engine_object_returns_500(monkeypatch, payload):
    # C3 (inverted repro) — a malformed engine object is validated to unavailable,
    # never a 500. (The client raises ProEngineUnavailable on a bad shape.)
    async def search(*a, **k): return payload
    client = app(monkeypatch, search)
    response = client.post('/v1/enrich', headers={"Authorization":"Bearer audit-test"}, json={"query":"audit.example"})
    assert response.status_code == 200
    assert response.json()['status'] == 'unavailable'

def test_nested_dropped_pii_crosses_projection_and_export():
    # C1 (inverted repro) — a nested dict under `source` is rejected at projection;
    # it never reaches evidence metadata or the export.
    raw = lead(); raw['source'] = {k:'SYNTHETIC_DROPPED_PII' for k in E._DROPPED_FIELDS}
    projected = E._project_lead(raw)
    assert projected['source'] is None
    channel = []
    _inject_pro_leads([], [projected], mode=MODE, key='audit-test',
                      domain='audit.example', corpus_leads_out=channel)
    res = result([]); res.corpus_leads = channel
    exported = json.dumps(R.format_harvest_json_export(res))
    assert 'SYNTHETIC_DROPPED_PII' not in exported
    assert not isinstance(channel[0].evidence[0]['metadata']['corpus_source'], dict)

def test_native_confirmed_person_claim_changes():
    # A2 (inverted repro) — a native confirmed row is NEVER influenced by corpus
    # evidence. The corpus name cannot replace the native person claim, and the
    # native row gains no corpus evidence or module tag.
    row = native()
    before = resolve_person_fields(row, mode=MODE)
    _inject_pro_leads([row], [dict(email=row.email, name='Zoe Corpus', title='CEO')], mode=MODE, key='audit-test')
    after = resolve_person_fields(row, mode=MODE)
    assert before.full_name == 'Steve Native'
    assert after.full_name == 'Steve Native'  # unchanged — corpus never wins
    assert 'mailaccess_pro' not in row.found_by_modules
    assert all(ev['module'] != 'mailaccess_pro' for ev in row.evidence)
    assert row.verification == 'smtp_verified' and row.confidence_label == 'CONFIRMED'

@pytest.mark.parametrize('mode', [MODE.value, 'security-investigation'])
@pytest.mark.parametrize('serializer', ['format_harvest_json_export', 'format_harvest_csv_export', 'format_harvest_ndjson_export'])
def test_keyless_export_is_not_byte_identical(monkeypatch, mode, serializer):
    # A3 (inverted repro) — with no corpus lead present, every machine export is
    # byte-identical to the v0.16.0 (HEAD) serializer: no new columns/keys.
    monkeypatch.setattr(settings, 'mailaccess_pro_key', None)
    source = subprocess.check_output(['git','show','HEAD:backend/core/domain_harvest_report.py']).decode('utf-8')
    old = types.ModuleType('backend.core._audit_old_report'); old.__package__ = 'backend.core'
    exec(compile(source, '<HEAD report>', 'exec'), old.__dict__)
    fixture = result([native()], mode)
    old_out = getattr(old, serializer)(fixture)
    new_out = getattr(R, serializer)(fixture)
    if serializer == 'format_harvest_json_export':
        # Normalise the watermark's wall-clock generation stamp (always time-varying,
        # even within v0.16.0) so the comparison tests the serialization CONTRACT.
        for out in (old_out, new_out):
            if isinstance(out.get('watermark'), dict):
                out['watermark']['generated_at'] = 'NORMALISED'
        # No sort_keys: assert genuine byte-identity (key order preserved too).
        old_out, new_out = json.dumps(old_out, default=str), json.dumps(new_out, default=str)
    assert old_out == new_out

def test_depth_duplicates_reduce_distinct_leads(monkeypatch):
    # C4 (inverted repro) — the 500 cap counts DISTINCT leads. A stream of duplicate
    # rows with a huge reported total collapses to the one distinct address, and the
    # loop is bounded (no-progress guard + page ceiling) despite has_more forever.
    calls = []
    async def search(*a, **k):
        calls.append(k)
        return {'rows':[lead() for _ in range(k['limit'])], 'total':10**30, 'has_more':True}
    monkeypatch.setattr(engine, 'search', search)
    out = asyncio.run(E._serve_domain('audit.example', None, 500))
    assert len(out['leads']) == 1
    assert len({r['email'] for r in out['leads']}) == 1
    assert len(calls) <= 4  # bounded, not an unbounded loop

def test_cached_corpus_never_persisted(monkeypatch, tmp_path):
    import backend.db.database as db
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from backend.db.models import Base
    async def run():
        eng = create_async_engine('sqlite+aiosqlite:///' + (tmp_path/'audit.db').as_posix())
        async with eng.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        monkeypatch.setattr(db, 'AsyncSessionLocal', async_sessionmaker(eng, expire_on_commit=False))
        monkeypatch.setattr(C, '_SCHEMA_READY', True)
        monkeypatch.setattr(settings, 'harvest_cache_enabled', True)
        channel = []; _inject_pro_leads([], [{'email':'synthetic.audit@audit.example', 'name':'Synthetic Audit'}],
            mode=MODE, key='audit-test', domain='audit.example', corpus_leads_out=channel)
        data = result([]); data.corpus_leads = channel; sig = C.scope_signature(mode=MODE.value)
        data.metadata[C.SCOPE_SIGNATURE_KEY] = sig
        await C.write_back('audit.example', data)
        monkeypatch.setattr(settings, 'mailaccess_pro_key', None)
        monkeypatch.setattr(settings, 'mailaccess_pro_lawful_basis_established', False)
        # A1 (inverted repro) — corpus leads are per-query, live-only and are NEVER
        # persisted. The reusable snapshot, the JSON export of it, the contacts
        # projection, and the generic lead reader all contain zero corpus rows.
        cached = await C.read_fresh_crawl('audit.example', C.scope_signature(mode=MODE.value))
        assert cached is not None  # a native-only snapshot was written
        assert all(e.email != 'synthetic.audit@audit.example' for e in cached.unique_emails)
        assert 'synthetic.audit@audit.example' not in json.dumps(R.format_harvest_json_export(cached))
        from sqlalchemy import select
        from backend.db.models import Contact
        async with db.AsyncSessionLocal() as session:
            contacts = (await session.execute(select(Contact))).scalars().all()
            assert all(c.email != 'synthetic.audit@audit.example' for c in contacts)
        served = await C.read_leads('audit.example', mode='security-investigation')
        assert all(row['email'] != 'synthetic.audit@audit.example' for row in served['leads'])
        await eng.dispose()
    asyncio.run(run())
@pytest.mark.parametrize('mode', [MODE.value, 'security-investigation'])
def test_keyless_cli_text_still_identical(monkeypatch, mode):
    monkeypatch.setattr(settings, 'mailaccess_pro_key', None)
    source = subprocess.check_output(['git','show','HEAD:backend/core/domain_harvest_report.py']).decode('utf-8')
    old = types.ModuleType('backend.core._audit_old_report'); old.__package__ = 'backend.core'
    exec(compile(source, '<HEAD report>', 'exec'), old.__dict__)
    fixture = result([native()], mode)
    assert old.format_harvest_cli_output(fixture) == R.format_harvest_cli_output(fixture)

@pytest.mark.parametrize('lawful', [False, True])
def test_server_lawful_basis_gate(monkeypatch, lawful):
    # The server-authoritative lawful-basis gate: while False the tier is
    # unavailable and the engine is never called, even for a valid key.
    calls = []
    async def search(q, **k):
        calls.append(k['mode'])
        return {'rows':[{'full_name':'Steve Lee','email':'steve@audit.example','domain':'audit.example'}],
                'total':1, 'organizations':[{'company':'Audit','domain':'audit.example'}]}
    client = app(monkeypatch, search)
    monkeypatch.setattr(settings, 'mailaccess_pro_lawful_basis_established', lawful)
    r = client.post('/v1/enrich',
        headers={'Authorization':'Bearer audit-test'},
        json={'query':'audit.example','type':'auto'}).json()
    if not lawful:
        assert calls == [] and r['status'] == 'unavailable'
    else:
        assert calls and r['status'] == 'ok'

def test_missing_key_equalizes_store_timing(monkeypatch):
    # P2(d) — an absent key does the SAME store work as a supplied-but-invalid one
    # (both hash + attempt a lookup), so absent-vs-invalid is not timing-
    # distinguishable. Both still fail closed.
    from backend.core import pro_keys
    calls = []
    async def delayed_store():
        calls.append(1); await asyncio.sleep(.025); raise RuntimeError('synthetic unavailable store')
    monkeypatch.setattr(pro_keys,'init_db',delayed_store)
    async def run():
        t=time.perf_counter(); assert not await pro_keys.validate_pro_key(None)
        absent=time.perf_counter()-t
        t=time.perf_counter(); assert not await pro_keys.validate_pro_key('audit-invalid')
        invalid=time.perf_counter()-t
        # Both paths hit the store (comparable work) and neither short-circuits.
        assert calls == [1, 1] and abs(invalid-absent) < .02
    asyncio.run(run())

@pytest.mark.parametrize('target', ['engine','connector'])
def test_drip_response_has_no_total_deadline(monkeypatch, target):
    # C2 (inverted repro) — a drip response that keeps the per-read timeout from ever
    # firing is aborted by the TOTAL wall-clock deadline: the engine client raises
    # ProEngineUnavailable and the connector fails open to `unavailable`, both well
    # before the ~1.2s drip completes.
    from backend.core import mailaccess_pro_connector as connector
    async def run():
        handlers = []
        async def slow(reader, writer):
            handlers.append(asyncio.current_task())
            try:
                await reader.readuntil(b'\r\n\r\n')
                tail=b'{"rows":[],"status":"ok","leads":[]}'
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(30+len(tail)).encode()+b'\r\n\r\n'); await writer.drain()
                for _ in range(30):
                    writer.write(b' '); await writer.drain(); await asyncio.sleep(.04)
                writer.write(tail); await writer.drain()
            except (ConnectionError, asyncio.CancelledError): pass
            finally: writer.close()
        server = await asyncio.start_server(slow, '127.0.0.1', 0)
        base='http://127.0.0.1:'+str(server.sockets[0].getsockname()[1])
        module=engine if target=='engine' else connector
        monkeypatch.setattr(module, '_TIMEOUT', .15)
        monkeypatch.setattr(settings, 'mailaccess_pro_base_url', base)
        monkeypatch.setattr(settings, 'mailaccess_pro_api_url', base)
        monkeypatch.setattr(settings, 'mailaccess_pro_key', 'audit-test')
        start=time.perf_counter()
        try:
            if target=='engine':
                with pytest.raises(engine.ProEngineUnavailable):
                    await engine.search('audit.example',mode='domain',limit=1,offset=0)
            else:
                response=await connector.fetch_leads('audit.example')
                assert response['status']=='unavailable'
            # Aborted at the total deadline, not after the full drip.
            assert time.perf_counter()-start < .5
        finally:
            server.close(); await server.wait_closed()
            for handler in handlers: handler.cancel()
            await asyncio.gather(*handlers, return_exceptions=True)
    asyncio.run(run())

def test_queue_four_stalled_keys_block_fifth():
    # C2 (inverted repro) — a fifth independent key is NOT blocked indefinitely by
    # four stalled keys: its bounded acquire raises ProQueueUnavailable, and once the
    # stalled holders are cancelled a fresh key acquires immediately.
    from backend.core.pro_query_queue import ProQueryQueue, ProQueueUnavailable
    async def run():
        queue=ProQueryQueue(acquire_timeout=.05); occupied=0; ready=asyncio.Event(); never=asyncio.Event()
        async def hold(key):
            nonlocal occupied
            async with queue.acquire(key):
                occupied+=1
                if occupied==4: ready.set()
                await never.wait()
        tasks=[asyncio.create_task(hold(str(i))) for i in range(4)]
        await ready.wait()
        try:
            with pytest.raises(ProQueueUnavailable):
                async with queue.acquire('fifth'): pass
        finally:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        async with queue.acquire('after-cancellation'): pass
    asyncio.run(run())
