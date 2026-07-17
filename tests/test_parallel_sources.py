import asyncio
import time

from backend.core.cc_index_client import CommonCrawlClient
from backend.modules.base import ModuleStatus
from backend.modules.pgp_domain_email import PgpDomainEmailModule, _SubSourceOutcome
from backend.modules.subdomain_intel import SubdomainIntelModule


def test_pgp_keyservers_queried_in_parallel(monkeypatch):
    module = PgpDomainEmailModule()

    # 0.13.2: sources mutate a shared outcome (partial-credit support).
    async def query(domain, client, outcome):
        await asyncio.sleep(0.05)
        outcome.ok = True
        return outcome

    monkeypatch.setattr(module, "_query_mit", query)
    monkeypatch.setattr(module, "_query_openpgp", query)
    monkeypatch.setattr(module, "_query_ubuntu", query)
    started = time.monotonic()
    result = asyncio.run(module.run("example.com"))
    assert time.monotonic() - started < 0.12
    assert result.status == ModuleStatus.SUCCESS


def test_pgp_one_server_timeout_does_not_fail_module(monkeypatch):
    module = PgpDomainEmailModule()
    # Keep the backoff retry from adding real latency to the test.
    monkeypatch.setattr("backend.modules.pgp_domain_email._RETRY_BACKOFF_SECONDS", 0.0)

    async def good(domain, client, outcome):
        outcome.ok = True
        return outcome

    async def bad(domain, client, outcome):
        raise asyncio.TimeoutError

    monkeypatch.setattr(module, "_query_mit", bad)
    monkeypatch.setattr(module, "_query_openpgp", good)
    monkeypatch.setattr(module, "_query_ubuntu", good)
    assert asyncio.run(module.run("example.com")).status == ModuleStatus.SUCCESS


def test_cc_collections_queried_in_batches_of_3(monkeypatch):
    client = CommonCrawlClient(min_interval=0)
    active = 0
    peak = 0

    async def collections():
        return [f"CC-MAIN-2026-{i:02d}" for i in range(6)]

    async def query(*args, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return []

    monkeypatch.setattr(client, "get_available_collections", collections)
    monkeypatch.setattr(client, "_query_index", query)
    asyncio.run(client.query_multi_collection("example.com"))
    asyncio.run(client.aclose())
    assert peak == 6  # three collections, each with broad + targeted queries


def test_crtsh_certspotter_parallel(monkeypatch):
    import backend.modules.subdomain_intel as source
    running = 0
    overlap = False

    async def empty_axfr(*args, **kwargs):
        return set()

    async def delayed(*args, **kwargs):
        nonlocal running, overlap
        running += 1
        overlap = overlap or running > 1
        await asyncio.sleep(0.02)
        running -= 1
        return set()

    monkeypatch.setattr(source, "discover_axfr", empty_axfr)
    monkeypatch.setattr(source, "discover_crtsh", delayed)
    monkeypatch.setattr(source, "discover_certspotter", delayed)
    monkeypatch.setattr(source, "discover_subdomain_center", lambda *a, **k: delayed())
    monkeypatch.setattr(source, "discover_wayback", lambda *a, **k: delayed())
    monkeypatch.setattr(source, "resolve_candidates", lambda *a, **k: asyncio.sleep(0, result={}))
    asyncio.run(SubdomainIntelModule().run("example.com", profile="t5", client=_DummyClient()))
    assert overlap


class _DummyClient:
    async def aclose(self):
        pass
