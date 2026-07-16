import asyncio

from backend.modules.base import ModuleStatus
from backend.modules.hackertarget_hosts import HackerTargetHostsModule, parse_hackertarget_response
from backend.modules.ripe_stat_asn import RIPEStatASNModule, parse_ripe_stat
from backend.modules.shodan_internetdb import ShodanInternetDBModule, parse_internetdb
from cli.harvest_emails import _write_cidr_file


class _Response:
    def __init__(self, status=200, text="", payload=None):
        self.status_code, self.text, self._payload = status, text, payload or {}

    def json(self):
        return self._payload


class _Client:
    def __init__(self, response):
        self.response, self.calls = response, []

    async def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response


def test_hackertarget_parses_response_correctly():
    rows = parse_hackertarget_response("www.example.com,1.2.3.4\nevil.com,5.6.7.8", "example.com")
    assert rows == [{"subdomain": "www.example.com", "addresses": ["1.2.3.4"], "resolved_ips": ["1.2.3.4"], "discovery_method": ["hackertarget"], "score": 0.0, "tier": "LOW", "scraped": []}]


def test_hackertarget_429_returns_partial():
    client = _Client(_Response(429))
    result = asyncio.run(HackerTargetHostsModule().run("example.com", fetch=client))
    assert result.status == ModuleStatus.PARTIAL and not result.findings


def test_shodan_internetdb_parses_ports_vulns():
    record = parse_internetdb("1.2.3.4", {"ports": [443, 80], "vulns": ["CVE-1"]})
    assert record.ports == [80, 443] and record.vulns == ["CVE-1"]


def test_shodan_internetdb_cap_50_ips(monkeypatch):
    client = _Client(_Response(payload={"ports": []}))
    async def no_sleep(*args):
        return None
    monkeypatch.setattr("backend.modules.shodan_internetdb.asyncio.sleep", no_sleep)
    ips = [f"10.0.0.{i}" for i in range(1, 61)]
    records = asyncio.run(ShodanInternetDBModule().enrich(ips, client=client))
    assert len(client.calls) == len(records) == 50


def test_ripe_stat_parses_cidr_prefixes():
    record = parse_ripe_stat(64500, "Example", {"data": {"prefixes": [{"prefix": "192.0.2.0/24"}]}})
    assert record.prefixes == ["192.0.2.0/24"]


def test_cidr_file_written_to_results_dir(monkeypatch, tmp_path):
    import cli.harvest_emails as command

    class Result:
        domain = "example.com"

    monkeypatch.setattr(command.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(command, "format_harvest_json_export", lambda result: {"infrastructure": {"asns": [{"prefixes": ["192.0.2.0/24"]}]}})
    path = _write_cidr_file(Result(), "20260716_100000")
    assert path.read_text() == "192.0.2.0/24\n"


def test_ripe_stat_cap_20_asns(monkeypatch):
    client = _Client(_Response(payload={"data": {"prefixes": []}}))
    async def no_sleep(*args):
        return None
    monkeypatch.setattr("backend.modules.ripe_stat_asn.asyncio.sleep", no_sleep)
    rows = [{"asn": 64000 + i, "name": "Example"} for i in range(25)]
    records = asyncio.run(RIPEStatASNModule().enrich(rows, client=client))
    assert len(client.calls) == len(records) == 20
