import asyncio
from unittest.mock import AsyncMock

from rich.console import Console

from backend.core.domain_harvest_orchestrator import DomainHarvestResult
from backend.core.domain_harvest_report import (
    _build_infrastructure,
    _build_suggested_next_steps,
    _format_infrastructure_panel,
    format_harvest_json_export,
)
from backend.core.harvest_results import _write_cidr_file as write_cidr_file
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.hackertarget_hosts import (
    HackerTargetHostsModule,
    parse_hackertarget_response,
)
from backend.modules.ripe_stat_asn import (
    RIPEStatASNModule,
    parse_ripe_network_info,
    parse_ripe_stat,
)
from backend.modules.shodan_internetdb import ShodanInternetDBModule, parse_internetdb
from backend.modules.subdomain_intel import lookup_asn_team_cymru
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
    rows = parse_hackertarget_response(
        "www.example.com,1.2.3.4\nevil.com,5.6.7.8", "example.com"
    )
    assert rows == [
        {
            "subdomain": "www.example.com",
            "addresses": ["1.2.3.4"],
            "resolved_ips": ["1.2.3.4"],
            "discovery_method": ["hackertarget"],
            "score": 0.0,
            "tier": "LOW",
            "scraped": [],
        }
    ]


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
    monkeypatch.setattr(
        command,
        "format_harvest_json_export",
        lambda result: {
            "infrastructure": {"asns": [{"prefixes": ["192.0.2.0/24"]}]}
        },
    )
    path = _write_cidr_file(Result(), "20260716_100000")
    assert path.read_text() == "192.0.2.0/24\n"


def test_ripe_stat_cap_20_asns():
    client = _Client(_Response(payload={"data": {"prefixes": []}}))
    rows = [{"asn": 64000 + i, "name": "Example"} for i in range(25)]
    records = asyncio.run(RIPEStatASNModule().enrich(rows, client=client))
    assert len(records) == 20
    assert len(client.calls) == 40  # announced-prefixes + as-overview per ASN


def test_ripe_network_info_resolves_ip_to_asn_and_prefix():
    rows = parse_ripe_network_info(
        "108.139.47.74",
        {"data": {"asns": [16509], "prefix": "108.139.44.0/22"}},
    )

    assert rows == [
        {
            "asn": 16509,
            "name": "Unknown",
            "ips": ["108.139.47.74"],
            "cidrs": ["108.139.44.0/22"],
            "prefixes": ["108.139.44.0/22"],
            "subdomains": [],
            "sources": ["ripe_stat"],
        }
    ]


def test_team_cymru_uses_origin_query_without_in_addr_arpa():
    class Resolver:
        def __init__(self):
            self.queries = []

        async def resolve(self, name, record_type):
            self.queries.append((name, record_type))
            return ['"16509 | 108.139.44.0/22 | US | arin | 2018-09-18"']

    resolver = Resolver()
    record = asyncio.run(lookup_asn_team_cymru("108.139.47.74", resolver=resolver))

    assert resolver.queries == [
        ("74.47.139.108.origin.asn.cymru.com", "TXT")
    ]
    assert record == {
        "asn": 16509,
        "prefix": "108.139.44.0/22",
        "country": "US",
        "rir": "arin",
        "date": "2018-09-18",
    }


def _asn_result() -> DomainHarvestResult:
    return DomainHarvestResult(
        domain="example.com",
        started_at="2026-07-16T00:00:00Z",
        completed_at="2026-07-16T00:00:01Z",
        duration_seconds=1.0,
        module_results={
            "hackertarget_hosts": ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={
                    "infrastructure": {
                        "ips": [
                            {
                                "ip": "192.0.2.1",
                                "subdomains": ["www.example.com"],
                                "sources": ["hackertarget"],
                            }
                        ],
                        "asns": [],
                    }
                },
            ),
            "ripe_stat_asn": ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={
                    "infrastructure": {
                        "ips": [
                            {
                                "ip": "192.0.2.1",
                                "asn": 64500,
                                "sources": ["hackertarget", "ripe_stat"],
                            }
                        ],
                        "asns": [
                            {
                                "asn": 64500,
                                "name": "Example Networks",
                                "ips": ["192.0.2.1"],
                                "prefixes": ["192.0.2.0/24"],
                                "cidrs": ["192.0.2.0/24"],
                                "sources": ["ripe_stat"],
                            }
                        ],
                    }
                },
            ),
        },
        unique_emails=[],
        total_unique_emails=0,
        high_confidence_count=0,
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=0,
        role_account_count=0,
        personal_email_count=0,
    )


def test_ripe_stat_run_calls_enrich_with_resolved_ips() -> None:
    module = RIPEStatASNModule()
    module.enrich = AsyncMock(
        return_value={
            64500: {
                "asn": 64500,
                "name": "Example Networks",
                "org_name": "Example Networks",
                "ips": ["192.0.2.1"],
                "prefixes": ["192.0.2.0/24"],
                "cidrs": ["192.0.2.0/24"],
                "sources": ["ripe_stat"],
            }
        }
    )

    result = asyncio.run(
        module.run("example.com", resolved_ips=["192.0.2.1", "192.0.2.1"])
    )

    module.enrich.assert_awaited_once_with(["192.0.2.1"])
    assert result.status is ModuleStatus.SUCCESS
    assert result.metadata["infrastructure"]["asns"][0]["asn"] == 64500


def test_asn_appears_in_infrastructure_json() -> None:
    payload = format_harvest_json_export(_asn_result())

    assert payload["infrastructure"]["asns"][0]["asn"] == 64500
    assert payload["infrastructure"]["asns"][0]["prefixes"] == [
        "192.0.2.0/24"
    ]


def test_cidr_prefixes_normalized_into_json_prefixes_array() -> None:
    result = _asn_result()
    result.module_results["ripe_stat_asn"].metadata["infrastructure"]["asns"][0].pop("prefixes")
    payload = format_harvest_json_export(result)
    assert payload["infrastructure"]["asns"][0]["prefixes"] == ["192.0.2.0/24"]


def test_cidrs_txt_written_with_real_prefixes(tmp_path) -> None:
    path = write_cidr_file(tmp_path / "cidrs.txt", _asn_result())

    assert path is not None
    assert path.read_text(encoding="utf-8") == "192.0.2.0/24\n"


def test_asn_panel_not_empty_when_ips_resolved() -> None:
    console = Console(record=True)
    console.print(_format_infrastructure_panel(_build_infrastructure(_asn_result())))
    output = console.export_text()

    assert "AS64500 Example Networks" in output
    assert "No ASN data resolved" not in output


def test_smtp_used_hint_does_not_tell_analyst_to_enable_smtp() -> None:
    result = _asn_result()
    result.total_unique_emails = 1
    result.smtp_verification_used = True

    hints = _build_suggested_next_steps(result)

    assert not any("--no-verify" in hint for hint in hints)
    assert any("Verification did not confirm" in hint for hint in hints)
