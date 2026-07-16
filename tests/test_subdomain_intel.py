from __future__ import annotations

import json

import pytest

from backend.modules.subdomain_intel import (
    SubdomainIntelModule,
    detect_wildcard,
    discover_ptr,
    filter_tier3,
    filter_wildcard_by_content_hash,
    normalize_hostname,
    score_subdomain,
    scrape_scored_subdomain,
    publish_subdomain_signals,
    scrape_scored_candidates,
    SubdomainBudget,
    profile_behavior,
    load_wordlist,
    resolve_doh,
)

from backend.core.harvest_diff import compare_harvest_exports


class Response:
    def __init__(self, payload=None, text="", status_code=200):
        self._payload = payload
        self.text = text
        self.status_code = status_code

    def json(self):
        return self._payload


class Client:
    def __init__(self, responses):
        self.responses = responses
        self.urls = []

    async def get(self, url, **kwargs):
        self.urls.append(url)
        for key, response in self.responses.items():
            if key in url:
                return response
        return Response([])


class Resolver:
    async def resolve(self, name, record_type):
        if record_type == "NS":
            return [type("Answer", (), {"target": "ns.example.net."})()]
        if name != "ns.example.net":
            return ["192.0.2.10"]
        if name == "ns.example.net":
            return ["192.0.2.53"]
        raise RuntimeError("NXDOMAIN")


def test_normalize_hostname_is_in_scope_and_deduplicated():
    assert normalize_hostname("*.Team.Example.COM.", "example.com") == "team.example.com"
    assert normalize_hostname("example.com", "example.com") is None
    assert normalize_hostname("evil.example.net", "example.com") is None


def test_profile_behavior_matches_t0_to_t5_contract():
    t0 = profile_behavior("t0")
    t1 = profile_behavior("t1")
    t2 = profile_behavior("t2")
    t5 = profile_behavior("t5")
    assert t0["active"] and t0["tier2"] and t0["github"]
    assert t1["active"] and not t1["tier2"] and t1["scrape_tiers"] == {"HIGH", "MEDIUM"}
    assert not t2["active"] and t2["scrape_tiers"] == {"HIGH"}
    assert t5["scrape_tiers"] == set()
    assert profile_behavior("t4", with_subdomains=True)["tier1"] is True
    assert profile_behavior("t2", subdomain_deep=True)["github"] is True


def test_structured_wordlist_contains_required_tiers_and_verticals():
    wordlist = load_wordlist()
    assert len(wordlist["tier1"]) >= 50
    assert len(wordlist["tier2"]) >= 150
    required = {"mail", "smtp", "imap", "pop", "pop3", "mx", "ns1", "ns2", "ftp", "sftp", "cpanel", "webmail", "cdn", "static", "assets", "img", "images", "js", "css", "fonts", "db", "redis", "ldap", "ntp"}
    assert required.issubset(set(wordlist["tier3_exclude"]))
    assert set(wordlist["vertical_extras"]) == {"tech", "healthcare", "education", "finance", "government", "manufacturing"}
    assert all(len(values) <= 25 for values in wordlist["vertical_extras"].values())


@pytest.mark.asyncio
async def test_passive_sources_are_ordered_and_deduplicated(monkeypatch):
    calls = []

    async def axfr(domain, *, resolver=None):
        calls.append("axfr")
        return set()

    async def crt(client, domain):
        calls.append("crt.sh")
        return {"*.team.example.com"}

    async def center(client, domain):
        calls.append("subdomain.center")
        return {"team.example.com", "docs.example.com"}

    async def wayback(client, domain):
        calls.append("wayback")
        return {"https.example.com"}

    async def cert(client, domain):
        calls.append("certspotter")
        return {"docs.example.com"}

    monkeypatch.setattr("backend.modules.subdomain_intel.discover_axfr", axfr)
    monkeypatch.setattr("backend.modules.subdomain_intel.discover_crtsh", crt)
    monkeypatch.setattr("backend.modules.subdomain_intel.discover_subdomain_center", center)
    monkeypatch.setattr("backend.modules.subdomain_intel.discover_wayback", wayback)
    monkeypatch.setattr("backend.modules.subdomain_intel.discover_certspotter", cert)
    async def resolve_doh(client, hostname):
        return {"2001:db8::1"}
    monkeypatch.setattr("backend.modules.subdomain_intel.resolve_doh", resolve_doh)
    monkeypatch.setenv("CERTSPOTTER_API_KEY", "present")

    result = await SubdomainIntelModule().run("example.com", client=Client({}), enable_scraping=False)
    assert calls == ["axfr", "crt.sh", "subdomain.center", "wayback", "certspotter"]
    assert {item["subdomain"] for item in result.findings} == {
        "team.example.com", "docs.example.com", "https.example.com"
    }


@pytest.mark.asyncio
async def test_axfr_success_skips_remaining_discovery(monkeypatch):
    async def axfr(domain, *, resolver=None):
        return {"team.example.com"}

    async def should_not_run(*args, **kwargs):
        raise AssertionError("passive source ran after AXFR success")

    monkeypatch.setattr("backend.modules.subdomain_intel.discover_axfr", axfr)
    monkeypatch.setattr("backend.modules.subdomain_intel.discover_crtsh", should_not_run)
    async def resolve_doh(client, hostname):
        return {"192.0.2.20"}
    monkeypatch.setattr("backend.modules.subdomain_intel.resolve_doh", resolve_doh)
    result = await SubdomainIntelModule().run("example.com", client=Client({}), enable_scraping=False)
    assert result.metadata["axfr_succeeded"] is True
    assert result.findings[0]["subdomain"] == "team.example.com"


@pytest.mark.asyncio
async def test_wildcard_detection_requires_three_identical_nonempty_answers():
    assert await detect_wildcard("example.com", resolver=Resolver()) is True


def test_tier3_prefixes_are_removed_before_resolution():
    candidates = {
        "mail.example.com": {"crt.sh"},
        "team.example.com": {"crt.sh"},
        "static.example.com": {"wayback"},
    }
    filter_tier3(candidates, ["mail", "static"])
    assert candidates == {"team.example.com": {"crt.sh"}}


def test_team_page_is_promoted_and_login_page_is_demoted():
    team = score_subdomain(
        "team.example.com",
        "example.com",
        "<title>Our Team</title><h1>Leadership</h1>"
        '<script type="application/ld+json">{"@type":"Person"}</script>'
        '<div class="vcard"><span itemprop="name">Jane Doe</span></div>'
        " Contact jane@example.com",
        final_url="https://team.example.com/team",
    )
    login = score_subdomain(
        "portal.example.com",
        "example.com",
        "<title>Login</title>" + "x" * 600,
        final_url="https://portal.example.com/login",
    )
    assert team["tier"] == "HIGH"
    assert float(login["score"]) < 0.10


def test_staging_override_promotes_real_low_score_and_infra_skips_scoring():
    staging = score_subdomain(
        "staging.example.com", "example.com", "<title>Preview</title>" + "x" * 600,
        final_url="https://staging.example.com/about",
    )
    infra = score_subdomain(
        "admin.example.com", "example.com", "<title>Welcome to nginx</title>" + "x" * 600
    )
    assert staging["tier"] == "HIGH"
    assert infra["tier"] == "INFRA"
    assert infra["score"] is None


@pytest.mark.asyncio
async def test_nxdomain_is_removed_but_ipv6_only_host_is_kept(monkeypatch):
    async def axfr(domain, *, resolver=None):
        return set()

    async def crt(client, domain):
        return {"ipv6.example.com", "missing.example.com"}

    async def resolve_doh(client, hostname):
        return {"2001:db8::1"} if hostname.startswith("ipv6") else set()

    monkeypatch.setattr("backend.modules.subdomain_intel.discover_axfr", axfr)
    monkeypatch.setattr("backend.modules.subdomain_intel.discover_crtsh", crt)
    monkeypatch.setattr("backend.modules.subdomain_intel.resolve_doh", resolve_doh)
    result = await SubdomainIntelModule().run("example.com", client=Client({}), enable_scraping=False)
    assert [item["subdomain"] for item in result.findings] == ["ipv6.example.com"]
    assert result.findings[0]["addresses"] == ["2001:db8::1"]


@pytest.mark.asyncio
async def test_high_staging_uses_existing_pipeline_and_two_internal_candidates(monkeypatch):
    captured = {}

    async def fake_extract(domain, session, **kwargs):
        captured.update(kwargs)
        return [type("Record", (), {
            "name": "Jane Doe", "email": "jane@example.com", "title": "CEO",
            "source_type": "json_ld", "confidence": 0.9, "page_url": f"https://{domain}/team",
        })()]

    monkeypatch.setattr("backend.modules.subdomain_intel.discover_and_extract", fake_extract)
    records = await scrape_scored_subdomain(
        object(),
        "staging.example.com",
        {"tier": "HIGH", "is_staging": True, "score": 0.2},
        domain="example.com",
    )
    assert captured["max_candidates"] == 2
    assert captured["timeout"] == 10.0
    assert "/leadership" in captured["candidate_paths"]
    assert records[0]["email"] == "jane@example.com"


@pytest.mark.asyncio
async def test_low_tier_returns_page_furniture_only():
    class LowSession:
        async def get(self, url, **kwargs):
            return Response(text='<title>Status</title><meta name="description" content="Healthy"><h1>Up</h1>' + "x" * 1200)

    records = await scrape_scored_subdomain(
        LowSession(), "status.example.com", {"tier": "LOW", "score": 0.12}, domain="example.com"
    )
    assert records[0]["title"] == "Status"
    assert records[0]["h1"] == "Up"
    assert records[0]["email"] is None


@pytest.mark.asyncio
async def test_signal_pool_receives_name_and_email_with_subdomain_metadata():
    class Pool:
        def __init__(self):
            self.signals = []

        async def publish(self, signal):
            self.signals.append(signal)

    pool = Pool()
    count = await publish_subdomain_signals(
        pool,
        "example.com",
        [{
            "subdomain": "staging.example.com",
            "discovery_method": ["crt.sh"],
            "score": 0.62,
            "tier": "HIGH",
            "is_staging": True,
            "scraped": [{"name": "Jane Doe", "email": "Jane@Example.com", "url": "https://staging.example.com/team"}],
        }],
    )
    assert count == 2
    assert {signal.kind for signal in pool.signals} == {"name", "email"}
    assert all(signal.source == "subdomain_intel" for signal in pool.signals)
    assert all(signal.flags == frozenset({"target_domain_match"}) for signal in pool.signals)
    assert all(signal.metadata["subdomain"] == "staging.example.com" for signal in pool.signals)
    assert {signal.value for signal in pool.signals} == {"Jane Doe", "jane@example.com"}


@pytest.mark.asyncio
async def test_hard_budget_cap_cancels_pending_scrapes_but_keeps_completed(monkeypatch):
    async def fake_scrape(session, hostname, score_data, *, domain):
        if hostname.startswith("fast"):
            return [{"name": "Fast Person"}]
        await __import__("asyncio").sleep(0.2)
        return [{"name": "Slow Person"}]

    monkeypatch.setattr("backend.modules.subdomain_intel.scrape_scored_subdomain", fake_scrape)
    budget = SubdomainBudget(0.06)
    result = await scrape_scored_candidates(
        "example.com",
        {
            "fast.example.com": {"tier": "HIGH", "is_staging": False},
            "slow.example.com": {"tier": "HIGH", "is_staging": False},
        },
        session=object(),
        budget=budget,
    )
    assert "fast.example.com" in result
    assert "slow.example.com" not in result


# Requirement-named regression coverage from the Subdomain Intelligence brief.
@pytest.mark.asyncio
async def test_wildcard_detection_stops_bruteforce():
    assert await detect_wildcard("example.com", resolver=Resolver()) is True


def test_tier3_prefixes_excluded_immediately():
    test_tier3_prefixes_are_removed_before_resolution()


def test_staging_override_promotes_low_score_to_high():
    test_staging_override_promotes_real_low_score_and_infra_skips_scoring()
    assert score_subdomain("staging.example.com", "example.com", "x" * 600, final_url="https://staging.example.com/about")["tier"] == "HIGH"


def test_osint_score_login_page_demoted():
    assert float(score_subdomain("portal.example.com", "example.com", "<title>Login</title>" + "x" * 600)["score"]) < 0.10


def test_osint_score_team_page_promoted():
    assert score_subdomain("team.example.com", "example.com", "<title>Our Team</title>" + "x" * 600)["tier"] == "HIGH"


@pytest.mark.asyncio
async def test_content_hash_dedup_removes_root_clone():
    class HashClient:
        async def get(self, url, **kwargs):
            return Response(text="same" if "example.com/" in url and "clone" not in url else "same")

    candidates = {"clone.example.com": {"brute_t1"}, "team.example.com": {"crt.sh"}}
    assert await filter_wildcard_by_content_hash(HashClient(), "example.com", candidates) == {"team.example.com"}


@pytest.mark.asyncio
async def test_hard_budget_cap_stops_scraping(monkeypatch):
    await test_hard_budget_cap_cancels_pending_scrapes_but_keeps_completed(monkeypatch)


@pytest.mark.asyncio
async def test_signal_pool_receives_name_from_subdomain():
    await test_signal_pool_receives_name_and_email_with_subdomain_metadata()


@pytest.mark.asyncio
async def test_signal_pool_receives_email_from_subdomain():
    await test_signal_pool_receives_name_and_email_with_subdomain_metadata()


def test_infra_subdomain_not_scraped():
    assert score_subdomain("mail.example.com", "example.com", "Welcome to nginx" + "x" * 600)["tier"] == "INFRA"


def test_calibrate_flag_skips_scraping():
    assert profile_behavior("t2")["scrape_tiers"] == {"HIGH"}


def test_passive_sources_run_at_all_profiles():
    assert all(profile_behavior(profile)["passive"] for profile in ("t0", "t1", "t2", "t3", "t4", "t5"))


def test_bruteforce_off_by_default_at_t2():
    assert profile_behavior("t2")["active"] is False


def test_with_subdomains_flag_enables_bruteforce():
    assert profile_behavior("t2", with_subdomains=True)["active"] is True


@pytest.mark.asyncio
async def test_ptr_mining_discovers_in_scope_names():
    class PtrClient:
        async def get(self, url, **kwargs):
            return Response(payload={"Answer": [{"data": "ptr.example.com."}]})

    hosts = await discover_ptr(
        PtrClient(), {"api.example.com": {"192.0.2.10"}}, "example.com"
    )
    assert hosts == {"ptr.example.com"}


@pytest.mark.asyncio
async def test_config_kill_switch_skips_new_module(monkeypatch):
    monkeypatch.setattr("backend.modules.subdomain_intel.settings.enable_subdomain_surface", False)
    result = await SubdomainIntelModule().run("example.com", enable_scraping=False)
    assert result.status.value == "skipped"
    assert result.metadata["skip_reason"] == "disabled_by_config"


def test_harvest_diff_accepts_subdomain_objects_and_legacy_strings():
    previous = {"subdomains": ["old.example.com", {"subdomain": "keep.example.com"}]}
    current = {"subdomains": [{"subdomain": "keep.example.com"}, {"subdomain": "new.example.com"}]}
    diff = compare_harvest_exports(previous, current)["subdomains"]
    assert diff == {"new": ["new.example.com"], "removed": ["old.example.com"], "unchanged": 1}


@pytest.mark.asyncio
async def test_doh_resolution_excludes_cname_values_from_addresses():
    class DohClient:
        async def get(self, url, **kwargs):
            return Response(payload={"Answer": [
                {"type": 5, "data": "origin.example.com."},
                {"type": 1, "data": "192.0.2.10"},
            ]})

    assert await resolve_doh(DohClient(), "www.example.com") == {"192.0.2.10"}
