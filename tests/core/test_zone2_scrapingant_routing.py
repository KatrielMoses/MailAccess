from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Zone2AuditCallSite:
    module_path: str
    function_name: str
    call_index: int
    expected_zone: str | None
    source_url_pattern: str
    decision: str


ZONE2_AUDITED_CALL_SITES = (
    Zone2AuditCallSite(
        "backend/modules/alternate_email.py",
        "run",
        2,
        None,
        "https://www.gravatar.com/{hash}.json",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/breach_deep.py",
        "run",
        1,
        "platforms",
        "mixed account-existence/profile endpoints",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/code_and_cert_email.py",
        "run",
        2,
        None,
        "https://crt.sh/?q=%.{domain}&output=json",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/code_and_cert_email.py",
        "run",
        3,
        None,
        "https://api.certspotter.com/v1/issuances?...",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/commoncrawl_email.py",
        "run",
        1,
        None,
        "Common Crawl index plus page fetches",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/domain_harvester.py",
        "run",
        1,
        None,
        "crt.sh/certspotter/bufferover/run/threatminer collectors",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/employee_name_discovery.py",
        "_linkedin",
        1,
        "platforms",
        "LinkedIn and search-result HTML",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/employee_name_discovery.py",
        "_company_pages",
        1,
        "platforms",
        "public company pages",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/fediverse_discovery.py",
        "run",
        1,
        None,
        "WebFinger/nodeinfo/instance APIs",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/gravatar.py",
        "_run_for_email",
        1,
        None,
        "https://www.gravatar.com/{hash}.json",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/gravatar_lookup.py",
        "run",
        1,
        None,
        "https://www.gravatar.com/{hash}.json",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/hackernews.py",
        "run",
        1,
        None,
        "HN Firebase and Algolia APIs",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/hudson_rock.py", "run", 1, None, "/search-by-email", "DROP"
    ),
    Zone2AuditCallSite(
        "backend/modules/hudson_rock.py",
        "search_by_domain",
        1,
        None,
        "/search-by-domain",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/hudson_rock.py",
        "search_by_username",
        1,
        None,
        "/search-by-username",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/keybase.py",
        "run",
        1,
        None,
        "https://keybase.io/_/api/1.0/user/lookup.json",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/linkedin_serp.py",
        "_ddg_search",
        1,
        "platforms",
        "https://html.duckduckgo.com/html/",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/marketplace_profile.py",
        "run",
        1,
        "platforms",
        "Etsy/eBay profile HTML",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/messaging_hints.py",
        "run",
        1,
        None,
        "t.me and wa.me landing pages",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/npm_discovery.py",
        "run",
        1,
        None,
        "registry.npmjs.org",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/npm_email.py",
        "run",
        1,
        None,
        "registry.npmjs.org",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/opencorporates.py",
        "run",
        1,
        None,
        "api.opencorporates.com",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/orcid_lookup.py",
        "run",
        1,
        None,
        "pub.orcid.org/v3.0",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/pastebin_search.py",
        "run",
        1,
        None,
        "https://psbdmp.ws/api/v3/search/{email}",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/pgp_domain_email.py",
        "run",
        1,
        None,
        "keys.openpgp.org and keyserver.ubuntu.com",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/pgp_keyserver.py",
        "run",
        1,
        None,
        "OpenPGP by-email and Ubuntu HKP",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/phone_intel.py",
        "run",
        1,
        None,
        "apilayer validate, wa.me, t.me",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/press_intel.py",
        "run",
        1,
        "platforms",
        "DuckDuckGo HTML and press-release pages",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/pypi_discovery.py",
        "run",
        1,
        "platforms",
        "PyPI search HTML and package JSON",
        "KEEP",
    ),
    Zone2AuditCallSite(
        "backend/modules/pypi_email.py",
        "run",
        1,
        None,
        "PyPI XML-RPC and JSON APIs",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/ransomware_intel.py",
        "run",
        1,
        None,
        "ransomware feed API",
        "DROP",
    ),
    Zone2AuditCallSite(
        "backend/modules/sec_edgar.py", "run", 1, None, "SEC submissions API", "DROP"
    ),
    Zone2AuditCallSite(
        "backend/modules/social.py",
        "run",
        1,
        "platforms",
        "social platform profile pages",
        "KEEP",
    ),
    Zone2AuditCallSite("backend/modules/wayback.py", "run", 1, None, "Wayback CDX API", "DROP"),
    Zone2AuditCallSite(
        "backend/modules/whois_lookup.py", "_fetch_rdap", 1, None, "RDAP endpoint", "DROP"
    ),
)

ROUTED_MODULES = {
    call.module_path for call in ZONE2_AUDITED_CALL_SITES if call.expected_zone == "platforms"
}

EXCLUDED_MODULES = {
    "backend/modules/companies_house.py",
    "backend/modules/email_discovery.py",
    "backend/modules/github_code_search.py",
    "backend/modules/github_commits.py",
    "backend/modules/haveibeenpwned.py",
    "backend/modules/hibp.py",
    "backend/modules/hunter_io.py",
    "backend/modules/intelx_lookup.py",
    "backend/modules/leakcheck.py",
    "backend/modules/shodan.py",
    "backend/modules/twitter_profile.py",
    "backend/modules/xposedornot.py",
}

LOCAL_OR_NO_CLIENT_MODULES = {
    "backend/modules/dns_lookup.py",
}

SPLIT_MODULES = {
    "backend/modules/alternate_email.py",
    "backend/modules/code_and_cert_email.py",
}

AUDITED_DIRECT_MODULES = {
    call.module_path
    for call in ZONE2_AUDITED_CALL_SITES
    if call.expected_zone is None and call.module_path not in SPLIT_MODULES
}

MISSING_INCLUDE_MODULES = {
    "backend/modules/email_pattern_generator.py",
}

ZONE2_INCLUDE_LIST = (
    ROUTED_MODULES
    | AUDITED_DIRECT_MODULES
    | EXCLUDED_MODULES
    | LOCAL_OR_NO_CLIENT_MODULES
    | SPLIT_MODULES
    | MISSING_INCLUDE_MODULES
)

RAW_HTTPX_OUTLIERS = {
    "backend/modules/fediverse_discovery.py",
    "backend/modules/gravatar_lookup.py",
    "backend/modules/pastebin_search.py",
}


def _source(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _tree(relative_path: str) -> ast.Module:
    return ast.parse(_source(relative_path), filename=relative_path)


def _build_client_zones(relative_path: str) -> list[str | None]:
    zones: list[str | None] = []
    for node in ast.walk(_tree(relative_path)):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "build_client":
            continue
        zones.append(_scrapingant_zone(node))
    return zones


def _build_client_zones_in_function(relative_path: str, function_name: str) -> list[str | None]:
    function = _find_function(relative_path, function_name)
    return [_scrapingant_zone(call) for call in _build_client_calls(function)]


def _find_function(relative_path: str, function_name: str) -> ast.AST:
    for node in ast.walk(_tree(relative_path)):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function_name:
            return node
    raise AssertionError(f"{function_name} not found in {relative_path}")


def _build_client_calls(function: ast.AST) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        if not isinstance(child.func, ast.Name) or child.func.id != "build_client":
            continue
        calls.append(child)
    return sorted(calls, key=lambda call: (call.lineno, call.col_offset))


def _scrapingant_zone(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "scrapingant_zone" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value
    return None


def test_zone2_include_list_is_classified_once() -> None:
    assert ROUTED_MODULES
    assert not (ROUTED_MODULES & LOCAL_OR_NO_CLIENT_MODULES)
    assert not (ROUTED_MODULES & SPLIT_MODULES)
    assert not (ROUTED_MODULES & AUDITED_DIRECT_MODULES)
    assert not (EXCLUDED_MODULES & LOCAL_OR_NO_CLIENT_MODULES)
    assert not (EXCLUDED_MODULES & SPLIT_MODULES)
    assert not (EXCLUDED_MODULES & AUDITED_DIRECT_MODULES)
    assert not (AUDITED_DIRECT_MODULES & SPLIT_MODULES)
    assert not (AUDITED_DIRECT_MODULES & LOCAL_OR_NO_CLIENT_MODULES)
    assert not (MISSING_INCLUDE_MODULES & ROUTED_MODULES)
    assert not (MISSING_INCLUDE_MODULES & EXCLUDED_MODULES)
    assert not (MISSING_INCLUDE_MODULES & LOCAL_OR_NO_CLIENT_MODULES)
    assert not (MISSING_INCLUDE_MODULES & SPLIT_MODULES)

    expected = {
        "backend/modules/alternate_email.py",
        "backend/modules/code_and_cert_email.py",
        "backend/modules/companies_house.py",
        "backend/modules/dns_lookup.py",
        "backend/modules/email_discovery.py",
        "backend/modules/email_pattern_generator.py",
        "backend/modules/github_code_search.py",
        "backend/modules/github_commits.py",
        "backend/modules/haveibeenpwned.py",
        "backend/modules/hibp.py",
        "backend/modules/hunter_io.py",
        "backend/modules/intelx_lookup.py",
        "backend/modules/leakcheck.py",
        "backend/modules/shodan.py",
        "backend/modules/twitter_profile.py",
        "backend/modules/xposedornot.py",
    }
    expected |= {call.module_path for call in ZONE2_AUDITED_CALL_SITES}
    assert ZONE2_INCLUDE_LIST == expected


def test_routed_zone2_modules_pass_platforms_zone_to_build_client() -> None:
    for module_path in sorted(ROUTED_MODULES):
        zones = _build_client_zones(module_path)
        assert "platforms" in zones, module_path


def test_excluded_zone2_modules_do_not_route_through_platforms_zone() -> None:
    for module_path in sorted(EXCLUDED_MODULES):
        zones = _build_client_zones(module_path)
        assert "platforms" not in zones, module_path


def test_linkedin_serp_routes_only_the_keyless_duckduckgo_branch() -> None:
    assert _build_client_zones_in_function("backend/modules/linkedin_serp.py", "_ddg_search") == [
        "platforms"
    ]
    assert _build_client_zones_in_function(
        "backend/modules/linkedin_serp.py", "_serpapi_search"
    ) == [None]


def test_local_zone2_modules_do_not_construct_routed_clients() -> None:
    for module_path in sorted(LOCAL_OR_NO_CLIENT_MODULES):
        assert _build_client_zones(module_path) == [], module_path


def test_missing_zone2_include_modules_are_not_present_in_this_checkout() -> None:
    for module_path in sorted(MISSING_INCLUDE_MODULES):
        assert not (REPO_ROOT / module_path).exists(), module_path


def test_split_modules_route_keyless_branches_without_routing_github_traffic() -> None:
    assert _build_client_zones_in_function("backend/modules/alternate_email.py", "run") == [
        None,
        None,
    ]
    assert _build_client_zones_in_function("backend/modules/code_and_cert_email.py", "run") == [
        None,
        None,
        None,
    ]


def test_raw_httpx_outliers_no_longer_construct_async_client_directly() -> None:
    for module_path in sorted(RAW_HTTPX_OUTLIERS):
        assert "httpx.AsyncClient(" not in _source(module_path), module_path


def test_zone2_audited_call_sites_match_documented_decisions() -> None:
    for call_site in ZONE2_AUDITED_CALL_SITES:
        calls = _build_client_calls(_find_function(call_site.module_path, call_site.function_name))
        assert len(calls) >= call_site.call_index, call_site
        actual_zone = _scrapingant_zone(calls[call_site.call_index - 1])
        assert actual_zone == call_site.expected_zone, (
            call_site.module_path,
            call_site.function_name,
            call_site.call_index,
            call_site.source_url_pattern,
        )


def test_transport_split_does_not_change_zone_audit_decisions() -> None:
    for call_site in ZONE2_AUDITED_CALL_SITES:
        if call_site.decision != "KEEP":
            continue
        calls = _build_client_calls(_find_function(call_site.module_path, call_site.function_name))
        assert len(calls) >= call_site.call_index, call_site
        actual_zone = _scrapingant_zone(calls[call_site.call_index - 1])
        assert actual_zone == call_site.expected_zone, call_site
