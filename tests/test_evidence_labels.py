"""One label rule: username_match | possible | confirmed (backend/core/evidence.py).

One test per row of the label table, plus the example.com shape, the trace contract
(technique + signal + reason, reason agrees with label) and the graph filter.
"""

from __future__ import annotations

import re
from typing import Any

from backend.core import evidence
from backend.core.identity_graph import IdentityGraph
from backend.core.platform_dedup import deduplicate_platform_findings
from backend.core.probe_detector import is_confirmed_account_hit
from backend.core.techniques import TECHNIQUES, technique_for
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.username_pivot import _collect_usernames

EMAIL = "alice@example.com"


def _res(*findings: dict[str, Any]) -> ModuleResult:
    return ModuleResult(status=ModuleStatus.SUCCESS, findings=list(findings))


def _sweep(url: str = "https://github.com/alice", **extra: Any) -> dict[str, Any]:
    return {
        "platform": "GitHub", "profile_url": url, "username": "alice", "confidence": "low",
        "metadata": {"source": "username_platforms", "verification": "unverified",
                     "speculative": True, **extra},
    }


def _registration(platform: str = "GitHub", domain: str = "github.com") -> dict[str, Any]:
    return {
        "platform": platform, "profile_url": f"https://{domain}", "confidence": "medium",
        "verification": "unverified", "source": "account_discovery", "email_linked": True,
        "metadata": {"verification": "unverified", "flow": "register"},
    }


def _reset_probe(domain: str = "github.com") -> dict[str, Any]:
    f = {
        "platform": domain, "url": f"https://{domain}/password_reset", "confidence": "medium",
        "verification": "unverified",
        "metadata": {"flow": "login", "method": "browser-oracle"},
    }
    return evidence.normalise_verification(f)


def _annotate(**by_module: ModuleResult) -> dict[str, ModuleResult]:
    evidence.annotate_results(by_module, EMAIL)
    return by_module


# ----------------------------------------------------------------- the label table
def test_username_only_is_username_match() -> None:
    r = _annotate(username_platforms=_res(_sweep()))
    f = r["username_platforms"].findings[0]
    assert f["label"] == "username_match"
    assert f["trace"]["independent_signals"] == 0
    assert not is_confirmed_account_hit(f)


def test_registration_check_alone_is_possible() -> None:
    r = _annotate(account_discovery=_res(_registration()))
    f = r["account_discovery"].findings[0]
    assert f["label"] == "possible"
    assert f["trace"]["independent_signals"] == 1
    # Confidence follows the label: never "high" while only possible.
    assert f["confidence"] == "medium"


def test_registration_plus_reset_probe_is_confirmed() -> None:
    r = _annotate(
        account_discovery=_res(_registration()),
        browser_account_probe=_res(_reset_probe()),
    )
    reg = r["account_discovery"].findings[0]
    probe = r["browser_account_probe"].findings[0]
    for f in (reg, probe):
        assert f["label"] == "confirmed"
        assert f["trace"]["independent_signals"] == 2
        assert f["trace"]["corroborated_by"]
    assert reg["confidence"] == "high"
    assert reg["trace"]["corroborated_by"][0]["module"] == "browser_account_probe"
    assert is_confirmed_account_hit(reg)


def test_two_local_part_guesses_are_not_confirmed() -> None:
    guess_a = {"platform": "HackerNews", "profile_url": "https://news.ycombinator.com/user?id=alice",
               "metadata": {}}
    guess_b = {"platform": "Social", "profile_url": "https://news.ycombinator.com/alice",
               "metadata": {}}
    r = _annotate(hackernews=_res(guess_a), permutation_discovery=_res(guess_b))
    for module in ("hackernews", "permutation_discovery"):
        f = r[module].findings[0]
        assert f["label"] == "possible"  # one signal at most, never two
        assert f["trace"]["independent_signals"] == 1


def test_same_signal_type_twice_counts_once() -> None:
    r = _annotate(
        account_discovery=_res(_registration("GitHub", "github.com"),
                               _registration("GitHub (alt)", "github.com")),
    )
    assert {f["label"] for f in r["account_discovery"].findings} == {"possible"}


def test_pivot_from_an_unverified_username_is_username_match() -> None:
    sweep = _res(_sweep("https://reddit.com/alice"))
    collected = _annotate(username_platforms=sweep)
    origins: dict[str, dict[str, Any]] = {}
    assert "alice" in _collect_usernames(EMAIL, collected, origins)
    assert origins["alice"]["username_match"] is False  # alice came from the email itself

    # A username lifted from an earlier username match is flagged as such.
    other = _sweep("https://reddit.com/bob")
    other["username"] = "bob"
    collected = _annotate(username_platforms=_res(other))
    origins = {}
    _collect_usernames("zed@example.com", collected, origins)
    assert origins["bob"]["username_match"] is True
    assert origins["bob"]["module"] == "username_platforms"

    pivot = {
        "platform": "GitLab", "profile_url": "https://gitlab.com/bob", "username": "bob",
        "confidence": "low",
        "metadata": {"source": "username_pivot", "verification": "unverified",
                     "derived_from_module": "username_platforms",
                     "derived_from_username_match": True},
    }
    r = _annotate(username_pivot=_res(pivot))
    f = r["username_pivot"].findings[0]
    assert f["label"] == "username_match"
    derived = f["trace"]["derived_from"]
    assert derived["type"] == "username" and derived["value"] == "bob"
    assert derived["only_username_match"] is True
    assert "only a username match" in f["trace"]["reason"]


def test_example_com_shape_is_not_confirmed() -> None:
    """The shape that used to come out "confirmed": the sweep and the pivot both guessed
    the same local part and landed on the same account. Two username-derived sources are
    one kind of evidence, so the merged finding stays a username match."""
    results = {
        "username_platforms": _res(_sweep("https://www.example.com/alice")),
        "username_pivot": _res(
            {**_sweep("https://m.example.com/alice"),
             "metadata": {"source": "username_pivot", "verification": "unverified",
                          "speculative": True}}
        ),
    }
    deduplicate_platform_findings(results)
    evidence.annotate_results(results, EMAIL)
    kept = [f for r in results.values() for f in r.findings]
    assert len(kept) == 1
    f = kept[0]
    assert f["label"] == "username_match"
    assert f["metadata"].get("verification") != "confirmed"
    assert f["confidence"] != "high"
    assert not is_confirmed_account_hit(f)


def test_example_com_with_two_independent_signals_is_confirmed() -> None:
    r = _annotate(
        account_discovery=_res(_registration("Example", "example.com")),
        browser_account_probe=_res(_reset_probe("example.com")),
    )
    assert r["account_discovery"].findings[0]["label"] == "confirmed"


# ------------------------------------------------------------- trace + reason contract
def _dns(platform: str, **meta: Any) -> dict[str, Any]:
    return {"platform": platform, "confidence": "high", "metadata": meta}


def test_every_finding_has_technique_signal_and_reason_that_agrees_with_label() -> None:
    r = _annotate(
        username_platforms=_res(_sweep()),
        account_discovery=_res(_registration()),
        browser_account_probe=_res(_reset_probe()),
        hibp=_res({"platform": "Adobe", "metadata": {"breach_name": "Adobe"}}),
        dns_lookup=_res(_dns("dns_mx", mx_provider="Google Workspace")),
    )
    seen = set()
    for module, result in r.items():
        for f in result.findings:
            trace = f["trace"]
            assert trace["technique_id"] and trace["technique"]
            assert trace["signal"], module
            assert 0 < len(trace["reason"]) < 160, module
            assert len(trace["technique"]) < 90
            assert set(trace["derived_from"]) >= {"type", "value", "finding_id"}
            label = f["label"]
            seen.add(label)
            reason = trace["reason"].lower()
            if label is None:
                assert trace["independent_signals"] == 0
                assert "confirmed" not in reason and "possible" not in reason
            elif label == "username_match":
                assert "username" in reason and "confirmed" not in reason
            elif label == "confirmed":
                assert "separate checks agree" in reason
            else:
                assert "nothing else" not in reason or "guess" in reason
                assert "separate checks" not in reason
    assert seen == {"username_match", "possible", "confirmed", None}


def test_records_read_directly_have_no_label_and_say_what_was_read() -> None:
    r = _annotate(
        dns_lookup=_res(
            _dns("dns_mx", mx_provider="Google Workspace"),
            _dns("dns_spf", has_spf=True),
            _dns("dns_a", ip_address="1.2.3.4"),
        ),
        whois_lookup=_res({"platform": "whois", "metadata": {"registrar": "GoDaddy"}}),
        email_credibility=_res({"platform": "email_credibility", "metadata": {"is_alias": False}}),
        domain_cluster=_res({"platform": "infra_cluster", "metadata": {"shared_registrar": "markmonitor"}}),
    )
    reasons = {f["platform"]: f for res in r.values() for f in res.findings}
    for f in reasons.values():
        assert f["label"] is None
        assert f["trace"]["technique"] and f["trace"]["signal"] and f["trace"]["reason"]
        assert f["trace"]["independent_signals"] == 0
    assert reasons["dns_mx"]["trace"]["reason"] == "The domain's mail is handled by Google Workspace (MX record)."
    assert reasons["whois"]["trace"]["reason"] == "WHOIS lists the domain's registrar as GoDaddy."
    assert is_confirmed_account_hit(reasons["dns_mx"]) is False


_UGLY = re.compile(r"\b[a-z0-9]+_[a-z0-9_]+\b|\(source\)|\bsource\)", re.I)


def test_no_reason_contains_an_internal_identifier_or_bracketed_source() -> None:
    gh_commit = {"platform": "github_commit", "profile_url": "https://github.com/o/r/commit/abc",
                 "metadata": {"repo": "owner/name", "commit_sha": "abc"}}
    gh_user = {"platform": "Katriel Moses", "profile_url": "https://github.com/KatrielMoses",
               "metadata": {"login": "KatrielMoses"}}
    google = {"platform": "google_account", "metadata": {"google_hosted": True, "hosting_kind": "gmail"}}
    hn = {"platform": "hackernews_profile", "profile_url": "https://news.ycombinator.com/user?id=alice",
          "metadata": {"username": "alice"}}
    links = {"platform": "social_links", "metadata": {"common_variations": ["alice"]}}
    patreon = {"platform": "Patreon", "metadata": {"note": "inferred via reset flow"}}
    deep = {"platform": "DemandScience by Pure Incubation", "url": "https://demandscience.com",
            "metadata": {"breach_name": "DemandScience"}}
    harvest = {"platform": "host_ip:mail.example.com", "metadata": {"ip": "1.2.3.4"}}
    unknown = {"platform": "wayback_machine", "profile_url": "https://web.archive.org/web/2026/https://a.example/",
               "metadata": {"original_domain": "a.example", "archive_date": "2026-10-01"}}
    r = _annotate(
        github_commits=_res(gh_commit, gh_user), google_account_intel=_res(google),
        hackernews=_res(hn), social_links=_res(links), social=_res(patreon),
        breach_deep=_res(deep), domain_harvester=_res(harvest), wayback=_res(unknown),
        account_discovery=_res(_registration("duolingo", "duolingo.com")),
        username_platforms=_res(_sweep()),
        fediverse_discovery=_res({
            "platform": "mastodon:infosec.exchange", "username": "alice@infosec.exchange",
            "metadata": {"localpart": "alice", "source": "fediverse_webfinger"}}),
    )
    texts = {}
    for module, result in r.items():
        for f in result.findings:
            for field in (f["trace"]["reason"], f["trace"]["signal"], f["trace"]["technique"]):
                assert not _UGLY.search(field), (module, field)
            texts[f["platform"]] = f["trace"]["reason"]
    assert texts["github_commit"] == (
        "A public commit on GitHub lists this email as its author (repo owner/name)."
    )
    assert texts["Katriel Moses"].startswith("A GitHub profile (KatrielMoses) is tied")
    assert texts["hackernews_profile"] == (
        "Hacker News has a user named alice, a guess from the email's local part; "
        "nothing tied to the email agrees yet."
    )
    assert texts["duolingo"] == "Duolingo's sign-up form says an account already uses this email."
    assert "Google" in texts["google_account"]
    assert texts["wayback_machine"] == "An archived copy of a.example from 2026-10-01 mentions this email."


def test_site_names_are_human() -> None:
    from backend.core.evidence import site_name

    assert site_name({"platform": "github_commit", "profile_url": "https://github.com/x"}, "github_commits") == "GitHub"
    assert site_name({"platform": "duolingo"}) == "Duolingo"
    assert site_name({"platform": "github.com"}) == "GitHub"
    assert site_name({"platform": "google_account"}) == "Google"
    assert site_name({"platform": "Docker Hub"}) == "Docker Hub"
    assert site_name({"platform": "mastodon:mas.to"}) == "mas.to"


def test_kinds_come_from_the_contract_set() -> None:
    from backend.core.evidence import IDENTITY_KINDS, kind_for

    assert IDENTITY_KINDS == (
        "account", "username_match", "name", "domain", "breach", "email", "phone", "other"
    )
    r = _annotate(
        github_commits=_res({"platform": "github_commit", "profile_url": "https://github.com/o/r/commit/a",
                             "metadata": {"commit_sha": "a"}}),
        hibp=_res({"platform": "Adobe", "metadata": {"breach_name": "Adobe"}}),
        username_platforms=_res(_sweep()),
        dns_lookup=_res(_dns("dns_mx")),
        email_credibility=_res({"platform": "email_credibility", "metadata": {}}),
        wayback=_res({"platform": "wayback_snapshot", "metadata": {}}),
    )
    kinds = {m: kind_for(m, res.findings[0], res.findings[0]["label"]) for m, res in r.items()}
    assert kinds == {
        "github_commits": "account", "hibp": "breach", "username_platforms": "username_match",
        "dns_lookup": "domain", "email_credibility": "email", "wayback": "other",
    }


def test_traces_carry_no_secrets_or_raw_payloads() -> None:
    f = _registration()
    f["metadata"]["raw_response"] = "<html>SECRET-RAW-BODY</html>"
    f["metadata"]["api_key"] = "sk-test-0123456789"
    r = _annotate(account_discovery=_res(f))
    text = str(r["account_discovery"].findings[0]["trace"])
    assert "SECRET-RAW-BODY" not in text and "sk-test" not in text


def test_catalogue_lines_are_short_and_plain() -> None:
    for module, (tid, line) in TECHNIQUES.items():
        assert tid and line.endswith("."), module
        assert len(line) < 90, (module, len(line))
    # Modules without an entry fall back to a rewrite of their description.
    tid, line = technique_for("some_future_module")
    assert tid == "some_future_module" and line
    assert technique_for("account_discovery")[1].startswith("Checking which sites")


def test_every_registered_module_has_a_technique_line() -> None:
    from backend.modules import get_all_modules

    for cls in get_all_modules():
        _tid, line = technique_for(cls.name)
        assert line and len(line) < 90, cls.name


# ------------------------------------------------------------------------ the graph
def _graph(*rows: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    by_module: dict[str, ModuleResult] = {}
    for module, finding in rows:
        by_module.setdefault(module, _res()).findings.append(finding)
    evidence.annotate_results(by_module, EMAIL)
    findings = [
        {"module_name": m, "data": f} for m, r in by_module.items() for f in r.findings
    ]
    return IdentityGraph.build({"email": EMAIL, "findings": findings}).to_dict()


def _platform_labels(graph: dict[str, Any]) -> set[str]:
    return {n["label"] for n in graph["nodes"] if n["type"] == "platform"}


def test_lone_browser_probe_joins_as_possible_account_and_fediverse_stays_a_username_match() -> None:
    probe = _reset_probe("lone.example")  # top-level verification only, as modules wrote it
    fedi = {
        "platform": "mastodon:mastodon.social", "profile_url": "https://mastodon.social/@alice",
        "username": "alice@mastodon.social", "confidence": "medium",
        "metadata": {"source": "fediverse_webfinger", "verification": "unverified"},
    }
    graph = _graph(("browser_account_probe", probe), ("fediverse_discovery", fedi))
    # One sign-in check is "possible": it joins as an account. The Fediverse guess is
    # only a username match and never becomes an account node.
    assert _platform_labels(graph) == {"Lone"}
    edge_types = {link["type"] for link in graph["links"]}
    assert "username_match" in edge_types  # fediverse shows up only as username -> site


def test_graph_accepts_confirmed_accounts_and_labels_username_matches() -> None:
    graph = _graph(
        ("account_discovery", _registration()),
        ("browser_account_probe", _reset_probe()),
        ("username_platforms", _sweep("https://reddit.com/alice")),
    )
    assert "GitHub" in _platform_labels(graph)
    username_edges = [l for l in graph["links"] if l["type"] == "username_match"]
    assert username_edges
    for link in graph["links"]:
        assert {"module", "finding_id", "reason"} <= set(link["metadata"]), link
    chain = {l["type"] for l in graph["links"]}
    assert "derived_username" in chain  # email -> username


def test_browser_probe_verification_is_normalised_into_metadata() -> None:
    f = _reset_probe()
    assert f["metadata"]["verification"] == "unverified"


def test_fediverse_source_tag_maps_to_fediverse_in_dedup() -> None:
    from backend.core.platform_dedup import MODULE_SOURCE_TAGS, _normalize_source

    assert MODULE_SOURCE_TAGS["fediverse_webfinger"] == "fediverse"
    finding = {"metadata": {"source": "fediverse_webfinger"}}
    assert _normalize_source(finding, "fediverse_discovery") == ["fediverse"]


def test_graph_data_saves_cluster_confidence() -> None:
    from backend.core.engine import _build_graph

    rows = [
        _registration("GitHub", "github.com"),
        _reset_probe("github.com"),
    ]
    collected = {
        "account_discovery": _res(rows[0]),
        "browser_account_probe": _res(rows[1]),
    }
    evidence.annotate_results(collected, EMAIL)
    data = _build_graph(EMAIL, collected)
    assert data is not None and "cluster_confidence" in data


def test_sweep_reason_reads_plainly_and_fediverse_names_the_tried_username() -> None:
    sweep = _annotate(username_platforms=_res(_sweep()))["username_platforms"].findings[0]
    assert sweep["trace"]["reason"].startswith("The username alice exists on GitHub")
    assert "itself only" not in sweep["trace"]["reason"]  # tried straight from the email
    fedi = {
        "platform": "mastodon:infosec.exchange", "profile_url": "https://infosec.exchange/@alice",
        "username": "alice@infosec.exchange", "confidence": "medium",
        "metadata": {"source": "fediverse_webfinger", "localpart": "alice",
                     "verification": "unverified"},
    }
    got = _annotate(fediverse_discovery=_res(fedi))["fediverse_discovery"].findings[0]
    assert got["trace"]["derived_from"]["value"] == "alice"
    assert "infosec.exchange" in got["trace"]["reason"] and "mastodon:" not in got["trace"]["reason"]


def test_social_links_guesses_carry_no_label_and_breach_nodes_use_the_breach_name() -> None:
    from backend.core.evidence import site_name

    r = _annotate(social_links=_res({"platform": "social_links", "metadata": {"common_variations": ["alice"]}}))
    f = r["social_links"].findings[0]
    assert f["label"] is None and "guesses, not findings" in f["trace"]["reason"]
    deep = {"platform": "DemandScience by Pure Incubation", "url": "https://demandscience.com",
            "metadata": {"breach_name": "DemandScience"}}
    other = {"platform": "demandscience.com", "url": "https://demandscience.com",
             "metadata": {"breach_name": "DemandScience"}}
    assert site_name(deep, "breach_deep") == site_name(other, "breach_deep") == "DemandScience"


def test_flow_ids_are_spelled_in_plain_words() -> None:
    probe = {"platform": "paypal.com", "url": "https://www.paypal.com/signin", "confidence": "medium",
             "verification": "unverified",
             "metadata": {"flow": "email_first", "method": "browser-oracle"}}
    forgot = {"platform": "typeform.com", "url": "https://admin.typeform.com/forgot-password",
              "metadata": {"flow": "forgot_password", "method": "browser-oracle"}}
    odd = {"platform": "x.example", "url": "https://x.example", "metadata": {"flow": "some_new_flow",
           "method": "browser-oracle"}}
    r = _annotate(browser_account_probe=_res(evidence.normalise_verification(probe),
                                             evidence.normalise_verification(forgot),
                                             evidence.normalise_verification(odd)))
    got = [f["trace"] for f in r["browser_account_probe"].findings]
    assert got[0]["reason"] == "PayPal's sign-in page behaves as if this email has an account."
    assert "password-reset page" in got[1]["reason"]
    for trace in got:
        for field in (trace["reason"], trace["signal"]):
            assert not re.search(r"[a-z0-9]+_[a-z0-9_]+", field), field


# ------------------------------------------------------------- browser oracle guards
def test_known_non_leaking_sign_in_oracles_are_disabled() -> None:
    from backend.core.browser_oracle import ORACLES

    off = {o.id for o in ORACLES if o.disabled}
    assert off == {"paypal", "docusign", "gemini", "box", "docker", "vivino", "subscribestar"}
    assert all("any address" in o.disabled for o in ORACLES if o.disabled)


def test_a_hit_the_random_control_also_gets_is_withheld() -> None:
    from backend.core.browser_oracle import apply_control, control_email_for

    assert apply_control("exists", "exists") == "inconclusive"
    assert apply_control("exists", "not_exists") == "exists"
    assert apply_control("exists", "inconclusive") == "exists"
    assert apply_control("not_exists", "exists") == "not_exists"
    a, b = control_email_for("katriel@mailaccess.pro"), control_email_for("katriel@mailaccess.pro")
    assert a != b and a.endswith("@mailaccess.pro") and not a.startswith("katriel")


async def test_browser_probe_module_skips_disabled_oracles_and_reports_withheld(monkeypatch) -> None:
    import backend.core.browser_oracle as bo
    from backend.modules.browser_account_probe import BrowserAccountProbeModule

    seen: list[str] = []

    async def fake_probe_all(email, oracles, *, report=None, **_):
        seen.extend(o.id for o in oracles)
        if report is not None:
            report["withheld"] = ["x.example"]
        return {o.domain: "not_exists" for o in oracles}

    monkeypatch.setattr(bo, "probe_all", fake_probe_all)
    result = await BrowserAccountProbeModule().run("a@b.example")
    assert not {"paypal", "docusign", "gemini", "box", "docker", "vivino", "subscribestar"} & set(seen)
    assert result.metadata["withheld_non_discriminating"] == ["x.example"]
