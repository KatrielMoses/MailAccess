"""One label rule, one trace builder.

``evidence_label(finding)`` is the only place that decides whether a finding is a
``username_match``, ``possible`` or ``confirmed``. The live stream, the saved
finding (``data.label``), the identity-graph filter, ``is_confirmed_account_hit``,
the Defender's Brief and name consensus all call it, so they cannot disagree.

* ``username_match``: the finding exists only because a username was found on a
  site (username sweep, username pivot, Fediverse local-part guess). It says "the
  username X exists on these sites", never counts as an owned account, and never
  corroborates another finding.
* ``possible``: one independent signal tied to the email.
* ``confirmed``: at least two independent signal TYPES tied to the email. Two
  findings of the same type count once, and guesses from the email's local part
  count together as one signal at most.

Every saved finding also gets ``data.trace`` (see :func:`build_trace`): how it was
found, from what, what agrees with it, and a one-sentence reason that matches the
label. Traces never carry keys, tokens or raw responses.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .techniques import technique_for

USERNAME_MATCH = "username_match"
POSSIBLE = "possible"
CONFIRMED = "confirmed"
LABELS = (USERNAME_MATCH, POSSIBLE, CONFIRMED)

# Signal types. Everything that is not USERNAME_MATCH is "tied to the email".
SIG_USERNAME = "username_match"
SIG_REGISTRATION = "email_registration_check"
SIG_SIGNIN_PROBE = "signin_or_reset_probe"
SIG_PUBLIC_RECORD = "public_commit_or_key"
SIG_GRAVATAR = "gravatar"
SIG_BREACH = "breach_record"
SIG_PROVIDER = "provider_account_intel"
SIG_LOCALPART = "localpart_guess"

_SIGNAL_NAMES = {
    SIG_REGISTRATION: "email registration check",
    SIG_SIGNIN_PROBE: "sign-in or reset-flow probe",
    SIG_PUBLIC_RECORD: "public commit or key",
    SIG_GRAVATAR: "Gravatar",
    SIG_BREACH: "breach record",
    SIG_PROVIDER: "provider account check",
    SIG_LOCALPART: "guess from the email's local part",
}

_USERNAME_MODULES = frozenset({"username_platforms", "username_pivot", "fediverse_discovery"})
_USERNAME_SOURCES = frozenset(
    {"username_platforms", "username_pivot", "pivot", "fediverse_webfinger", "fediverse"}
)
_LOCALPART_MODULES = frozenset({"hackernews", "social_links", "permutation_discovery"})
_PUBLIC_RECORD_MODULES = frozenset(
    {
        "github_commits", "github_domain_commits", "github_code_search", "keybase",
        "pgp_keyserver", "pgp_domain_email", "name_to_github_profile",
    }
)
_BREACH_MODULES = frozenset(
    {
        "hibp", "haveibeenpwned", "breachdirectory", "breach_deep", "breach_aggregator",
        "xposedornot", "leakcheck", "intelx_lookup", "hudson_rock", "pastebin_search",
    }
)
_PROVIDER_MODULES = frozenset(
    {
        "google_account_intel", "outlook_autodiscover", "m365_active_intel",
        "m365_passive_intel", "imap_existence", "emailrep",
    }
)
_SOURCE_TO_MODULE = {
    "github_profile": "github_commits",
    "gravatar": "gravatar",
    "keybase": "keybase",
    "account_discovery": "account_discovery",
    "browser-oracle": "browser_account_probe",
}
_SIGNIN_FLOWS = frozenset(
    {"login", "password-recovery", "account-recovery", "forgot", "forgot-password", "reset", "signin"}
)
MAX_REASON = 159


def _meta(finding: dict[str, Any]) -> dict[str, Any]:
    meta = finding.get("metadata")
    return meta if isinstance(meta, dict) else {}


def normalise_verification(finding: dict[str, Any]) -> dict[str, Any]:
    """Mirror a top-level ``verification`` into ``metadata.verification`` (one helper
    for modules that wrote it at the top level only, so no filter misses it)."""
    top = finding.get("verification")
    if isinstance(top, str) and top:
        meta = finding.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
            finding["metadata"] = meta
        meta.setdefault("verification", top)
    return finding


def infer_module(finding: dict[str, Any], module: str | None = None) -> str:
    if module:
        return module
    trace = finding.get("trace")
    if isinstance(trace, dict) and trace.get("module"):
        return str(trace["module"])
    meta = _meta(finding)
    for raw in (finding.get("source"), meta.get("source")):
        if isinstance(raw, str) and raw:
            key = raw.strip().lower()
            if key in _USERNAME_SOURCES:
                return {"pivot": "username_pivot", "fediverse": "fediverse_discovery",
                        "fediverse_webfinger": "fediverse_discovery"}.get(key, key)
            if key in _SOURCE_TO_MODULE:
                return _SOURCE_TO_MODULE[key]
            return key
    if meta.get("method") == "browser-oracle":
        return "browser_account_probe"
    return ""


def signal_type_for(module: str, finding: dict[str, Any] | None = None) -> str:
    """The independent-signal type a finding from ``module`` represents."""
    finding = finding or {}
    meta = _meta(finding)
    if module in _USERNAME_MODULES:
        return SIG_USERNAME
    if module == "account_discovery":
        flow = str(meta.get("flow") or meta.get("method") or "").lower()
        return SIG_SIGNIN_PROBE if flow in _SIGNIN_FLOWS else SIG_REGISTRATION
    if module == "browser_account_probe":
        return SIG_SIGNIN_PROBE
    if module in _LOCALPART_MODULES:
        return SIG_LOCALPART
    if module in _PUBLIC_RECORD_MODULES:
        return SIG_PUBLIC_RECORD
    if module in ("gravatar", "gravatar_lookup"):
        return SIG_GRAVATAR
    if module in _BREACH_MODULES:
        return SIG_BREACH
    if module in _PROVIDER_MODULES:
        return SIG_PROVIDER
    return f"other:{module or 'unknown'}"


def evidence_label(finding: dict[str, Any], module: str | None = None) -> str:
    """``username_match`` | ``possible`` | ``confirmed`` (the single label rule)."""
    if not isinstance(finding, dict):
        return POSSIBLE
    trace = finding.get("trace") if isinstance(finding.get("trace"), dict) else {}
    stype = str(trace.get("signal_type") or "") or signal_type_for(
        infer_module(finding, module), finding
    )
    if stype == SIG_USERNAME:
        return USERNAME_MATCH
    signals = {str(s) for s in (trace.get("signal_types") or []) if s} | {stype}
    signals.discard(SIG_USERNAME)
    if len(signals) >= 2:
        return CONFIRMED
    # Legacy findings with no trace: a corroborated flag from an older dedup pass.
    if not trace and str(_meta(finding).get("verification") or "").lower() == "confirmed":
        return CONFIRMED
    return POSSIBLE


def host_key(finding: dict[str, Any]) -> str:
    """The site a finding is about (registrable-ish host), '' when unknown."""
    from .platform_dedup import dedup_key

    for key in ("profile_url", "url", "response_url"):
        value = finding.get(key)
        if isinstance(value, str) and value.startswith("http"):
            host = dedup_key(value)
            if host:
                return host
    platform = str(finding.get("platform") or "")
    if "." in platform and " " not in platform and ":" not in platform:
        return dedup_key("https://" + platform.lower())
    if platform.startswith("mastodon:"):
        return platform.split(":", 1)[1].lower()
    return ""


# --------------------------------------------------------------------------- naming
# Records we READ directly (DNS, WHOIS, the address check, hosting/infrastructure).
# They are facts about a domain or address, not claims that something belongs to this
# person, so they carry no label (None) and never become accounts in the graph.
NON_IDENTITY_MODULES = frozenset(
    {
        "dns_lookup", "whois_lookup", "domain_intel", "domain_harvester", "subdomain_intel",
        "hackertarget_hosts", "domain_cluster", "email_credibility", "domain_resolution",
        "ip_intel", "shodan", "shodan_internetdb", "ripe_stat_asn", "enterprise_net_intel",
        "netlas_org_surface", "ransomware_intel", "companies_house", "opencorporates",
        "sec_edgar", "technographics",
        "social_links",  # name variations derived from the address: guesses, not findings
    }
)
_NON_IDENTITY_PLATFORMS = frozenset({"infra_cluster", "email_credibility", "domain_resolution"})
_NON_IDENTITY_PREFIXES = ("dns_", "whois", "host:", "host_ip:")

_KNOWN_SITES = {
    "github": "GitHub", "gitlab": "GitLab", "linkedin": "LinkedIn", "youtube": "YouTube",
    "paypal": "PayPal", "stackoverflow": "Stack Overflow", "hackernews": "Hacker News",
    "hackernews_profile": "Hacker News", "news.ycombinator.com": "Hacker News",
    "github_commit": "GitHub", "github_user": "GitHub", "google_account": "Google",
    "twitter": "X (Twitter)", "x": "X (Twitter)", "wordpress": "WordPress", "tiktok": "TikTok",
    "keybase_profile": "Keybase", "gravatar_profile": "Gravatar", "orcid_profile": "ORCID",
    "linkedin_snippet": "LinkedIn", "twitter_profile": "X (Twitter)", "pgp_keyserver": "PGP key servers",
    "docker": "Docker", "dockerhub": "Docker Hub", "sourceforge": "SourceForge",
    "bitbucket": "Bitbucket", "reddit": "Reddit", "facebook": "Facebook",
}
_PROFILE_HOST_MODULES = frozenset(
    {"github_commits", "github_code_search", "gravatar", "gravatar_lookup", "keybase"}
)
_FLOW_WORDS = {
    "login": "sign-in", "email_first": "sign-in", "login_error": "sign-in", "signin": "sign-in",
    "password-recovery": "password-reset", "forgot_password": "password-reset",
    "forgot-password": "password-reset", "forgot": "password-reset", "reset": "password-reset",
    "account-recovery": "account-recovery", "signup-validation": "sign-up",
    "register": "sign-up", "signup": "sign-up",
}


def is_identity_claim(module: str, finding: dict[str, Any]) -> bool:
    """False for records read directly (DNS, WHOIS, email checks, hosts, infrastructure)."""
    if module in NON_IDENTITY_MODULES:
        return False
    platform = str(finding.get("platform") or "").lower() if isinstance(finding, dict) else ""
    if platform in _NON_IDENTITY_PLATFORMS or platform.startswith(_NON_IDENTITY_PREFIXES):
        return False
    return True


def _pretty_domain(host: str) -> str:
    host = host.lower().removeprefix("www.")
    if host in _KNOWN_SITES:
        return _KNOWN_SITES[host]
    first = host.split(".")[0]
    return _KNOWN_SITES.get(first) or first.replace("-", " ").title()


def site_name(finding: dict[str, Any], module: str = "") -> str:
    """A human site name ("GitHub", "Duolingo"): never an internal title like github_commit."""
    raw = str(finding.get("platform") or "").strip()
    if module in _BREACH_MODULES:
        named = _first(_meta(finding).get("breach_name"), _meta(finding).get("name"))
        if named:
            return named[:60]
    if raw.startswith("mastodon:"):
        return raw.split(":", 1)[1][:60]
    if module in _PROFILE_HOST_MODULES or not raw:
        host = host_key(finding)
        if host:
            return _pretty_domain(host)
    if raw.lower() in _KNOWN_SITES:
        return _KNOWN_SITES[raw.lower()]
    if "_" in raw and " " not in raw:
        return raw.replace("_", " ").title()[:60]
    if "." in raw and " " not in raw:
        return _pretty_domain(raw)
    if raw and raw == raw.lower() and " " not in raw:
        return raw.title()[:60]
    return (raw or "this site")[:60]


def _site(finding: dict[str, Any], module: str = "") -> str:
    return site_name(finding, module)


def _username(finding: dict[str, Any]) -> str:
    meta = _meta(finding)
    return str(
        meta.get("localpart")  # Fediverse: "alice@server" -> the name that was tried
        or finding.get("username") or meta.get("matched_username") or meta.get("username") or ""
    )[:60]


def _words(module: str) -> str:
    return module.replace("_", " ") or "source"


def _flow(meta: dict[str, Any]) -> str:
    flow = str(meta.get("flow") or "").lower()
    # Never show an internal flow id: unknown ids are spelled out in plain words.
    return _FLOW_WORDS.get(flow) or flow.replace("_", " ").replace("-", " ") or "sign-in"


def _first(*values: Any) -> str:
    for v in values:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def read_sentence(module: str, finding: dict[str, Any]) -> str:
    """What a directly-read record says, in plain words (non-identity findings)."""
    meta = _meta(finding)
    platform = str(finding.get("platform") or "")
    if platform == "dns_mx" or (module == "dns_lookup" and meta.get("mx_records")):
        provider = _first(meta.get("mx_provider"))
        if not provider:
            recs = meta.get("mx_records")
            if isinstance(recs, list) and recs and isinstance(recs[0], dict):
                provider = _first(recs[0].get("exchange"))
        return f"The domain's mail is handled by {provider or 'its mail servers'} (MX record)."
    if platform == "dns_spf":
        return (
            "The domain publishes an SPF record listing who may send its mail."
            if meta.get("has_spf") else "The domain has no SPF record."
        )
    if platform == "dns_dmarc":
        policy = _first(meta.get("dmarc_policy"))
        return (
            f"The domain publishes a DMARC policy ({policy or 'set'}) for forged mail."
            if meta.get("has_dmarc") else "The domain has no DMARC policy."
        )
    if platform == "dns_a":
        return f"The domain's web address points to the IP {_first(meta.get('ip_address')) or 'shown'} (A record)."
    if platform == "dns_ns":
        ns = meta.get("nameservers")
        names = ", ".join(str(n) for n in ns[:2]) if isinstance(ns, list) and ns else "its name servers"
        return f"The domain's DNS is run by {names}."
    if module == "dns_lookup":
        return "A DNS record for the domain was read."
    if module == "whois_lookup":
        if "phone" in platform:
            return "WHOIS lists a contact phone for the domain's registration."
        registrar = _first(meta.get("registrar"), finding.get("registrar"))
        return (
            f"WHOIS lists the domain's registrar as {registrar}."
            if registrar else "The domain's WHOIS registration record was read."
        )
    if module == "domain_intel":
        return (
            "The domain's website was fetched and its details read."
            if platform == "website" else "The domain's DNS security settings were read."
        )
    if module in ("domain_harvester", "subdomain_intel", "hackertarget_hosts"):
        host = platform.split(":", 1)[1] if ":" in platform else _first(meta.get("host"))
        if platform.startswith("host_ip:"):
            ip = _first(meta.get("ip"), meta.get("ip_address"))
            return f"The host {host} resolves to {ip}." if ip else f"The host {host} resolves to an IP address."
        return f"The host {host} exists under this domain." if host else "A host under this domain was found."
    if module == "email_credibility":
        if meta.get("is_disposable"):
            return "The address comes from a disposable email provider."
        aliases = meta.get("aliases_detected")
        if meta.get("is_alias") and isinstance(aliases, list) and aliases:
            return f"This address has {len(aliases)} equivalent spellings that reach the same inbox."
        return "The address is well-formed and does not come from a disposable provider."
    if module == "social_links":
        return claim_sentence(module, finding, "")
    if platform == "infra_cluster" or module == "domain_cluster":
        registrar = _first(meta.get("shared_registrar"))
        return (
            f"Sites found for this email share a registrar ({registrar}) and network range."
            if registrar else "Sites found for this email share hosting infrastructure."
        )
    return f"The {_words(module)} check read a record about this domain."


def claim_sentence(module: str, finding: dict[str, Any], stype: str) -> str:
    """The identity claim a single check makes, naming the real site or record."""
    meta = _meta(finding)
    site = site_name(finding, module)
    if module == "account_discovery":
        if stype == SIG_SIGNIN_PROBE:
            return f"{site}'s {_flow(meta)} step recognises this email."
        return f"{site}'s sign-up form says an account already uses this email."
    if module == "browser_account_probe":
        return f"{site}'s {_flow(meta)} page behaves as if this email has an account."
    if module in ("github_commits", "github_domain_commits"):
        if str(finding.get("platform")) == "github_commit" or meta.get("commit_sha"):
            repo = _first(meta.get("repo"))
            return f"A public commit on GitHub lists this email as its author{f' (repo {repo})' if repo else ''}."
        login = _first(meta.get("login"))
        return f"A GitHub profile{f' ({login})' if login else ''} is tied to this email."
    if module == "github_code_search":
        return "Public code on GitHub contains this email."
    if module == "keybase":
        return "A Keybase profile is tied to this email."
    if module in ("gravatar", "gravatar_lookup"):
        return "Gravatar has a public profile for this email."
    if module in ("pgp_keyserver", "pgp_domain_email"):
        return "A public PGP key lists this email."
    if module == "google_account_intel":
        if meta.get("gaia_id") or meta.get("profile_name") or meta.get("display_name"):
            return "Google has a public profile for this email."
        return "This is a Google (Gmail) address; that is judged from its mail domain, not an account lookup."
    if module == "hackernews":
        user = _first(meta.get("username"), finding.get("username"))
        return (
            f"Hacker News has a user named {user}, a guess from the email's local part; "
            "nothing tied to the email agrees yet."
        )
    if module == "social_links":
        names = meta.get("common_variations")
        guess = f" (such as {names[0]})" if isinstance(names, list) and names else ""
        return f"Likely usernames{guess} were derived from the email's local part; they are guesses, not findings."
    if module == "social":
        if "reset" in str(meta.get("note") or "").lower():
            return f"{site}'s password-reset flow recognises this email."
        return f"A check of social sites found an account on {site} for this email."
    if stype == SIG_BREACH:
        name = _first(meta.get("breach_name"), meta.get("name"))
        if module == "breach_deep":
            return f"A check of breached sites found an account for this email on {name or site}."
        return f"A breach list{f' ({name})' if name else ''} includes this email."
    if module == "pastebin_search":
        return "A public paste mentions this email."
    if module == "wayback":
        domain = _first(meta.get("original_domain"))
        when = _first(meta.get("archive_date"))
        return (
            f"An archived copy of {domain or 'a web page'}{f' from {when}' if when else ''} "
            "mentions this email."
        )
    if module == "hudson_rock":
        return "Infostealer malware logs list this email."
    if module in ("commoncrawl_email", "google_dork", "email_search_dork", "code_and_cert_email",
                  "wayback_domain_harvest"):
        return "A public web page or record mentions this email."
    if stype == SIG_LOCALPART:
        return f"A profile on {site} was guessed from the email's local part."
    words = _words(module)
    site_key = re.sub(r"[^a-z0-9]", "", site.lower())
    mod_key = module.replace("_", "")
    if not site_key or site_key in mod_key or mod_key in site_key:
        return f"The {words} check found a result for this email."
    return f"The {words} check found {site} for this email."


def _signal_sentence(module: str, finding: dict[str, Any], stype: str) -> str:
    """What was actually observed, in plain words. Never raw responses or keys."""
    meta = _meta(finding)
    site = site_name(finding, module)
    if not is_identity_claim(module, finding):
        return read_sentence(module, finding)
    if module == "username_platforms":
        check = str(meta.get("check_type") or "status_code").replace("_", " ")
        return f"{site} has a profile page for that username (detected by a {check} check)."
    if module == "username_pivot":
        return f"{site} has a profile page for that username."
    if module == "fediverse_discovery":
        return f"{site} answered a WebFinger lookup for that username."
    if module == "account_discovery":
        if stype == SIG_SIGNIN_PROBE:
            return f"{site}'s {_flow(meta)} step recognised this email."
        return "The sign-up form said this email is already in use."
    if module == "browser_account_probe":
        return f"{site}'s {_flow(meta)} page behaved as if this email has an account."
    return claim_sentence(module, finding, stype)


def _types_phrase(types: list[str]) -> str:
    names = [_SIGNAL_NAMES.get(t, t.replace("other:", "").replace("_", " ")) for t in types]
    return " and ".join(names) if len(names) <= 2 else ", ".join(names[:-1]) + " and " + names[-1]


def build_reason(
    finding: dict[str, Any],
    label: str | None,
    *,
    module: str = "",
    signal_type: str,
    signal_types: list[str],
    derived_from: dict[str, Any],
) -> str:
    """One sentence, under 160 characters, that agrees with ``label`` and names real things."""
    site = site_name(finding, module)
    if label is None:
        text = read_sentence(module, finding)
    elif label == USERNAME_MATCH:
        user = derived_from.get("value") or _username(finding) or "that username"
        origin = derived_from.get("origin_module")
        if origin and origin != "email_local_part" and derived_from.get("only_username_match"):
            text = (
                f"The username {user} (itself only a username match) exists on {site}; "
                "this does not show an owned account."
            )
        else:
            text = (
                f"The username {user} exists on {site}; that only shows the name is taken, "
                "not that this person owns it."
            )
    elif label == CONFIRMED:
        text = (
            f"{len(signal_types)} separate checks agree an account on {site} uses this email "
            f"({_types_phrase(signal_types)})."
        )
    else:
        text = claim_sentence(module, finding, signal_type)
    return text[:MAX_REASON]


def derive_from(
    module: str, finding: dict[str, Any], email: str, stype: str
) -> dict[str, Any]:
    meta = _meta(finding)
    if stype == SIG_USERNAME:
        derived: dict[str, Any] = {
            "type": "username",
            "value": _username(finding),
            "finding_id": meta.get("derived_from_finding"),
        }
        if module == "username_pivot":
            derived["origin_module"] = meta.get("derived_from_module") or "email"
            derived["only_username_match"] = bool(meta.get("derived_from_username_match"))
        else:
            # Sweep and Fediverse try variants of the email's local part directly.
            derived["origin_module"] = "email_local_part"
            derived["only_username_match"] = False
        return derived
    return {"type": "email", "value": email, "finding_id": None}


def build_trace(module: str, finding: dict[str, Any], email: str) -> dict[str, Any]:
    """Create (or refresh) ``finding['trace']`` and ``finding['label']`` in place."""
    normalise_verification(finding)
    tech_id, tech_line = technique_for(module)
    stype = signal_type_for(module, finding)
    old = finding.get("trace") if isinstance(finding.get("trace"), dict) else {}
    trace = {
        "module": module,
        "technique_id": tech_id,
        "technique": tech_line,
        "signal_type": stype,
        "signal": old.get("signal") or _signal_sentence(module, finding, stype),
        "derived_from": derive_from(module, finding, email, stype),
        "corroborated_by": old.get("corroborated_by") or [],
        "signal_types": old.get("signal_types") or (
            [] if stype == SIG_USERNAME or not is_identity_claim(module, finding) else [stype]
        ),
        "independent_signals": 0,
        "reason": "",
    }
    finding["trace"] = trace
    refresh_label(finding, module)
    return trace


def refresh_label(finding: dict[str, Any], module: str | None = None) -> str | None:
    """Recompute label, independent_signals and reason from the trace so far.

    Records read directly (DNS, WHOIS, the address check...) get ``label = None``:
    they are not claims that something belongs to this person."""
    trace = finding.get("trace")
    if not isinstance(trace, dict):
        return POSSIBLE
    mod = str(trace.get("module") or module or "")
    if not is_identity_claim(mod, finding):
        trace["signal_types"] = []
        trace["independent_signals"] = 0
        trace["reason"] = build_reason(
            finding, None, module=mod, signal_type="", signal_types=[], derived_from={}
        )
        finding["label"] = None
        return None
    label = evidence_label(finding, module)
    stype = str(trace.get("signal_type") or "")
    types = [t for t in (trace.get("signal_types") or []) if t != SIG_USERNAME]
    if stype and stype != SIG_USERNAME and stype not in types:
        types.insert(0, stype)
    trace["signal_types"] = types
    trace["independent_signals"] = 0 if label == USERNAME_MATCH else len(types)
    trace["reason"] = build_reason(
        finding, label, module=mod, signal_type=stype, signal_types=types,
        derived_from=trace.get("derived_from") or {},
    )
    finding["label"] = label
    meta = finding.get("metadata")
    if label == CONFIRMED and isinstance(meta, dict) and stype != SIG_USERNAME:
        meta["verification"] = "confirmed"
        meta["speculative"] = False
    if mod == "account_discovery":
        # Confidence follows the label, never "high" while unverified.
        finding["confidence"] = "high" if label == CONFIRMED else "medium"
    return label


def corroborate(results: dict[str, Any]) -> None:
    """Link findings about the same site that came from different signal types.

    ``results`` maps module name -> ModuleResult (anything with ``.findings``).
    Username matches never corroborate and are never corroborated.
    """
    by_site: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for module, result in results.items():
        for finding in getattr(result, "findings", None) or []:
            if not isinstance(finding, dict) or not isinstance(finding.get("trace"), dict):
                continue
            if finding["trace"].get("signal_type") == SIG_USERNAME:
                continue
            if not is_identity_claim(module, finding):
                continue
            site = host_key(finding)
            if site:
                by_site.setdefault(site, []).append((module, finding))
    for rows in by_site.values():
        for module, finding in rows:
            trace = finding["trace"]
            own = trace.get("signal_type")
            others = [
                (m, f) for m, f in rows
                if f is not finding and f["trace"].get("signal_type") != own
            ]
            corroborators = []
            types = {own}
            seen: set[str] = set()
            for m, f in others:
                t = f["trace"].get("signal_type")
                types.add(t)
                if t in seen:
                    continue
                seen.add(t)
                corroborators.append(
                    {
                        "module": m,
                        "finding_id": f.get("finding_id"),
                        "signal": f["trace"].get("signal", "")[:160],
                    }
                )
            trace["corroborated_by"] = corroborators
            trace["signal_types"] = sorted(t for t in types if t)
            refresh_label(finding, module)


def annotate_results(results: dict[str, Any], email: str) -> None:
    """Give every finding a trace + label, then link corroborating findings."""
    for module, result in results.items():
        for finding in getattr(result, "findings", None) or []:
            if isinstance(finding, dict) and not isinstance(finding.get("trace"), dict):
                build_trace(module, finding, email)
    corroborate(results)


_TITLES = {
    "dns_mx": "Mail servers (MX)", "dns_spf": "SPF record", "dns_dmarc": "DMARC policy",
    "dns_a": "Web address (A record)", "dns_ns": "Name servers", "whois": "WHOIS registration",
    "whois_phone": "WHOIS phone", "email_credibility": "Address check",
    "infra_cluster": "Shared infrastructure", "website": "Website", "dns": "DNS settings",
}
_EMAIL_MODULES = frozenset({"alternate_email", "email_discovery", "permutation_discovery"})
_NAME_PLATFORMS = frozenset({"linkedin_snippet", "orcid_profile", "pgp_keyserver"})
IDENTITY_KINDS = ("account", "username_match", "name", "domain", "breach", "email", "phone", "other")


def finding_title(module: str, finding: dict[str, Any]) -> str:
    platform = str(finding.get("platform") or "")
    if platform in _TITLES:
        return _TITLES[platform]
    if platform.startswith("host_ip:"):
        return f"Host IP ({platform.split(':', 1)[1]})"[:80]
    if platform.startswith("host:"):
        return f"Host ({platform.split(':', 1)[1]})"[:80]
    return site_name(finding, module)[:80]


def kind_for(module: str, finding: dict[str, Any], label: str | None) -> str:
    """One of ``IDENTITY_KINDS`` (the event contract's ``kind`` set)."""
    meta = _meta(finding)
    platform = str(finding.get("platform") or "").lower()
    if label is None:
        if module == "email_credibility":
            return "email"
        if module in ("dns_lookup", "whois_lookup", "domain_intel", "domain_harvester",
                      "subdomain_intel", "hackertarget_hosts", "domain_cluster",
                      "companies_house", "opencorporates"):
            return "domain"
        if module == "social_links":
            return "other"
        return "other"
    if label == USERNAME_MATCH:
        return "username_match"
    stype = signal_type_for(module, finding)
    if stype == SIG_BREACH:
        return "breach"
    if "phone" in platform or module in ("phone_intel", "messaging_hints"):
        return "phone"
    if platform in _NAME_PLATFORMS:
        return "name"
    if module in _EMAIL_MODULES or meta.get("discovered_email"):
        return "email"
    if module == "social_links":
        return "other"
    if stype in (SIG_REGISTRATION, SIG_SIGNIN_PROBE, SIG_PROVIDER, SIG_GRAVATAR,
                 SIG_PUBLIC_RECORD, SIG_LOCALPART) or module in ("social", "hackernews"):
        return "account"
    return "other"


def finding_url(finding: dict[str, Any]) -> str | None:
    for key in ("profile_url", "url"):
        v = finding.get(key)
        if isinstance(v, str) and v.startswith("http"):
            return v[:300]
    return None


def site_of_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
