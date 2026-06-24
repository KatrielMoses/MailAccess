from __future__ import annotations

_INFOSTEALER_MODULES = frozenset({"hudson_rock"})
_BREACH_MODULES = frozenset(
    {"hibp", "breachdirectory", "breach_deep", "xposedornot", "intelx_lookup"}
)
_USERNAME_ENUM_MODULES = frozenset(
    {
        "sherlock_platforms",
        "maigret_platforms",
        "blackbird_platforms",
        "nexfil_platforms",
        "whatsmyname",
        "github_code_search",
        "pastebin_search",
        "fediverse_discovery",
        "gravatar_lookup",
        "account_discovery",
        "user_scanner",
        "username_pivot",
    }
)
_DOMAIN_INTEL_MODULES = frozenset(
    {"domain_harvester", "domain_intel", "whois_lookup", "dns_lookup", "shodan"}
)
_SOCIAL_MODULES = frozenset(
    {
        "gravatar",
        "social_links",
        "google_search",
        "ghunt",
        "social",
        "twitter_profile",
        "linkedin_serp",
        "marketplace_profile",
        "email_discovery",
    }
)
_POST_PRIMARY_ONLY = frozenset(
    {
        "username_pivot",
        "phone_intel",
        "email_discovery",
        "alternate_email",
        "twitter_profile",
        "linkedin_serp",
        "marketplace_profile",
        "domain_cluster",
    }
)

_WEIGHT_INFOSTEALER = 20
_WEIGHT_BREACH = 15
_WEIGHT_SOCIAL = 5
_WEIGHT_META = 2

_MODULE_WEIGHT_OVERRIDES: dict[str, int] = {
    "breach_deep": 18,
    "domain_harvester": 5,
    "domain_intel": 5,
    "whois_lookup": 5,
    "dns_lookup": 5,
    "shodan": 5,
}
_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "high": 1.0,
    "medium": 0.5,
    "low": 0.2,
    "none": 0.0,
}
_MODULE_CAP: dict[str, int] = {
    "whatsmyname": 20,
    "maigret_platforms": 25,
    "sherlock_platforms": 30,
    "nexfil_platforms": 25,
    "blackbird_platforms": 30,
    "account_discovery": 15,
    "user_scanner": 15,
    "username_pivot": 10,
    "email_discovery": 10,
    "social": 10,
    "github_code_search": 10,
    "pastebin_search": 8,
    "gravatar_lookup": 5,
    "fediverse_discovery": 15,
    "domain_harvester": 25,
    "social_links": 5,
    "hudson_rock": 40,
    "breach_deep": 50,
    "hibp": 45,
    "breachdirectory": 40,
    "xposedornot": 45,
    "intelx_lookup": 50,
}
_MODULE_DEFAULT_TIMEOUTS: dict[str, int] = {
    "breach_deep": 90,
    "github_commits": 90,
}
_MODULE_TIMEOUT_FLOORS: dict[str, int] = {
    "account_discovery": 120,
    "username_pivot": 120,
    "user_scanner": 180,
    "whatsmyname": 200,
    "maigret_platforms": 180,
    "sherlock_platforms": 180,
}
_OPT_IN_FLAG_BY_MODULE: dict[str, str] = {
    "breach_deep": "enable_breach_deep",
    "ghunt": "enable_ghunt",
    "email_discovery": "enable_email_discovery",
    "press_intel": "enable_press_intel",
    "maigret_platforms": "enable_maigret_platforms",
}


def module_weight(module_name: str) -> int:
    if module_name in _MODULE_WEIGHT_OVERRIDES:
        return _MODULE_WEIGHT_OVERRIDES[module_name]
    if module_name in _INFOSTEALER_MODULES:
        return _WEIGHT_INFOSTEALER
    if module_name in _BREACH_MODULES:
        return _WEIGHT_BREACH
    if module_name in _USERNAME_ENUM_MODULES:
        return _WEIGHT_SOCIAL
    if module_name in _SOCIAL_MODULES:
        return _WEIGHT_SOCIAL
    if module_name in _DOMAIN_INTEL_MODULES:
        return _WEIGHT_META
    return _WEIGHT_META
