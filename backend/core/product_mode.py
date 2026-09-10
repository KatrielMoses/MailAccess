"""Phase 2B — product-mode separation (the governance keystone).

A first-class *product mode* selects, for a run, a **module allowlist**, a
**retention policy**, and an **export schema**. It is the single control that
lets one engine be both an aggressive security-investigation tool *and* a lawful
public-business-contact (lead-gen) tool without the two capability sets bleeding
into each other.

Three modes:

- ``security-investigation`` — today's full capability (the default). Every
  registered module may run; this is a straight rename of existing behavior and
  must show zero regression.
- ``public-business-contact`` — lead-gen. Only lawfully-published business
  contact sources and authorized user-supplied data; breach/credential sources,
  account-reset probing, personal-email pivots, private-profile inference and
  active mailbox probing for growth are **not** a lawful basis for cold B2B
  outreach and are blocked.
- ``org-authorized-verification`` — verification of contacts on a domain the
  operator is authorized over. Permits active verification against that domain
  (the mode selection *is* the operator's attestation) but still blocks
  breach/credential sources and personal pivots.

This module is *classification + framework* only. The dispatch gate that
actually denies a module (2C), the suppression store (2A), and the eligibility
verdict (2D) consume this classification; they are not implemented here.

**Fail closed:** an *unclassified* module is denied in the two non-security
modes. The classification is kept exhaustive (see ``_ALL_KNOWN_MODULES`` and the
policy test suite), so the fail-closed default is a safety net, not the norm.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass
from enum import Enum

from .policy import (
    _BREACH_MODULES,
    _INFOSTEALER_MODULES,
    _USERNAME_ENUM_MODULES,
)


class ProductMode(str, Enum):
    """The run's governance mode. ``str`` mixin so the value serializes plainly
    (into config, request bodies, DB columns, exports)."""

    SECURITY_INVESTIGATION = "security-investigation"
    PUBLIC_BUSINESS_CONTACT = "public-business-contact"
    ORG_AUTHORIZED_VERIFICATION = "org-authorized-verification"


DEFAULT_MODE = ProductMode.SECURITY_INVESTIGATION

# Public string values, for config validators / CLI help / API validation.
MODE_VALUES: tuple[str, ...] = tuple(m.value for m in ProductMode)


def normalize_mode(value: str | ProductMode | None) -> ProductMode:
    """Resolve a mode from config/CLI/API to a :class:`ProductMode`.

    ``None`` → the default (security-investigation). An **invalid** mode string
    raises ``ValueError`` — a bad mode is a hard error, never a silent fallback
    to a more-permissive default.
    """
    if value is None:
        return DEFAULT_MODE
    if isinstance(value, ProductMode):
        return value
    try:
        return ProductMode(str(value).strip())
    except ValueError as exc:
        raise ValueError(
            f"unknown product mode {value!r}; expected one of {MODE_VALUES}"
        ) from exc


# ---------------------------------------------------------------------------
# Module classification.
#
# Seeded from the existing ``backend/core/policy.py`` sensitivity buckets rather
# than inventing a parallel taxonomy. Each blocked-bucket names *why* a module is
# unlawful/unsafe for cold outreach so the rationale is auditable.
# ---------------------------------------------------------------------------

# Breach / credential / infostealer sources — Doc-1 #6/#10: not a lawful basis
# for cold B2B outreach.
_CREDENTIAL_BLOCKED = (
    _BREACH_MODULES
    | _INFOSTEALER_MODULES
    | frozenset({"leakcheck", "ransomware_intel", "xposed_or_not"})
)

# Personal-email pivots — deriving a person's *personal* address / cross-account
# identity, not a published business contact.
_PERSONAL_PIVOT_BLOCKED = frozenset(
    {
        "alternate_email",
        "username_pivot",
        "person_email_pivot",
        "persona_email_pivot",
        "email_discovery",
        "email_identity_enrichment",
        # Phase 7B — People Data Labs is an aggregated/data-broker source, not a
        # published business contact; gated to security-investigation only.
        "pdl",
    }
)

# Private-profile inference / username enumeration across platforms — profiling a
# person, not identifying a business contact.
_PROFILE_INFERENCE_BLOCKED = _USERNAME_ENUM_MODULES | frozenset(
    {
        "gravatar",
        "keybase",
        "google_account_intel",
        "social",
        "social_links",
        "twitter_profile",
        "marketplace_profile",
        "phone_intel",
        "messaging_hints",
        "hackernews",
        "name_to_github_profile",
        "github_commits",
    }
)

# Infrastructure recon — a security behavior, not a contact source.
_INFRA_RECON_BLOCKED = frozenset(
    {"shodan", "shodan_internetdb", "ripe_stat_asn", "enterprise_net_intel"}
)

# Public-only blocks — the FTC candidate-generation-vs-dictionary-attack line
# (Doc-1 #6). Blocked for cold-outreach lead-gen but permitted in
# org-authorized-verification against the operator's *own* domain:
#   - outlook_autodiscover: active mailbox probing for growth;
#   - permutation_discovery: un-evidenced dictionary-style address permutation
#     (evidenced pattern generation via pattern_and_verify stays allowed).
_ACTIVE_PROBE_PUBLIC_ONLY = frozenset({"outlook_autodiscover"})
_UNEVIDENCED_GENERATION_PUBLIC_ONLY = frozenset({"permutation_discovery"})
_PUBLIC_ONLY_BLOCKED = _ACTIVE_PROBE_PUBLIC_ONLY | _UNEVIDENCED_GENERATION_PUBLIC_ONLY

# What the two non-security modes block.
_PUBLIC_BLOCKED = (
    _CREDENTIAL_BLOCKED
    | _PERSONAL_PIVOT_BLOCKED
    | _PROFILE_INFERENCE_BLOCKED
    | _INFRA_RECON_BLOCKED
    | _PUBLIC_ONLY_BLOCKED
)
# org-authorized-verification is public-business-contact plus the public-only
# blocks lifted (active verification + permutation against the authorized domain).
_ORG_BLOCKED = _PUBLIC_BLOCKED - _PUBLIC_ONLY_BLOCKED

# The exhaustive universe of canonical module names across BOTH pipelines
# (investigate auto-discovery registry + harvest factory registry). Kept
# authoritative here; the policy test asserts it stays in sync with the live
# registries so a new module cannot silently rely on the fail-closed default.
_ALL_KNOWN_MODULES: frozenset[str] = frozenset(
    {
        # --- investigate registry (get_all_modules) ---
        "account_discovery",
        "alternate_email",
        "breach_aggregator",
        "breach_deep",
        "breachdirectory",
        "code_and_cert_email",
        "commoncrawl_email",
        "companies_house",
        "dns_lookup",
        "domain_cluster",
        "domain_harvester",
        "domain_intel",
        "email_credibility",
        "email_discovery",
        "email_identity_enrichment",
        "email_search_dork",
        "emailrep",
        "employee_name_discovery",
        "fediverse_discovery",
        "google_account_intel",
        "github_code_search",
        "github_commits",
        "github_domain_commits",
        "github_org_members",
        "google_dork",
        "gravatar",
        "gravatar_lookup",
        "hackernews",
        "hackertarget_hosts",
        "hibp",
        "hudson_rock",
        "hunter_io",
        "intelx_lookup",
        "keybase",
        "leakcheck",
        "linkedin_serp",
        "username_platforms",
        "marketplace_profile",
        "messaging_hints",
        "name_to_github_profile",
        "npm_discovery",
        "npm_email",
        "opencorporates",
        "orcid_lookup",
        "outlook_autodiscover",
        "package_ecosystems",
        "pastebin_search",
        "pattern_and_verify",
        "permutation_discovery",
        "person_email_pivot",
        "persona_email_pivot",
        "pgp_domain_email",
        "pgp_keyserver",
        "phone_intel",
        "press_intel",
        "public_forge",
        "public_surface_sweeper",
        "pypi_discovery",
        "pypi_email",
        "ransomware_intel",
        "ripe_stat_asn",
        "sec_edgar",
        "security_txt",
        "shodan",
        "shodan_internetdb",
        "social",
        "social_links",
        "subdomain_intel",
        "syndication_feed_sweeper",
        "twitter_profile",
        "username_pivot",
        "wayback",
        "wayback_domain_harvest",
        "whois_lookup",
        "wordpress_rest",
        "xposedornot",
        # --- harvest-only additions (factory registry + tail) ---
        "hunter",
        "xposed_or_not",
        "enterprise_net_intel",
        # --- Phase 5C: company discovery (segment -> domain list) ---
        # A top-of-funnel entry point, not a pipeline module, but classified here
        # so the lawful gate governs it. Uses only lawful-public sources (search
        # dorking, OpenCorporates free tier, Common Crawl host index) — not in
        # any blocked bucket, so it is allowed in every mode.
        "company_discovery",
        # --- Phase 7A/7B: enrichment waterfall connectors ---
        # ``apollo`` returns lawful-public business contact data → in no blocked
        # bucket → allowed in every mode. ``pdl`` is data-broker/personal → in
        # ``_PERSONAL_PIVOT_BLOCKED`` → security-investigation only.
        "apollo",
        "pdl",
    }
)


def allowed_modes(module_name: str) -> frozenset[ProductMode]:
    """The set of modes a module may run in.

    Every module runs in security-investigation. The two non-security modes are
    an allowlist derived by subtracting the blocked buckets. An **unknown**
    module (not in :data:`_ALL_KNOWN_MODULES`) is fail-closed to security only.
    """
    modes = {ProductMode.SECURITY_INVESTIGATION}
    if module_name not in _ALL_KNOWN_MODULES:
        return frozenset(modes)
    if module_name not in _PUBLIC_BLOCKED:
        modes.add(ProductMode.PUBLIC_BUSINESS_CONTACT)
    if module_name not in _ORG_BLOCKED:
        modes.add(ProductMode.ORG_AUTHORIZED_VERIFICATION)
    return frozenset(modes)


def is_module_allowed(module_name: str, mode: str | ProductMode) -> bool:
    """Whether ``module_name`` may run in ``mode`` (fail-closed for unknowns)."""
    return normalize_mode(mode) in allowed_modes(module_name)


# ---------------------------------------------------------------------------
# Active-mode context — a task-local marker of the mode the current run is
# executing under. Lets defense-in-depth guards deep in the call graph (e.g.
# reset_prober) refuse to run outside security-investigation, independent of the
# module-dispatch gate. contextvars are copied per asyncio task, so setting this
# inside a module task does not leak to siblings.
# ---------------------------------------------------------------------------

_ACTIVE_MODE: contextvars.ContextVar[str] = contextvars.ContextVar(
    "mailaccess_active_mode", default=DEFAULT_MODE.value
)


def set_active_mode(mode: str | ProductMode) -> contextvars.Token:
    """Set the current task's active mode; returns a token for optional reset."""
    return _ACTIVE_MODE.set(normalize_mode(mode).value)


def get_active_mode() -> ProductMode:
    return normalize_mode(_ACTIVE_MODE.get())


def is_security_mode() -> bool:
    return get_active_mode() is ProductMode.SECURITY_INVESTIGATION


def mode_module_allowlist(mode: str | ProductMode) -> frozenset[str]:
    """The set of known module names permitted in ``mode``.

    Used by the harvest side (2C) to translate a mode into ``skip_modules``:
    ``skip = all_scheduled - mode_module_allowlist(mode)``.
    """
    m = normalize_mode(mode)
    return frozenset(name for name in _ALL_KNOWN_MODULES if m in allowed_modes(name))


def blocked_modules(mode: str | ProductMode) -> frozenset[str]:
    """The set of known module names *denied* in ``mode`` — the complement of the
    allowlist. Unioned into the harvest ``skip_modules`` to enforce the gate.
    Empty for security-investigation (zero regression)."""
    return _ALL_KNOWN_MODULES - mode_module_allowlist(mode)


# ---------------------------------------------------------------------------
# The candidate-generation vs. dictionary-attack boundary (Doc-1 #6, FTC line).
#
# The non-negotiable principle: generating a candidate address from an
# *independently evidenced person* + an observed/corpus email pattern is
# permitted; un-evidenced dictionary permutation and active mailbox probing *for
# growth* are not a lawful basis for cold outreach and are blocked in
# public-business-contact. The mechanism:
#   - un-evidenced permutation is a module-classification block
#     (``permutation_discovery`` is public-only-blocked);
#   - active mailbox probing is blocked by disabling active SMTP verification in
#     public mode (see ``active_mailbox_probing_allowed``);
#   - an emitted *generated* candidate must clear ``is_evidenced_candidate`` in
#     public mode — it must trace to a real, independently-observed person.
# ---------------------------------------------------------------------------

# Evidence keys that establish an independently-observed real person behind a
# generated candidate (as opposed to a blind permutation).
_PERSON_EVIDENCE_KEYS = (
    "person_name",
    "full_name",
    "name",
    "display_name",
    "first_name",
    "last_name",
    "first",
    "last",
    "linkedin_url",
    "employee_source",
)


def active_mailbox_probing_allowed(mode: str | ProductMode) -> bool:
    """Whether active mailbox probing (SMTP RCPT / provider existence) for growth
    is permitted. Security and org-authorized (own domain) yes; public-business-
    contact no."""
    return normalize_mode(mode) is not ProductMode.PUBLIC_BUSINESS_CONTACT


def is_evidenced_candidate(evidence: object, mode: str | ProductMode) -> bool:
    """Whether a *generated* candidate address may be emitted under ``mode``.

    Outside public-business-contact, generation is unrestricted (the mode's own
    gate governs it). In public mode, a generated candidate must trace to an
    independently-evidenced person (a name/LinkedIn/employee source) — un-
    evidenced permutations are dropped.
    """
    if normalize_mode(mode) is not ProductMode.PUBLIC_BUSINESS_CONTACT:
        return True
    if isinstance(evidence, dict):
        return any(evidence.get(key) for key in _PERSON_EVIDENCE_KEYS)
    return False


# Introspection view: {module_name: {modes}} over the known universe. Handy for
# tests and for surfacing the classification in docs/exports.
MODULE_MODE_POLICY: dict[str, frozenset[ProductMode]] = {
    name: allowed_modes(name) for name in sorted(_ALL_KNOWN_MODULES)
}


# ---------------------------------------------------------------------------
# Retention-policy + export-schema hooks.
#
# 2B only establishes that *mode selects these*. The retention jobs are 2E and
# the export eligibility is 2D; the values here are defaults those phases refine.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetentionPolicy:
    """Per-mode retention descriptor (consumed by the 2E expiry jobs)."""

    ttl_days: int  # 0 / negative = no expiry
    store_raw_payloads: bool


_RETENTION: dict[ProductMode, RetentionPolicy] = {
    ProductMode.SECURITY_INVESTIGATION: RetentionPolicy(
        ttl_days=180, store_raw_payloads=True
    ),
    ProductMode.PUBLIC_BUSINESS_CONTACT: RetentionPolicy(
        ttl_days=365, store_raw_payloads=False
    ),
    ProductMode.ORG_AUTHORIZED_VERIFICATION: RetentionPolicy(
        ttl_days=180, store_raw_payloads=False
    ),
}

_EXPORT_SCHEMA: dict[ProductMode, str] = {
    ProductMode.SECURITY_INVESTIGATION: "security_full",
    ProductMode.PUBLIC_BUSINESS_CONTACT: "lead_outreach",
    ProductMode.ORG_AUTHORIZED_VERIFICATION: "verification",
}


# Per-mode source-policy status stamped onto every observation (the 1C field).
# The dispatch gate ensures only mode-appropriate modules run, so the mode alone
# determines the lawful basis of the data collected under it. Security stays
# "unreviewed" (unchanged — zero regression); 2D's eligibility consumes these.
_POLICY_STATUS_BY_MODE: dict[ProductMode, str] = {
    ProductMode.SECURITY_INVESTIGATION: "unreviewed",
    ProductMode.PUBLIC_BUSINESS_CONTACT: "lawful-public",
    ProductMode.ORG_AUTHORIZED_VERIFICATION: "authorized-supplied",
}


def policy_status_for_mode(mode: str | ProductMode) -> str:
    """The `source_policy_status` an observation gets for its collection mode."""
    return _POLICY_STATUS_BY_MODE[normalize_mode(mode)]


def retention_policy(mode: str | ProductMode) -> RetentionPolicy:
    """The retention descriptor a mode selects (2E consumes this)."""
    return _RETENTION[normalize_mode(mode)]


def export_schema(mode: str | ProductMode) -> str:
    """The export schema label a mode selects (2D consumes this)."""
    return _EXPORT_SCHEMA[normalize_mode(mode)]
