from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

_DEFAULT_DB = Path.home() / ".mailaccess" / "mailaccess.db"
_PROFILE_ENV_FILE = Path.home() / ".mailaccess" / ".env"
_DEFAULT_CORS_ORIGINS = ["http://localhost:5173", "http://localhost:3000"]

logger = logging.getLogger(__name__)

def _read_app_version() -> str:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject.exists():
        match = re.search(
            r'(?m)^version\s*=\s*["\']([^"\']+)["\']',
            pyproject.read_text(encoding="utf-8"),
        )
        if match:
            return match.group(1)
    try:
        from importlib.metadata import version as _pkg_version

        return _pkg_version("mailaccess")
    except Exception:
        return "0.0.0"


APP_VERSION: str = _read_app_version()


def _coerce_cors_origins(value: Any) -> list[str]:
    if value is None:
        return list(_DEFAULT_CORS_ORIGINS)

    items: list[Any]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return list(_DEFAULT_CORS_ORIGINS)
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON for CORS_ORIGINS; falling back to comma parsing")
            else:
                if isinstance(parsed, list):
                    items = parsed
                    origins = [str(item).strip() for item in items if str(item).strip()]
                    return origins or list(_DEFAULT_CORS_ORIGINS)
                logger.warning(
                    "CORS_ORIGINS JSON value is not a list; falling back to comma parsing"
                )
        items = raw.split(",")
    elif isinstance(value, list | tuple | set):
        items = list(value)
    else:
        logger.warning(
            "Unsupported CORS_ORIGINS value type %s; using defaults",
            type(value).__name__,
        )
        return list(_DEFAULT_CORS_ORIGINS)

    origins = [str(item).strip() for item in items if str(item).strip()]
    return origins or list(_DEFAULT_CORS_ORIGINS)


def _coerce_mapping(
    value: Any,
    field_name: str,
    value_type: type[int] | type[float],
) -> dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON for %s; using empty mapping", field_name)
            return {}
        if not isinstance(parsed, dict):
            logger.warning("%s JSON value is not an object; using empty mapping", field_name)
            return {}
        value = parsed
    elif not isinstance(value, dict):
        logger.warning(
            "Unsupported %s value type %s; using empty mapping",
            field_name,
            type(value).__name__,
        )
        return {}

    parsed_mapping: dict[str, Any] = {}
    for key, raw_item in value.items():
        key_name = str(key).strip()
        if not key_name:
            continue
        try:
            converted = int(raw_item) if value_type is int else float(raw_item)
        except (TypeError, ValueError):
            logger.warning("Skipping invalid %s entry for %s: %r", field_name, key_name, raw_item)
            continue
        parsed_mapping[key_name] = converted
    return parsed_mapping


class _MailAccessSettingsSourceMixin:
    def prepare_field_value(
        self,
        field_name: str,
        field: Any,
        value: Any,
        value_is_complex: bool,
    ) -> Any:
        if field_name == "cors_origins":
            return _coerce_cors_origins(value)
        if field_name == "module_timeout_overrides":
            return _coerce_mapping(value, field_name, int)
        if field_name == "rate_limit_overrides":
            return _coerce_mapping(value, field_name, int)
        if field_name == "rate_limit_delays":
            return _coerce_mapping(value, field_name, float)
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class _MailAccessEnvSettingsSource(_MailAccessSettingsSourceMixin, EnvSettingsSource):
    pass


class _MailAccessDotEnvSettingsSource(_MailAccessSettingsSourceMixin, DotEnvSettingsSource):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = f"sqlite+aiosqlite:///{_DEFAULT_DB}"

    # Application
    debug: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Worker
    max_concurrent_modules: int = 10
    module_timeout_seconds: int = 30
    # Per-module timeout overrides: MODULE_TIMEOUT_OVERRIDES={"username_platforms": 120}
    module_timeout_overrides: dict[str, int] = {}

    # Investigate mode — overall wall-clock completion budget (Phase 1B).
    # The whole investigation (all phases/modules) must finish within this many
    # seconds. When the budget is reached, modules still in flight are cut short
    # and not-yet-started ones are skipped — both recorded as budget_truncated —
    # so the run completes with partial results instead of hanging or failing.
    # The default is generous enough that the full default module set completes
    # on normal targets (it only bites pathological runs). CLI --budget and the
    # API budget_seconds override per-run; a value <= 0 means unlimited.
    investigation_budget_seconds: float = 420.0
    # Minimum budget a module needs left to be worth starting; below this it is
    # skipped as budget_truncated instead of started for a sliver of time.
    investigation_budget_min_module_seconds: float = 2.0
    # Optionally pin a fast primary module set for investigate (the Phase-0
    # fast-run workaround, persisted). When non-empty AND the caller passes no
    # explicit --modules, the primary phase is restricted to these module names.
    # JSON list, e.g. INVESTIGATION_FAST_MODULES=["hibp","gravatar_lookup"].
    # Empty = full default module set.
    investigation_fast_modules: list[str] = []

    # Phase 2B — product mode (the governance keystone). Selects a per-run module
    # allowlist, retention policy and export schema. Default = today's full
    # capability, renamed (zero regression). CLI --mode and the API `mode` field
    # override per-run. One of: security-investigation, public-business-contact,
    # org-authorized-verification. See backend/core/product_mode.py.
    product_mode: str = "security-investigation"

    # Phase 2D — eligibility (≠ confidence). Outreach export requires BOTH a
    # confidence threshold AND a policy verdict. Per-mode confidence thresholds
    # for the "eligible" verdict, plus the floor above which a below-threshold
    # record is "review" (rather than "research-only"). Scores are 0..1.
    eligibility_confidence_threshold_public: float = 0.7
    eligibility_confidence_threshold_org: float = 0.6
    eligibility_review_floor: float = 0.4

    # Phase 2F — API safe-by-default. Per-principal request quota on the
    # investigation-triggering endpoints (embedded/in-process; no shared infra).
    api_quota_enabled: bool = True
    api_quota_per_principal: int = 60
    api_quota_window_seconds: float = 60.0

    # Phase 1C — canonical evidence ledger (the immutable `observations` store).
    # Both pipelines dual-write observations alongside their existing outputs.
    # Master switch (safety escape hatch); the write is always fully guarded so a
    # ledger failure can never break investigate/harvest.
    enable_observation_ledger: bool = True
    # Default time-to-live for a ledger observation (days) → sets expires_at.
    # Per-source-type TTLs are a Phase 2 refinement; 0 or negative = no expiry.
    ledger_default_ttl_days: int = 180
    # Optional raw-payload storage (Doc-1 #2): OFF by default. The content hash is
    # always stored; the raw evidence bytes are stored (expiry-bound) only when
    # this is enabled AND a module supplies them.
    ledger_store_raw_payloads: bool = False

    # Phase 4A — self-calibrating scoring: ground-truth & feature capture. Every
    # deliverability score is snapshotted (immutable, ledger-linked) so the
    # Phase-4B trainer has data to learn from; an objective outcome that later
    # arrives is joined as a new linked row. Master switch; the capture is fully
    # guarded so it can never break a harvest. Retention obeys ledger_default_ttl_days.
    enable_scoring_capture: bool = True
    # Phase 4D — run the calibrated model in shadow (log prediction + delta vs the
    # hand-tuned scorer) without affecting live output. Shadow logging only; the
    # calibrated model becomes authoritative only after the 4B promotion gate
    # passes (see backend/core/shadow_scorer.py). Independent of promotion state.
    enable_shadow_scoring: bool = True
    # Phase 4C — per-source accounting (marginal unique/confirmed contribution,
    # latency, failure/FP rate) + explainable, reversible auto-demotion of sources
    # that no longer earn their runtime. Recording is always on when enabled; a
    # demotion only ever fires on the strict dead-source criteria and is reversible.
    enable_source_accounting: bool = True

    # Phase 6A — confidence decay in the corpus (Doc-2 A4). B2B contact data rots
    # ~25–30%/yr; the read-first corpus is compounding, so an aging row must be
    # down-weighted at serve time and flagged for re-verification rather than
    # served stale-but-fast at full confidence. Applied purely at read time over
    # the servable `contacts` projection — stored confidence is never mutated and
    # the parity-preserving crawl reconstruction is untouched, so fresh rows never
    # regress. See backend/core/corpus_decay.py.
    enable_corpus_decay: bool = True
    # Fraction of confidence lost after one year without re-verification (the
    # geometric decay rate). 0.28 ≈ the middle of the 25–30%/yr B2B rot estimate.
    corpus_decay_annual_rot: float = 0.28
    # Floor below which the decay multiplier never falls (a very old row is
    # down-weighted, not zeroed — it may still be worth re-verifying).
    corpus_decay_min_factor: float = 0.3
    # Age (days) past which a served row is flagged needs_reverification.
    corpus_decay_stale_after_days: int = 180

    # Phase 6C — corpus-derived Bayesian pattern priors (Doc-2 A5). Aggregates
    # verified per-provider/per-industry email-pattern distributions from the
    # corpus and feeds them as an explainable prior into pattern inference
    # (a small, bounded boost for the corpus-favored template, analogous to the
    # Hunter pattern boost). Privacy-safe: aggregate distributions only, never a
    # raw contact. No-op on an empty corpus (uniform prior → zero change). See
    # backend/core/pattern_priors.py.
    enable_corpus_pattern_priors: bool = True

    # Phase 6F — change intelligence. Diffs consecutive corpus crawls into
    # first-seen / disappeared / title-change / verification-drift signals →
    # likely-new-hire / likely-departure detection, plus surfacing "likely stale"
    # rows (6A) rather than silently retaining them. Read-only over the corpus
    # history; guarded. See backend/core/change_intelligence.py.
    enable_change_intelligence: bool = True

    # Phase 6D/6E — the shared-corpus distribution + contribution machinery. This
    # is the ONLY point at which corpus data could leave the local machine, and
    # the governing principle is private-by-default, publish-never-without-explicit-
    # approval. The machinery (artifact format, signing, sharding, delta, rollback,
    # batching) is built and testable now but INERT: it does not publish unless the
    # operator (a) turns the master switch on, (b) configures a concrete sync
    # adapter (none ships), and (c) explicitly opts in / approves a batch. Only
    # 6B-safe artifacts are ever eligible; contact-level artifacts require explicit
    # per-batch human review. Left off pending the infra decision.
    enable_corpus_distribution: bool = False
    enable_corpus_contribution: bool = False
    # Number of domain-hash shards a published corpus update is split into.
    corpus_distribution_shards: int = 256
    # HMAC signing secret for corpus bundles (a local key file is generated when
    # unset). A future Ed25519 signer drops in behind the same Signer interface.
    corpus_signing_key: str | None = None
    # Contribution batching caps (rate-limiting): max safe artifacts per batch and
    # max batches per rolling window.
    corpus_contribution_max_per_batch: int = 500
    corpus_contribution_max_per_window: int = 5
    corpus_contribution_window_seconds: float = 3600.0

    # Account discovery — probes 250+ platforms for account existence by email
    enable_account_discovery: bool = True

    # Native username platform engine — sweeps the unified 5,000+ platform corpus
    # (data/mailaccess_sites.json) for username-url account existence. This single
    # engine covers the full corpus (including the former standalone username sweep,
    # now folded in). Wave 2 opts into lower-ranked/long-tail platforms beyond the
    # default high-signal cut.
    enable_username_platforms: bool = True
    enable_username_wave2: bool = False
    # Per-run cap on the number of platforms probed per wave, selected by popularity
    # rank (best first, unranked last) after health/skip filtering. It is a *ceiling*:
    # The username sweep probes a SPECULATIVE guess derived from the email localpart
    # (not confirmed evidence), so T1 (Output-Trust final) restricts it to the
    # HIGH-PRECISION tier of Wave 1: platforms that are popularity-ranked OR carry a
    # discriminating probe contract (two-marker presence+absence / regex / distinct
    # existence-vs-miss codes). The dropped remainder is the unranked bare-status_code
    # long tail — the false-positive source (a soft 200 for any string). This tail-drop
    # is applied by ``_cap_queue_by_rank`` regardless of this value; ``alexaRank`` is
    # too sparse in the corpus (only ~340/2238 Wave-1 sites ranked, GitHub/YouTube/…
    # unranked) to shrink by rank without evicting real majors, so precision — not a
    # magic count — selects the subset. This value is a further RANK CEILING on that
    # high-precision tier (~600 sites today, so 2500 never trims it) that bounds a
    # cold-box run's wall-clock if the corpus grows. 0 disables the ceiling (the
    # precision tail-drop still applies). The evidence-first PrimaryPhase ordering
    # ensures even a full sweep never starves the real identity sources; confirmed-
    # handle enumeration is username_pivot's job.
    username_wave1_cap: int = 2500
    username_wave2_cap: int = 0

    # GitHub Code Search — surfaces email mentions in public code and gists
    enable_github_code_search: bool = True

    # Pastebin / paste-site search — aggregated via psbdmp.ws (no auth required)
    enable_pastebin_search: bool = True

    # Gravatar profile lookup — single public endpoint, no auth required
    enable_gravatar_lookup: bool = True

    # Fediverse discovery — WebFinger probes across ~50 popular instances
    enable_fediverse_discovery: bool = True
    enable_keybase_lookup: bool = True
    enable_hackernews_lookup: bool = True

    # Username pivot — re-runs the username platform sweep for recovered
    # usernames after primary modules
    enable_username_pivot: bool = True

    # Permutation discovery — generates email variations from recovered names,
    # then probes each with Hudson Rock (+ HIBP if key is set)
    enable_permutation_discovery: bool = True
    enable_email_discovery: bool = False
    enable_press_intel: bool = False

    # Phase 3E — IntelligenceX leak/paste/darknet correlation
    enable_intelx_lookup: bool = True
    intelx_api_key: str | None = None
    intelx_base_url: str | None = None
    intelx_buckets: list[str] = ["leaks.public", "pastes"]
    intelx_max_results: int = 50

    # Domain harvester — native subdomain enumeration for the target email's domain
    enable_domain_harvester: bool = True
    personal_email_providers: list[str] = [
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "protonmail.com",
        "icloud.com",
        "aol.com",
        "live.com",
        "msn.com",
        "me.com",
        "mail.com",
        "proton.me",
        "pm.me",
        "gmx.com",
        "gmx.net",
        "yandex.com",
        "yandex.ru",
        "mail.ru",
        "zoho.com",
        "fastmail.com",
        "tutanota.com",
    ]

    # Native Google-account intelligence — unauthenticated, stable public signals
    # (Gmail/Google account existence, public GAIA profile, avatar, review/presence).
    # Plain HTTP/DNS, no credentials required, so it is on by default and health-registered.
    enable_google_account_intel: bool = True
    # Optional: a Google public web API key enables best-effort public-profile
    # enrichment (display name / avatar / GAIA id) via the public People endpoint.
    # Left empty by default — the module still returns the stable MX/domain signal
    # without it, and the enrichment source is health-registered so any endpoint
    # change degrades gracefully rather than erroring.
    google_intel_api_key: str = ""

    # Phone intel: validates recovered phones and probes WhatsApp/Telegram (post-primary)
    enable_phone_intel: bool = True

    # Messaging hints: Telegram username checks during primary gather
    enable_messaging_hints: bool = True

    # Domain infrastructure clustering (Phase 6B.1): groups platform domains
    # by shared registrar + /24 subnet.  Emits infrastructure_correlation
    # findings when 3+ platforms share infrastructure.
    enable_domain_cluster: bool = True
    domain_cluster_cap: int = 20

    # Phase 5 — breach aggregation. Four sources: Scylla.so (free), HIBP
    # pastes (needs HIBP_API_KEY), Dehashed and Snusbase (both paid). Each
    # source is skipped gracefully when its key/toggle is absent.
    enable_scylla: bool = True
    enable_hibp_pastes: bool = True
    dehashed_api_key: str = ""
    # Dehashed Basic auth uses the account holder's login email, not the
    # target being searched. Leave empty to fall back to key-only auth.
    dehashed_account_email: str = ""
    snusbase_api_key: str = ""
    breach_aggregator_timeout: float = 15.0

    # Deep breach probing: opt-in account-existence checks across top HIBP breach domains
    enable_breach_deep: bool = False
    breach_deep_limit: int = 100
    breach_deep_full: bool = False

    # Investigation cache: when an identical email is investigated within
    # `investigation_cache_window_minutes`, reuse the most recent COMPLETE
    # result instead of running modules again. Avoids rate-limit-driven
    # variance between back-to-back runs. CLI/API callers can force a fresh
    # run by passing `force=true`.
    enable_investigation_cache: bool = True
    investigation_cache_window_minutes: int = 30

    # 0.12.7 — Default JSON export on every harvest.
    # When true, `mailaccess harvest-emails` writes a JSON export to
    # `harvest_results_dir` automatically.  CLI flag --no-export
    # overrides per-run.  ``harvest_results_max_per_domain`` enforces
    # a per-domain rolling cap; ``harvest_results_max_age_days``
    # triggers lazy cleanup of stale files on next harvest.
    harvest_auto_export: bool = True
    harvest_results_dir: Path = Path.home() / ".mailaccess" / "results"
    harvest_results_max_per_domain: int = 50
    harvest_results_max_age_days: int = 30

    # Phase 5A — bulk / list harvest mode. ``harvest-emails --file domains.csv``
    # fans out over a domain list with a bounded concurrency governor,
    # resumable per-domain checkpoints, corpus-backed cross-batch dedup, and one
    # merged evidence-preserving export. ``bulk_max_concurrent_domains`` bounds
    # how many domains harvest at once (each domain is itself internally
    # concurrent); keep it modest so the batch does not self-DoS shared sources
    # (Phase 5B unifies the throttle across both transport stacks). Checkpoints
    # land under ``bulk_checkpoint_dir`` keyed by the input-list fingerprint.
    bulk_max_concurrent_domains: int = 3
    bulk_checkpoint_dir: Path = Path.home() / ".mailaccess" / "bulk"
    bulk_results_dir: Path = Path.home() / ".mailaccess" / "results" / "bulk"

    # Common Crawl email harvesting (domain harvest mode only — Phase A of 0.10.0).
    # Master kill switch; the module itself is opt-in via domain harvest
    # mode, this is the global enable flag for the underlying fetcher too.
    enable_commoncrawl_email: bool = True
    # Phase 5B — Common-Crawl-first posture. When on (default), the harvest
    # prefers the already-crawled web (CC index/page fetch) and treats live
    # search scraping as the FALLBACK, invoked only when CC under-delivers. This
    # is the single biggest block-reduction lever at volume: it avoids hitting
    # DDG/Bing (the 202/CAPTCHA walls) for domains CC already covers.
    cc_first: bool = True
    # Hard fallback: once at least this many on-domain emails have already been
    # discovered (from Common Crawl / archive / other on-domain sources), the
    # block-prone live-search email dork is SKIPPED entirely — it never touches
    # DDG/Bing. This is what turns CC-first into a measurable block reduction
    # (not just a reordering): live search runs only when the cheap sources
    # under-deliver. Set to 0 to always run the live-search dork.
    cc_first_min_emails: int = 3
    cc_max_records: int = 100
    cc_fetch_concurrency: int = 10
    cc_fetch_timeout_seconds: int = 8
    # 0.11.1 Phase 3 — multi-collection sweep.  ``cc_max_collections``
    # caps the number of CC crawls (newest first) the module sweeps.
    # ``cc_max_records_per_collection`` caps the CDX row count returned
    # per collection.  Aggressive mode (the CLI ``--aggressive`` flag)
    # doubles both.  ``cc_max_records`` is preserved for legacy callers
    # that pass a single budget; the module redistributes it across
    # the configured collection count.
    cc_max_collections: int = 6
    cc_max_records_per_collection: int = 250
    # 0.11.1 Phase 3 — Wayback Machine domain harvest.  When enabled,
    # the orchestrator's Phase 1 spawns WaybackDomainHarvestModule
    # alongside Common Crawl.  ``wayback_max_urls`` is the
    # post-scoring cap on URLs fetched per harvest.
    enable_wayback_harvest: bool = True
    wayback_max_urls: int = 100
    # Syndication feed sweep (domain harvest mode only).
    # Scans homepage feed links and fallback feed endpoints for author data.
    enable_syndication_feed_sweeper: bool = True
    enable_harvest_history_cache: bool = True
    enable_yield_prediction: bool = True
    yield_prediction_tail_seconds: float = 15.0

    # Search-engine dorking (domain harvest mode only — Phase B1 of 0.10.0).
    # Master kill switch for the search-dork module.  The module is
    # already opt-in via the domain harvest entry point.
    # 0.11.1 Phase 4: Google CSE added as an optional third engine.
    # Active only when google_cse_api_key and google_cse_cx are both set.
    enable_email_search_dork: bool = True
    dork_max_queries_per_engine: int = 5
    dork_lite_mode: bool = False
    dork_ddg_delay_seconds: float = 5.0
    dork_bing_delay_seconds: float = 4.0
    # Supported API-backed search provider. ``auto`` uses Brave when a key
    # is configured and otherwise keeps legacy HTML as best-effort fallback.
    search_provider: str = "auto"
    brave_search_api_key: str | None = None
    google_cse_api_key: str | None = None
    google_cse_cx: str | None = None
    # Phase 5B — search-provider failover. A provider that returns a hard block
    # (202/403/429/CAPTCHA) is benched for ``search_provider_cooldown_seconds``
    # and the router rolls to the next provider in the chain (Brave→DDG→Bing),
    # instead of the old behaviour where a Brave block short-circuited the whole
    # chain. Health is tracked per-provider across the run.
    search_provider_cooldown_seconds: float = 300.0

    # Code + certificate-transparency email harvest (Phase B2 of 0.10.0).
    # Master kill switch for the GitHub + crt.sh + certspotter module.
    enable_code_and_cert_email: bool = True
    github_email_max_results: int = 30
    github_email_max_repos_checked: int = 10
    github_email_max_commits_per_repo: int = 20

    # Employee / executive name discovery (Phase C1 of 0.10.0).
    # Master kill switch for the multi-source name discovery module. The
    # module is opt-in via domain harvest mode and feeds Phase C2's
    # pattern generation, not the email-mode investigation pipeline.
    enable_employee_name_discovery: bool = True
    employee_name_max_company_pages: int = 5
    # Optional spaCy-backed classifier. One of: on, off.
    ml_name_classifier: str = "off"

    # Email pattern generation + SMTP verification (Phase C2 of 0.10.0).
    # Master kill switch for the pattern_and_verify module.  Lives in
    # domain harvest mode; takes the names from Phase C1's output.
    enable_email_pattern_and_verify: bool = True
    pattern_high_confidence_threshold: float = 0.75
    pattern_medium_confidence_threshold: float = 0.50

    # W5: Phase 0.10.0 final additions — three new structured-source
    # modules that slot into Phase 1 of the harvest orchestrator
    # (the parallel fast/cheap-sources phase). All three default on,
    # no API key required, and run concurrently with commoncrawl_email
    # and code_and_cert_email via asyncio.gather.
    #
    # npm_email: package maintainer emails on registry.npmjs.org.
    # PyPI_email: package maintainer emails on pypi.org.
    # pgp_domain_email: UID-bearing public PGP keys on keys.openpgp.org
    #                   + keyserver.ubuntu.com, restricted to UIDs that
    #                   contain the target domain string.
    enable_npm_email: bool = True
    enable_pypi_email: bool = True
    enable_pgp_domain_email: bool = True
    # PGP keyserver resilience. When all keyservers fail simultaneously the
    # module falls back to a 24h result cache with a freshness penalty and
    # retries each server once with backoff before moving on.
    pgp_cache_enabled: bool = True
    pgp_cache_ttl_hours: int = 24
    pgp_retry_on_failure: bool = True
    # Keyless public-surface expansion. All limits are hard caps per run.
    enable_public_surface_sweeper: bool = True
    public_surface_max_urls: int = 12
    enable_public_forge: bool = True
    public_forge_max_projects: int = 5
    public_forge_max_commits: int = 10
    enable_package_ecosystems: bool = True
    package_ecosystems_max_packages: int = 5
    enable_subdomain_surface: bool = True
    subdomain_surface_max_hosts: int = 8
    enable_subdomain_intel: bool = True
    # AlienVault OTX requires authentication for passive DNS from this
    # environment; keep it opt-in so an anonymous 429 cannot consume harvest
    # budget or distort passive-source health.
    otx_api_key: str | None = None
    # ------------------------------------------------------------------
    # SMTP verification runs for domain harvests unless the caller opts out.
    # Keep the legacy names as compatibility aliases while the 0.12.5 names
    # are the canonical public configuration surface.
    # ------------------------------------------------------------------
    smtp_verify_default: bool = True
    smtp_verify_max_probes: int = 10
    smtp_verify_timeout: float = 10.0
    smtp_greylist_retry_delay: float = 30.0
    enable_smtp_verification: bool = True
    smtp_max_probes_per_domain: int = 10
    smtp_probe_delay_seconds: float = 2.5
    # Explicit MAIL FROM override.  Leave empty ("") to derive a
    # realistic per-probe sender from ``smtp_probe_domain_pattern``
    # (the default), which makes the probe look like an internal
    # bounce check rather than an obvious OSINT tool.  Set a fixed
    # address here only if you have a specific operator mailbox to use.
    smtp_sender_address: str = ""
    # Probe identity policy (FIX 1):
    #   "target" — derive MAIL FROM <verify-{uuid8}@{target_domain}>
    #              and HELO mail.{target_domain} from the domain being
    #              verified (default).
    #   "custom" — use ``smtp_probe_custom_domain`` instead of the
    #              target domain for the sender/HELO hostname.
    smtp_probe_domain_pattern: str = "target"
    smtp_probe_custom_domain: str = ""
    smtp_connect_timeout_seconds: int = 10
    # A persona pivot is reactive only; it is never seeded as a normal module.
    persona_pivot_enabled: bool = True
    persona_pivot_max_names: int = 10
    persona_pivot_max_queries_per_name: int = 3
    harvest_cache_enabled: bool = True
    harvest_cache_ttl_seconds: int = 3600
    # Automatic low-confidence email validation during domain harvests.
    # The validator itself is default-on; the per-run cap limits network probes.
    enable_low_email_validation: bool = True
    harvest_validation_max_per_run: int = 25
    # Keyless XposedOrNot passive breach corroboration.
    xposed_or_not_enabled: bool = True
    # Provider-aware verification. M365 is opt-in because the endpoint is
    # undocumented and tenant privacy/throttle settings affect semantics.
    enable_m365_email_verification: bool = False
    m365_verification_delay_seconds: float = 0.1
    m365_verification_max_checks: int = 50
    m365_verification_timeout_seconds: float = 10.0
    # Microsoft Autodiscover existence probe (FIX 2). Faster and
    # unthrottled relative to GetCredentialType; runs first on M365.
    enable_outlook_autodiscover: bool = True
    autodiscover_timeout_seconds: float = 8.0
    autodiscover_max_probes: int = 50
    # M365 Passive Intelligence — Phase 1. Five unauthenticated passive
    # checks against Microsoft infrastructure. All run by default on any
    # domain/email that resolves to M365; none authenticate or risk lockout.
    enable_m365_passive_intel: bool = True
    # Check 3 — REST Autodiscover variant, run alongside the v1 probe.
    enable_autodiscover_rest: bool = True
    # Check 5 — OpenID configuration preflight (per domain).
    m365_openid_timeout_seconds: float = 8.0
    # Check 1 — GetUserRealm (getuserrealm.srf XML variant).
    m365_getuserrealm_timeout_seconds: float = 10.0
    # Check 4 — OneDrive personal-site probe (per email).
    m365_onedrive_timeout_seconds: float = 8.0
    m365_onedrive_max_probes: int = 25
    # Hard overall budget for the passive-intel enrichment block. It is
    # additive tenant intelligence, never worth stalling the harvest tail.
    m365_passive_intel_budget_seconds: float = 20.0
    # M365 Active Intelligence — Phase 3. Three single-probe account-state
    # checks that each send exactly ONE probe per account with a deliberately
    # invalid credential. A module-level guard enforces one probe per account
    # per process; at one attempt each there is no lockout risk.
    enable_aadsts_probe: bool = True
    enable_activesync_probe: bool = True
    enable_wstrust_probe: bool = True
    active_probe_timeout: float = 10.0
    # IMAP Single-Probe Existence — Phase 4. One guarded IMAP LOGIN per account
    # for self-hosted / shared-hosting / unknown domains that SMTP left
    # inconclusive. A module-level one-probe guard makes lockout impossible.
    enable_imap_probe: bool = True
    imap_probe_timeout: float = 8.0
    imap_port_check_timeout: float = 5.0
    # Enterprise Network Intelligence — Phase 2. Two unauthenticated,
    # domain-level passive checks that extract internal Active Directory
    # (NTLM Type-2 challenge reader) and unified-communications (Lync /
    # Skype for Business discovery) infrastructure. Neither authenticates
    # nor risks lockout; both run once per domain regardless of provider.
    enable_ntlm_challenge: bool = True
    enable_lync_discovery: bool = True
    # Combined wall-clock cap for both checks (run concurrently).
    enterprise_net_intel_budget_seconds: float = 15.0
    enable_yahoo_email_verification: bool = False
    yahoo_verification_delay_seconds: float = 1.2
    yahoo_verification_max_checks: int = 25
    yahoo_verification_timeout_seconds: float = 10.0
    google_workspace_verifier_enabled: bool = True
    google_verifier_timeout: float = 8.0
    gravatar_verification_enabled: bool = True

    # Webhooks
    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None
    integration_webhook_url: str | None = None
    integration_webhook_secret: str | None = None

    # API keys (all optional — modules skip themselves when their key is absent)
    mailaccess_api_key: str | None = None
    haveibeenpwned_api_key: str | None = None
    hibp_api_key: str | None = None
    breachdirectory_api_key: str | None = None
    hunter_io_api_key: str | None = None
    emailrep_api_key: str | None = None
    shodan_api_key: str | None = None
    serpapi_key: str | None = None
    github_token: str | None = None
    companies_house_api_key: str | None = None

    # Hunter.io usage tracking (Phase 6). Free tier is 25 searches/month and
    # 25 verifications/month with no CC. ``hunter_usage_tracking`` gates the
    # persistent monthly circuit breaker; when False, calls are neither counted
    # nor capped. The two limits are enforced independently against separate
    # counters in ``~/.mailaccess/hunter_usage.json``.
    hunter_usage_tracking: bool = True
    hunter_domain_search_limit: int = 25
    hunter_verify_limit: int = 25

    # Phase 7A/7B — enrichment waterfall + BYO free-tier connector keys. All
    # keys are the OPERATOR's own (never ours); a connector skips itself when
    # its key is absent or its enable flag is off, so enrichment is inert by
    # default and never changes yield until the operator opts in. Per-provider
    # monthly free-tier caps are enforced by ``provider_budget`` so no tier is
    # silently overrun. The waterfall tries connectors in priority order,
    # stopping at the first confident hit per field.
    enable_enrichment_waterfall: bool = True  # master switch; inert without keys
    enrichment_min_confidence: float = 0.5  # a connector hit at/above this fills a field
    enrichment_max_lookups: int = 50  # cap enrichment API calls per harvest run
    # Apollo — lawful-public business contact data (allowed in every mode).
    apollo_api_key: str | None = None
    enable_apollo: bool = False
    apollo_monthly_limit: int = 10000  # documented free-tier size; operator-tunable
    # People Data Labs — aggregated/data-broker data (security-investigation only).
    pdl_api_key: str | None = None
    enable_pdl: bool = False
    pdl_monthly_limit: int = 1000

    # Proxy (single static endpoint — legacy; superseded by the Phase 5B egress
    # pool below, which treats a single configured proxy as a pool of one).
    proxy_url: str | None = None
    proxy_enabled: bool = False

    # Phase 5B — egress rotation pool. ``egress_proxies`` is a BYO/config-driven
    # list of proxy URLs (socks5/http(s)) — point it at the Hetzner box or a
    # self-supplied endpoint list; empty means direct egress (no hardcoded paid
    # dependency). Both transport stacks (httpx + curl-cffi stealth) rotate over
    # it and report success/failure; an endpoint that fails ``egress_max_failures``
    # times in a row is benched for ``egress_cooldown_seconds`` then re-admitted
    # on probation. ``egress_health_check_url`` is the target the optional
    # health-check probes through each proxy.
    egress_proxies: list[str] = []
    egress_max_failures: int = 3
    egress_cooldown_seconds: float = 300.0
    egress_health_check_url: str = "https://www.google.com/generate_204"

    # ScrapingAnt - optional off-by-default clearnet proxy (referral partnership)
    scrapingant_enabled: bool = True
    scrapingant_api_key: str | None = None
    scrapingant_enabled_dorking: bool = False
    scrapingant_enabled_platforms: bool = False
    scrapingant_proxy_type: str = "residential"
    scrapingant_transport: str = "rest_api"
    scrapingant_proxy_residential_username: str | None = None
    scrapingant_proxy_residential_password: str | None = None
    scrapingant_proxy_datacenter_username: str | None = None
    scrapingant_proxy_datacenter_password: str | None = None

    # 0.11.1 Phase 1 — Stealth HTTP client (harvest mode only).
    # ``harvest_timing_profile`` selects one of the six T0..T5 pacing
    # profiles defined in :mod:`backend.core.stealth_client`.  The
    # ``T2 Balanced`` default keeps the harvest at human-like
    # cadence.
    # Phase 5B — ``harvest_fingerprint_rotation`` (default on) rotates a small
    # pool of internally-consistent desktop fingerprints (UA + sec-ch-ua +
    # curl-cffi impersonate target all agree) per stealth session, replacing the
    # previously-hardcoded single Chrome-120. ``harvest_impersonate_browser``, if
    # set to a specific target (e.g. "chrome124"), PINS the fingerprint and
    # disables rotation; empty (default) means rotate. See
    # :mod:`backend.core.fingerprints`.
    harvest_timing_profile: str = "t2"
    harvest_impersonate_browser: str = ""
    harvest_fingerprint_rotation: bool = True

    # 0.11.1 Phase 2 — Site Intelligence Rebuild.
    # ``harvest_aggressive`` enables the low-confidence body-text
    # name extraction in :func:`backend.core.structured_data_extractor.extract_people`
    # AND loosens a couple of upstream filters for higher recall.
    # Default false — opt in via ``--aggressive`` CLI flag or the
    # ``HARVEST_AGGRESSIVE`` env var.
    #
    # ``site_discovery_max_candidates`` caps the number of probe-
    # fetched URLs after merging the sitemap / homepage / robots
    # sources.  25 gives enough budget to probe all industry-router
    # paths AND the top universal paths; users can override per-run.
    #
    # ``site_discovery_timeout_seconds`` is the per-request budget
    # for each sitemap / homepage / robots / probe fetch.
    harvest_aggressive: bool = False
    site_discovery_max_candidates: int = 25
    site_discovery_timeout_seconds: int = 5

    # Rate limiting
    rate_limit_enabled: bool = True
    request_delay_ms: int = 1000
    # Per-domain overrides (ms): RATE_LIMIT_OVERRIDES={"api.github.com": 500}
    rate_limit_overrides: dict[str, int] = {}
    # Legacy per-domain delays (seconds): RATE_LIMIT_DELAYS={"haveibeenpwned.com": 1.5}
    rate_limit_delays: dict[str, float] = {}

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _validate_cors_origins(cls, value: Any) -> list[str]:
        return _coerce_cors_origins(value)

    @field_validator("product_mode", mode="before")
    @classmethod
    def _validate_product_mode(cls, value: Any) -> str:
        # Fail closed on an unknown mode: a bad mode is a hard error, never a
        # silent fallback to a more-permissive default. Kept in sync with
        # backend/core/product_mode.ProductMode (literals inlined to avoid an
        # import cycle at settings-construction time).
        allowed = {
            "security-investigation",
            "public-business-contact",
            "org-authorized-verification",
        }
        if value is None or value == "":
            return "security-investigation"
        text = str(value).strip()
        if text not in allowed:
            raise ValueError(
                f"unknown product_mode {value!r}; expected one of {sorted(allowed)}"
            )
        return text

    def with_overrides(self, **kwargs: Any):
        from .core._phase_runner import settings_override

        return settings_override(self, **kwargs)

    @field_validator("module_timeout_overrides", mode="before")
    @classmethod
    def _validate_module_timeout_overrides(cls, value: Any) -> dict[str, Any]:
        return _coerce_mapping(value, "module_timeout_overrides", int)

    @field_validator("rate_limit_overrides", mode="before")
    @classmethod
    def _validate_rate_limit_overrides(cls, value: Any) -> dict[str, Any]:
        return _coerce_mapping(value, "rate_limit_overrides", int)

    @field_validator("rate_limit_delays", mode="before")
    @classmethod
    def _validate_rate_limit_delays(cls, value: Any) -> dict[str, Any]:
        return _coerce_mapping(value, "rate_limit_delays", float)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        config = settings_cls.model_config
        source_kwargs = {
            "case_sensitive": getattr(env_settings, "case_sensitive", config.get("case_sensitive")),
            "env_prefix": getattr(env_settings, "env_prefix", config.get("env_prefix")),
            "env_nested_delimiter": getattr(
                env_settings, "env_nested_delimiter", config.get("env_nested_delimiter")
            ),
            "env_ignore_empty": getattr(
                env_settings, "env_ignore_empty", config.get("env_ignore_empty")
            ),
            "env_parse_none_str": getattr(
                env_settings, "env_parse_none_str", config.get("env_parse_none_str")
            ),
            "env_parse_enums": getattr(
                env_settings, "env_parse_enums", config.get("env_parse_enums")
            ),
        }
        dotenv_kwargs = {
            **source_kwargs,
            "env_file": getattr(dotenv_settings, "env_file", config.get("env_file")),
            "env_file_encoding": getattr(
                dotenv_settings, "env_file_encoding", config.get("env_file_encoding")
            ),
        }
        profile_dotenv_kwargs = {
            **dotenv_kwargs,
            "env_file": _PROFILE_ENV_FILE,
        }
        return (
            init_settings,
            _MailAccessEnvSettingsSource(settings_cls, **source_kwargs),
            _MailAccessDotEnvSettingsSource(settings_cls, **profile_dotenv_kwargs),
            _MailAccessDotEnvSettingsSource(settings_cls, **dotenv_kwargs),
            file_secret_settings,
        )


settings = Settings()


# ── L1: task-local per-run opt-in overrides ────────────────────────────────────
# Concurrent investigations share this one ``settings`` singleton. The engine used
# to enable a run's opt-in modules by *mutating* the singleton for the duration of
# the run (``settings_override``), holding that mutation open across every phase
# ``await`` — so an overlapping run on the same event loop could observe another
# run's flags, or have its own reverted mid-flight. Instead, each run publishes its
# opt-in flag *names* into this ContextVar, which is task-local (child tasks copy
# the context at creation, siblings never share it). ``opt_in_active`` ORs that
# per-run set over the global default at each read site, so no global state is
# mutated and runs cannot cross-contaminate.
import contextvars  # noqa: E402

_RUN_OPT_IN_FLAGS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "mailaccess_run_opt_in_flags", default=frozenset()
)


def set_run_opt_in_flags(flags: set[str] | frozenset[str]) -> contextvars.Token:
    """Publish this run's opt-in flag names task-locally. Returns a reset token."""
    return _RUN_OPT_IN_FLAGS.set(frozenset(flags))


def reset_run_opt_in_flags(token: contextvars.Token) -> None:
    _RUN_OPT_IN_FLAGS.reset(token)


def opt_in_active(flag_name: str, base: bool) -> bool:
    """True if ``flag_name`` is globally enabled OR opted-in for the current run."""
    return bool(base) or flag_name in _RUN_OPT_IN_FLAGS.get()
