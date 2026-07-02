from __future__ import annotations

import json
import logging
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
_DEFAULT_CORS_ORIGINS = ["http://localhost:5173", "http://localhost:3000"]

logger = logging.getLogger(__name__)

# Dynamically read the installed package version so health / OpenAPI stay in sync.
try:
    from importlib.metadata import version as _pkg_version
    APP_VERSION: str = _pkg_version("mailaccess")
except Exception:
    APP_VERSION = "0.0.0"


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
    elif isinstance(value, (list, tuple, set)):
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
    # Per-module timeout overrides: MODULE_TIMEOUT_OVERRIDES={"whatsmyname": 120}
    module_timeout_overrides: dict[str, int] = {}

    # Account discovery — probes 120+ platforms via Holehe
    enable_account_discovery: bool = True

    # WhatsMyName — username enumeration across 700+ platforms (~15s with concurrency)
    enable_whatsmyname: bool = True

    # Maigret native platform engine — 2500+ platform username sweep
    enable_maigret_platforms: bool = True
    enable_maigret_wave2: bool = False

    # Sherlock native platform engine — ~400 curated platforms (independent dataset)
    enable_sherlock_platforms: bool = True
    enable_sherlock_wave2: bool = True

    # Phase 3D — Nexfil
    enable_nexfil_platforms: bool = True
    enable_nexfil_wave2: bool = True

    # Phase 3C — Blackbird / WhatsMyName native two-marker platform engine
    enable_blackbird_platforms: bool = True
    enable_blackbird_wave2: bool = True
    enable_blackbird_nsfw: bool = False
    blackbird_concurrency: int = 60

    # GitHub Code Search — surfaces email mentions in public code and gists
    enable_github_code_search: bool = True

    # Pastebin / paste-site search — aggregated via psbdmp.ws (no auth required)
    enable_pastebin_search: bool = True

    # Gravatar profile lookup — single public endpoint, no auth required
    enable_gravatar_lookup: bool = True

    # Fediverse discovery — WebFinger probes across ~50 popular instances
    enable_fediverse_discovery: bool = True

    # User-scanner — probes 205+ platforms via user-scanner (no API key required)
    enable_user_scanner: bool = True

    # Username pivot — re-runs WhatsMyName for recovered usernames after primary modules
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

    # Domain harvester — theHarvester-style subdomain enumeration for the target email's domain
    enable_domain_harvester: bool = True
    personal_email_providers: list[str] = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "protonmail.com", "icloud.com", "aol.com", "live.com",
        "msn.com", "me.com", "mail.com", "proton.me", "pm.me",
        "gmx.com", "gmx.net", "yandex.com", "yandex.ru", "mail.ru",
        "zoho.com", "fastmail.com", "tutanota.com",
    ]

    # GHunt (opt-in — requires ghunt>=2.3 installed and a valid creds file from `ghunt login`)
    # Cookies expire periodically and require manual refresh via `ghunt login`.
    enable_ghunt: bool = False
    ghunt_creds_path: str | None = None

    # Phone intel: validates recovered phones and probes WhatsApp/Telegram (post-primary)
    enable_phone_intel: bool = True

    # Messaging hints: Telegram username checks during primary gather
    enable_messaging_hints: bool = True

    # Domain infrastructure clustering (Phase 6B.1): groups platform domains
    # by shared registrar + /24 subnet.  Emits infrastructure_correlation
    # findings when 3+ platforms share infrastructure.
    enable_domain_cluster: bool = True
    domain_cluster_cap: int = 20

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

    # Common Crawl email harvesting (domain harvest mode only — Phase A of 0.10.0).
    # Master kill switch; the module itself is opt-in via domain harvest
    # mode, this is the global enable flag for the underlying fetcher too.
    enable_commoncrawl_email: bool = True
    cc_max_records: int = 100
    cc_fetch_concurrency: int = 10
    cc_fetch_timeout_seconds: int = 8

    # Search-engine dorking (domain harvest mode only — Phase B1 of 0.10.0).
    # Master kill switch for the search-dork module.  The module is
    # already opt-in via the domain harvest entry point.
    enable_email_search_dork: bool = True
    dork_max_queries_per_engine: int = 5
    dork_lite_mode: bool = False
    dork_ddg_delay_seconds: float = 5.0
    dork_bing_delay_seconds: float = 4.0

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

    # Email pattern generation + SMTP verification (Phase C2 of 0.10.0).
    # Master kill switch for the pattern_and_verify module.  Lives in
    # domain harvest mode; takes the names from Phase C1's output.
    enable_email_pattern_and_verify: bool = True

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
    # ------------------------------------------------------------------
    # SMTP verification — OPT-IN ONLY.  The default is False to keep
    # "just run a domain harvest" safe.  Flipping ENABLE_SMTP_VERIFICATION
    # to true is the only way to actually probe mail servers.  Even when
    # true, all safety ceilings are HARD-CODED in smtp_verifier.py
    # (max 100 probes per domain, max 30/minute pacing).
    # ------------------------------------------------------------------
    enable_smtp_verification: bool = False
    # Configurable downward only — smtp_verifier clamps to
    # MAX_PROBES_HARD_CAP (100) regardless of what's set here.
    smtp_max_probes_per_domain: int = 100
    smtp_probe_delay_seconds: float = 2.5
    # Sender address used in MAIL FROM.  Spec requires this be a
    # non-attributable, non-deliverable anonymous address; do not
    # change it to anything that points back at the operator.
    smtp_sender_address: str = "probe@mailaccess.invalid"
    smtp_connect_timeout_seconds: int = 8

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

    # Proxy
    proxy_url: str | None = None
    proxy_enabled: bool = False

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
        return (
            init_settings,
            _MailAccessEnvSettingsSource(settings_cls, **source_kwargs),
            _MailAccessDotEnvSettingsSource(settings_cls, **dotenv_kwargs),
            file_secret_settings,
        )


settings = Settings()
