from __future__ import annotations

import contextlib
import asyncio
import logging
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import dns.resolver

from ..config import settings
from .http_client import build_client
from .rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DISPOSABLE_CACHE_FILE = _REPO_ROOT / "data" / "cache" / "disposable_domains.txt"
_DISPOSABLE_SOURCE_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)
_DISPOSABLE_CACHE_TTL = timedelta(days=7)
_COMMON_DISPOSABLE_SUFFIXES = (
    "guerrillamail.com",
    "mailinator.com",
    "temp-mail.org",
)
_FALLBACK_DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "dispostable.com",
    "guerrillamail.com",
    "mailinator.com",
    "temp-mail.org",
    "yopmail.com",
}
_EMAILREP_CACHE_TTL = timedelta(hours=12)
_DISPOSABLE_LOCK = asyncio.Lock()
_EMAILREP_LOCK = asyncio.Lock()
_disposable_domains: set[str] | None = None
_disposable_loaded_at: datetime | None = None
_emailrep_cache: dict[tuple[str, bool], tuple[datetime, dict[str, Any]]] = {}
_emailrep_daily_usage: dict[tuple[bool, date], int] = {}

_DOMAIN_ALIAS_MAP = {
    "googlemail.com": "gmail.com",
    "hotmail.com": "outlook.com",
    "live.com": "outlook.com",
    "msn.com": "outlook.com",
    "pm.me": "protonmail.com",
    "me.com": "icloud.com",
    "mac.com": "icloud.com",
}


@dataclass(frozen=True)
class EmailNormalizationResult:
    canonical_email: str
    aliases_detected: list[str] = field(default_factory=list)
    provider_family: str = "other"
    is_plus_alias: bool = False
    is_dot_alias: bool = False
    is_alias: bool = False


@dataclass(frozen=True)
class EmailReputationResult:
    reputation_verdict: str
    reputation_flags: list[str]
    is_malicious: bool
    first_seen: str | None
    sources_checked: list[str]
    emailrep_reputation: str | None = None
    emailrep_suspicious: bool = False
    emailrep_malicious_activity: bool = False
    emailrep_malicious_activity_recent: bool = False
    emailrep_credentials_leaked: bool = False
    emailrep_spam: bool = False
    emailrep_blacklisted: bool = False
    emailrep_last_seen: str | None = None
    emailrep_free_provider: bool = False
    emailrep_disposable: bool = False
    emailrep_references: int | None = None
    spamhaus_list: str | None = None
    spamhaus_listed: bool = False
    domain_age_days: int | None = None
    domain_age_note: str | None = None


@dataclass(frozen=True)
class EmailCredibilityResult:
    canonical_email: str
    is_alias: bool
    aliases_detected: list[str]
    provider_family: str
    is_disposable: bool
    disposable_provider: str | None
    reputation_verdict: str
    reputation_flags: list[str]
    is_malicious: bool
    first_seen: str | None
    sources_checked: list[str]
    emailrep_reputation: str | None = None
    emailrep_suspicious: bool = False
    emailrep_malicious_activity: bool = False
    emailrep_malicious_activity_recent: bool = False
    emailrep_credentials_leaked: bool = False
    emailrep_spam: bool = False
    emailrep_blacklisted: bool = False
    emailrep_last_seen: str | None = None
    emailrep_free_provider: bool = False
    emailrep_disposable: bool = False
    emailrep_references: int | None = None
    spamhaus_list: str | None = None
    spamhaus_listed: bool = False
    domain_age_days: int | None = None
    domain_age_note: str | None = None


def _trimmed_lower(value: str) -> str:
    return value.strip().lower()


def _split_email(email: str) -> tuple[str, str] | None:
    cleaned = _trimmed_lower(email)
    if "@" not in cleaned:
        return None
    local, domain = cleaned.rsplit("@", 1)
    if not local or not domain:
        return None
    return local, domain


def _canonical_domain(domain: str) -> str:
    return _DOMAIN_ALIAS_MAP.get(domain, domain)


def _provider_family(domain: str) -> str:
    if domain in {"gmail.com"}:
        return "google"
    if domain in {"outlook.com"}:
        return "microsoft"
    if domain in {"yahoo.com"}:
        return "yahoo"
    if domain in {"icloud.com"}:
        return "apple"
    if domain in {"protonmail.com"}:
        return "proton"
    return "other"


def normalize_email_address(email: str) -> EmailNormalizationResult:
    cleaned = _trimmed_lower(email)
    parts = _split_email(cleaned)
    if parts is None:
        return EmailNormalizationResult(
            canonical_email=cleaned,
            aliases_detected=[cleaned] if cleaned else [],
            provider_family="other",
            is_alias=False,
        )

    local, domain = parts
    canonical_domain = _canonical_domain(domain)
    aliases: list[str] = []

    def add_alias(value: str) -> None:
        if value and value not in aliases:
            aliases.append(value)

    add_alias(f"{local}@{domain}")

    canonical_local = local
    is_plus_alias = False
    is_dot_alias = False

    if canonical_domain == "gmail.com":
        dot_free = canonical_local.replace(".", "")
        if dot_free != canonical_local:
            canonical_local = dot_free
            is_dot_alias = True
            add_alias(f"{canonical_local}@{canonical_domain}")
        if "+" in canonical_local:
            canonical_local = canonical_local.split("+", 1)[0]
            is_plus_alias = True
            add_alias(f"{canonical_local}@{canonical_domain}")
    elif canonical_domain == "outlook.com":
        if "+" in canonical_local:
            canonical_local = canonical_local.split("+", 1)[0]
            is_plus_alias = True
            add_alias(f"{canonical_local}@{canonical_domain}")
    elif canonical_domain == "yahoo.com":
        if "+" in canonical_local:
            canonical_local = canonical_local.split("+", 1)[0]
            is_plus_alias = True
            add_alias(f"{canonical_local}@{canonical_domain}")
        if "-" in canonical_local:
            canonical_local = canonical_local.split("-", 1)[0]
            is_plus_alias = True
            add_alias(f"{canonical_local}@{canonical_domain}")
    elif canonical_domain == "protonmail.com":
        if "+" in canonical_local:
            canonical_local = canonical_local.split("+", 1)[0]
            is_plus_alias = True
            add_alias(f"{canonical_local}@{canonical_domain}")

    canonical_email = f"{canonical_local}@{canonical_domain}"
    add_alias(canonical_email)

    return EmailNormalizationResult(
        canonical_email=canonical_email,
        aliases_detected=aliases,
        provider_family=_provider_family(canonical_domain),
        is_plus_alias=is_plus_alias,
        is_dot_alias=is_dot_alias,
        is_alias=canonical_email != cleaned,
    )


async def _load_disposable_domains() -> set[str]:
    global _disposable_domains, _disposable_loaded_at

    now = datetime.now(timezone.utc)
    if (
        _disposable_domains is not None
        and _disposable_loaded_at is not None
        and now - _disposable_loaded_at < _DISPOSABLE_CACHE_TTL
    ):
        return _disposable_domains

    async with _DISPOSABLE_LOCK:
        now = datetime.now(timezone.utc)
        if (
            _disposable_domains is not None
            and _disposable_loaded_at is not None
            and now - _disposable_loaded_at < _DISPOSABLE_CACHE_TTL
        ):
            return _disposable_domains

        cached = await asyncio.to_thread(_read_disposable_cache_file)
        if cached is not None:
            _disposable_domains = cached
            _disposable_loaded_at = now
            return cached

        downloaded = await _fetch_disposable_domains()
        if downloaded:
            _disposable_domains = downloaded
            _disposable_loaded_at = now
            await asyncio.to_thread(_write_disposable_cache_file, downloaded)
            return downloaded

        _disposable_domains = set(_FALLBACK_DISPOSABLE_DOMAINS)
        _disposable_loaded_at = now
        return _disposable_domains


def _read_disposable_cache_file() -> set[str] | None:
    try:
        if not _DISPOSABLE_CACHE_FILE.exists():
            return None
        mtime = datetime.fromtimestamp(_DISPOSABLE_CACHE_FILE.stat().st_mtime, tz=timezone.utc)
        if datetime.now(timezone.utc) - mtime > _DISPOSABLE_CACHE_TTL:
            return None
        domains = {
            line.strip().lower()
            for line in _DISPOSABLE_CACHE_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        return domains or None
    except Exception:
        return None


def _write_disposable_cache_file(domains: set[str]) -> None:
    try:
        _DISPOSABLE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _DISPOSABLE_CACHE_FILE.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")
    except Exception:
        logger.debug("Failed to write disposable cache file", exc_info=True)


async def _fetch_disposable_domains() -> set[str]:
    try:
        async with build_client(timeout=15.0) as client:
            res = await client.get(_DISPOSABLE_SOURCE_URL)
            if res.status_code != 200:
                return set()
            domains = {
                line.strip().lower()
                for line in res.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            return domains
    except Exception:
        logger.debug("Disposable domain fetch failed", exc_info=True)
        return set()


def _is_disposable_domain(domain: str, domains: set[str]) -> tuple[bool, str | None]:
    if domain in domains:
        return True, _provider_name_from_domain(domain)
    for suffix in _COMMON_DISPOSABLE_SUFFIXES:
        if domain == suffix or domain.endswith(f".{suffix}"):
            return True, _provider_name_from_domain(suffix)
    for disposable in domains:
        if domain == disposable or domain.endswith(f".{disposable}"):
            return True, _provider_name_from_domain(disposable)
    return False, None


def _provider_name_from_domain(domain: str) -> str:
    return domain.split(".", 1)[0]


async def detect_disposable_email(email: str) -> tuple[bool, str | None]:
    parts = _split_email(email)
    if parts is None:
        return False, None
    _, domain = parts
    domains = await _load_disposable_domains()
    return _is_disposable_domain(domain, domains)


def _parse_emailrep_date(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in _EMAILREP_DATE_FORMATS:
        try:
            if fmt == "%Y-%m":
                sample = text[:7]
            elif fmt == "%Y-%m-%d":
                sample = text[:10]
            else:
                sample = text
            parsed = datetime.strptime(sample, fmt)
            return parsed.date().isoformat()
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.date().isoformat()
    except ValueError:
        return None


def _parse_whois_date(value: Any) -> int | None:
    candidate = value
    if isinstance(candidate, list):
        candidate = candidate[0] if candidate else None
    if candidate is None:
        return None
    if isinstance(candidate, datetime):
        parsed = candidate.astimezone(timezone.utc) if candidate.tzinfo else candidate
        return (datetime.now(timezone.utc).date() - parsed.date()).days
    if isinstance(candidate, date):
        return (datetime.now(timezone.utc).date() - candidate).days
    text = str(candidate).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            sample = text[:10] if fmt == "%Y-%m-%d" else text[:19] if fmt == "%Y-%m-%dT%H:%M:%S" else text[:20]
            parsed = datetime.strptime(sample, fmt)
            return (datetime.now(timezone.utc).date() - parsed.date()).days
        except ValueError:
            continue
    return None


def _whois_creation_date(domain: str) -> int | None:
    try:
        import whois  # type: ignore[import]

        data = whois.whois(domain)
    except Exception:
        return None

    creation = None
    if hasattr(data, "creation_date"):
        creation = getattr(data, "creation_date")
    elif isinstance(data, dict):
        creation = data.get("creation_date")
    return _parse_whois_date(creation)


async def _lookup_spamhaus(domain: str) -> tuple[bool, str | None]:
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "MX")
    except Exception:
        return False, None

    mx_hosts = [str(answer.exchange).rstrip(".").lower() for answer in answers]
    if not mx_hosts:
        return False, None

    for host in mx_hosts[:3]:
        try:
            host_answers = await asyncio.to_thread(dns.resolver.resolve, host, "A")
        except Exception:
            continue
        for answer in host_answers:
            ip = str(answer)
            query = ".".join(reversed(ip.split("."))) + ".zen.spamhaus.org"
            try:
                zen_answers = await asyncio.to_thread(dns.resolver.resolve, query, "A")
            except Exception:
                continue
            for zen_answer in zen_answers:
                listed_ip = str(zen_answer)
                if listed_ip == "127.0.0.2":
                    return True, "SBL"
                if listed_ip == "127.0.0.3":
                    return True, "XBL"
                if listed_ip in {"127.0.0.10", "127.0.0.11"}:
                    return True, "PBL"
                return True, "ZEN"
    return False, None


async def _lookup_emailrep(email: str) -> dict[str, Any] | None:
    has_key = bool(settings.emailrep_api_key)
    cache_key = (email, has_key)
    async with _EMAILREP_LOCK:
        cached = _emailrep_cache.get(cache_key)
        if cached and datetime.now(timezone.utc) - cached[0] < _EMAILREP_CACHE_TTL:
            return cached[1]
        usage_key = (has_key, datetime.now(timezone.utc).date())
        limit = 1000 if has_key else 10
        if _emailrep_daily_usage.get(usage_key, 0) >= limit:
            return None

    await rate_limiter.acquire("emailrep.io")
    headers = {"User-Agent": "MailAccess OSINT Tool"}
    if has_key:
        headers["Key"] = settings.emailrep_api_key or ""

    try:
        async with build_client(timeout=8.0) as client:
            res = await client.get(f"https://emailrep.io/{email}", headers=headers)
    except Exception:
        return None

    if res.status_code in (400, 404, 429):
        return None
    if res.status_code != 200:
        return None

    try:
        payload = res.json()
    except Exception:
        return None

    async with _EMAILREP_LOCK:
        _emailrep_cache[cache_key] = (datetime.now(timezone.utc), payload)
        usage_key = (has_key, datetime.now(timezone.utc).date())
        _emailrep_daily_usage[usage_key] = _emailrep_daily_usage.get(usage_key, 0) + 1
    return payload


async def assess_email_reputation(
    email: str,
    normalization: EmailNormalizationResult | None = None,
    *,
    disposable: bool | None = None,
) -> EmailCredibilityResult:
    normalized = normalization or normalize_email_address(email)
    canonical_email = normalized.canonical_email
    parts = _split_email(canonical_email)
    domain = parts[1] if parts is not None else canonical_email.rsplit("@", 1)[-1]

    sources_checked = ["alias_normalization"]
    reputation_flags: list[str] = []
    first_seen: str | None = None
    is_disposable = bool(disposable)
    disposable_provider: str | None = None
    emailrep_reputation: str | None = None
    emailrep_suspicious = False
    emailrep_malicious_activity = False
    emailrep_malicious_activity_recent = False
    emailrep_credentials_leaked = False
    emailrep_spam = False
    emailrep_blacklisted = False
    emailrep_last_seen: str | None = None
    emailrep_free_provider = False
    emailrep_disposable = False
    emailrep_references: int | None = None
    spamhaus_list: str | None = None
    spamhaus_listed = False
    domain_age_days: int | None = None
    domain_age_note: str | None = None

    if disposable is None:
        is_disposable, disposable_provider = await detect_disposable_email(canonical_email)
    else:
        parts = _split_email(canonical_email)
        if parts is not None:
            _, disposable_provider = _is_disposable_domain(
                parts[1],
                await _load_disposable_domains(),
            )

    if is_disposable:
        sources_checked.append("disposable_blocklist")
        reputation_flags.append("Disposable email address detected")
        return EmailCredibilityResult(
            canonical_email=canonical_email,
            is_alias=normalized.is_alias,
            aliases_detected=normalized.aliases_detected,
            provider_family=normalized.provider_family,
            is_disposable=True,
            disposable_provider=disposable_provider,
            reputation_verdict="suspicious",
            reputation_flags=reputation_flags,
            is_malicious=False,
            first_seen=None,
            sources_checked=sources_checked,
        )

    emailrep = await _lookup_emailrep(canonical_email)
    sources_checked.append("emailrep.io")
    if emailrep:
        emailrep_reputation = str(emailrep.get("reputation") or "none")
        emailrep_suspicious = bool(emailrep.get("suspicious", False))
        emailrep_references = emailrep.get("references")
        if isinstance(emailrep_references, str):
            with contextlib.suppress(Exception):
                emailrep_references = int(emailrep_references)
        details = emailrep.get("details") if isinstance(emailrep.get("details"), dict) else {}
        emailrep_blacklisted = bool(details.get("blacklisted", False))
        emailrep_malicious_activity = bool(details.get("malicious_activity", False))
        emailrep_malicious_activity_recent = bool(details.get("malicious_activity_recent", False))
        emailrep_credentials_leaked = bool(details.get("credentials_leaked", False))
        emailrep_spam = bool(details.get("spam", False))
        emailrep_free_provider = bool(details.get("free_provider", False))
        emailrep_disposable = bool(details.get("disposable", False))
        emailrep_last_seen = _parse_emailrep_date(details.get("last_seen"))
        first_seen = _parse_emailrep_date(details.get("first_seen"))
        if first_seen is None:
            first_seen = _parse_emailrep_date(emailrep.get("first_seen"))

    try:
        spamhaus_listed, spamhaus_list = await _lookup_spamhaus(domain)
    except Exception:
        spamhaus_listed, spamhaus_list = False, None
    sources_checked.append("spamhaus_zen")

    try:
        domain_age_days = await asyncio.to_thread(_whois_creation_date, domain)
    except Exception:
        domain_age_days = None
    sources_checked.append("whois_age")

    if emailrep_malicious_activity:
        reputation_flags.append("Malicious activity detected (emailrep.io)")
    if emailrep_suspicious:
        reputation_flags.append("Suspicious email detected by emailrep.io")
    if emailrep_malicious_activity_recent:
        reputation_flags.append("Recent malicious activity reported by emailrep.io")
    if emailrep_credentials_leaked:
        reputation_flags.append("Credentials leaked (emailrep.io)")
    if emailrep_spam:
        reputation_flags.append("Spam flagged by emailrep.io")
    if emailrep_blacklisted:
        reputation_flags.append("Blacklisted by emailrep.io")
    if emailrep_disposable:
        reputation_flags.append("Disposable provider flagged by emailrep.io")
    if emailrep_free_provider:
        reputation_flags.append("Free provider flagged by emailrep.io")
    if spamhaus_listed and spamhaus_list:
        reputation_flags.append(f"Listed on Spamhaus ZEN ({spamhaus_list})")
    if domain_age_days is not None and domain_age_days < 30:
        reputation_flags.append("Domain registered less than 30 days ago")
    elif domain_age_days is not None and domain_age_days < 365:
        domain_age_note = f"Domain registered {domain_age_days} days ago"
        reputation_flags.append("Domain registered less than 1 year ago")

    is_malicious = bool(emailrep_malicious_activity or spamhaus_listed)
    if is_malicious:
        verdict = "malicious"
    elif reputation_flags:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return EmailCredibilityResult(
        canonical_email=canonical_email,
        is_alias=normalized.is_alias,
        aliases_detected=normalized.aliases_detected,
        provider_family=normalized.provider_family,
        is_disposable=False,
        disposable_provider=disposable_provider,
        reputation_verdict=verdict,
        reputation_flags=reputation_flags,
        is_malicious=is_malicious,
        first_seen=first_seen,
        sources_checked=sources_checked,
        emailrep_reputation=emailrep_reputation,
        emailrep_suspicious=emailrep_suspicious,
        emailrep_malicious_activity=emailrep_malicious_activity,
        emailrep_malicious_activity_recent=emailrep_malicious_activity_recent,
        emailrep_credentials_leaked=emailrep_credentials_leaked,
        emailrep_spam=emailrep_spam,
        emailrep_blacklisted=emailrep_blacklisted,
        emailrep_last_seen=emailrep_last_seen,
        emailrep_free_provider=emailrep_free_provider,
        emailrep_disposable=emailrep_disposable,
        emailrep_references=emailrep_references if isinstance(emailrep_references, int) else None,
        spamhaus_list=spamhaus_list,
        spamhaus_listed=spamhaus_listed,
        domain_age_days=domain_age_days,
        domain_age_note=domain_age_note,
    )


def export_email_credibility(result: EmailCredibilityResult) -> dict[str, Any]:
    return asdict(result)
_EMAILREP_DATE_FORMATS = ("%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d", "%Y-%m")
