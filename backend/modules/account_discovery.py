from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from ..config import settings
from ..core.account_probe import default_health_key, probe_site
from ..core.http_client import build_client
from ..core.mailaccess_sites_loader import load_mailaccess_sites
from ..core.phone_extractor import mask_phone
from ..core.platform_health import get_health_db
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

# Native engine version. Bump when the probe engine's behavior (not just the
# site list) changes materially.
ENGINE_VERSION = "mailaccess-account-probe/1.0"
_CONCURRENCY = 20

_CACHE_DIR = Path.home() / ".mailaccess" / "cache" / "account_discovery"
_CACHE_TTL = 21_600  # 6 hours


def _cache_path(email: str) -> Path:
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    return _CACHE_DIR / f"{digest}.json"


def _read_cache(email: str) -> ModuleResult | None:
    path = _cache_path(email)
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age >= _CACHE_TTL:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return ModuleResult(
            status=ModuleStatus(payload["status"]),
            findings=payload.get("findings", []),
            metadata={**(payload.get("metadata") or {}), "from_cache": True},
            errors=payload.get("errors", []),
        )
    except Exception as exc:
        _LOG.debug("account_discovery: cache read failed (%s) — refreshing", exc)
        return None


def _write_cache(email: str, result: ModuleResult) -> None:
    if result.status not in (
        ModuleStatus.SUCCESS,
        ModuleStatus.SUCCESS_EMPTY,
        ModuleStatus.PARTIAL,
    ):
        return
    # R11 (S2) — only cache a sweep that produced DEFINITIVE coverage (at least
    # one confirmed hit or confirmed miss). An all-blocked / all-unknown sweep
    # carries no answer, so caching it would let a later run serve a fabricated
    # "all negative" instead of re-probing. Leaving it uncached means the next
    # run actually probes again.
    md = result.metadata or {}
    definitive = int(md.get("platforms_confirmed", 0)) + int(md.get("platforms_not_found", 0))
    if definitive <= 0:
        return
    path = _cache_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": result.status.value,
        "findings": result.findings,
        "metadata": result.metadata,
        "errors": result.errors,
    }
    try:
        path.write_text(json.dumps(payload), encoding="utf-8")
    except Exception as exc:
        _LOG.debug("account_discovery: cache write failed (%s)", exc)


def _make_finding(record: dict[str, Any]) -> dict[str, Any]:
    domain = record.get("domain") or ""
    profile_url = f"https://{domain}" if domain else None

    meta: dict[str, Any] = {}
    if record.get("emailrecovery"):
        meta["email_recovery"] = record["emailrecovery"]
    if record.get("phoneNumber"):
        meta["phone_hint"] = mask_phone(str(record["phoneNumber"]))
    if record.get("others"):
        meta["extras"] = record["others"]
    if record.get("emailrecovery") or record.get("phoneNumber"):
        meta["high_value"] = True
    # Additive, forward-compatible cross-source dedup key (does not change the
    # existing platform node id — see docs/mailaccess-sites-schema.md).
    if record.get("dedup_key"):
        meta["platform_dedup_key"] = record["dedup_key"]
    # Output-Trust (C): an email-existence probe is a SINGLE, uncorroborated signal
    # with a bare ``https://<domain>`` url — never a linkable, confirmed profile. Mark
    # it ``unverified`` so every fact surface (``is_confirmed_account_hit`` → brief /
    # graph / name candidates) and the CLI render treat it as a lead, not a confirmed
    # account. platform_dedup can still promote it to ``confirmed`` on dual-confirmation.
    meta.setdefault("verification", "unverified")

    return {
        "platform": record.get("name", "unknown"),
        "profile_url": profile_url,
        "metadata": meta,
        "confidence": "high",
        "verification": "unverified",
        "source": "account_discovery",
    }


class AccountDiscoveryModule(BaseModule):
    name = "account_discovery"
    description = (
        "Probe 250+ platforms via MailAccess's native account-existence engine "
        "to detect account registration (no login attempt). "
        "Enable via ENABLE_ACCOUNT_DISCOVERY=true."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        if not settings.enable_account_discovery:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_ACCOUNT_DISCOVERY=true to run this module"],
            )

        cached = _read_cache(email)
        if cached is not None:
            _LOG.debug("account_discovery: using cache for %s", email)
            return cached
        _LOG.debug("account_discovery: probing fresh for %s", email)

        sites, load_meta = load_mailaccess_sites()
        probeable = [
            defn
            for defn in sites.values()
            if defn.get("check_type") == "email-existence" and not defn.get("disabled")
        ]

        no_password_recovery = bool(
            getattr(settings, "account_discovery_no_password_recovery", False)
        )
        health = None
        try:
            health = get_health_db()
        except Exception:
            health = None

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        rate_limited: list[str] = []
        not_found_count = 0
        skipped_health = 0

        sem = asyncio.Semaphore(_CONCURRENCY)

        async def _run_one(defn: dict[str, Any], client: Any) -> dict[str, Any] | None:
            nonlocal skipped_health
            health_key = default_health_key(defn)
            if health is not None:
                try:
                    if not await health.should_probe_async(health_key):
                        skipped_health += 1
                        return None
                except Exception:
                    pass
            t0 = time.perf_counter()
            record = await probe_site(
                client, sem, defn, email,
                no_password_recovery=no_password_recovery,
            )
            if record is None:
                return None
            record.setdefault("dedup_key", defn.get("dedup_key"))
            if health is not None:
                outcome = (
                    "hit" if record.get("exists") is True
                    else "miss" if record.get("exists") is False
                    else "inconclusive"
                )
                try:
                    await health.record_probe_async(
                        platform=health_key,
                        domain=defn.get("domain"),
                        outcome=outcome,
                        latency_ms=int((time.perf_counter() - t0) * 1000),
                        content_length=0,
                    )
                except Exception:
                    pass
            return record

        async with build_client(timeout=15.0, follow_redirects=True) as client:
            gathered = await asyncio.gather(
                *[_run_one(defn, client) for defn in probeable],
                return_exceptions=True,
            )

        inconclusive_count = 0
        none_count = 0
        for item in gathered:
            if isinstance(item, Exception):
                errors.append(str(item))
                continue
            if item is None:
                none_count += 1
                continue
            if item.get("rateLimit"):
                rate_limited.append(str(item.get("name", "unknown")))
            elif item.get("exists") is True:
                findings.append(_make_finding(item))
            elif item.get("exists") is False:
                not_found_count += 1
            else:
                # R11 (S2) — exists is None: the probe ran but could not decide
                # (challenge / malformed / transport). This is UNKNOWN, not a
                # miss; count it so it can never masquerade as coverage.
                inconclusive_count += 1

        if rate_limited:
            errors.append(
                f"Rate-limited by {len(rate_limited)} platform(s): "
                + ", ".join(sorted(rate_limited))
            )

        hard_errors = [e for e in errors if not e.startswith("Rate-limited")]
        # R11 (S2) — model coverage honestly. A blocked (all-429) or all-unknown
        # sweep produced NO definitive answer, so it may never be reported as a
        # successful all-negative (SUCCESS_EMPTY) nor SUCCESS.
        executed = max(0, len(probeable) - skipped_health)
        no_response = max(0, none_count - skipped_health)
        blocked_unknown = len(rate_limited) + inconclusive_count + no_response
        coverage_complete = (
            executed > 0 and blocked_unknown == 0 and not hard_errors
        )
        if findings:
            # Found at least one account. Fully covered → SUCCESS, else PARTIAL.
            status = ModuleStatus.SUCCESS if coverage_complete else ModuleStatus.PARTIAL
        elif not_found_count > 0:
            # Only misses. A genuine all-negative ONLY when coverage was complete;
            # otherwise the "negative" is really "we were blocked" → PARTIAL.
            status = (
                ModuleStatus.SUCCESS_EMPTY if coverage_complete else ModuleStatus.PARTIAL
            )
        else:
            # No definitive result at all — everything blocked / unknown / errored
            # / skipped. Never SUCCESS_EMPTY (that would be a false all-negative).
            status = ModuleStatus.FAILED if hard_errors else ModuleStatus.PARTIAL

        result = ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "platforms_checked": len(probeable),
                "platforms_executed": executed,
                "platforms_confirmed": len(findings),
                "platforms_rate_limited": len(rate_limited),
                "platforms_not_found": not_found_count,
                "platforms_inconclusive": inconclusive_count,
                "platforms_no_response": no_response,
                "platforms_skipped_health": skipped_health,
                "coverage_complete": coverage_complete,
                "engine_version": ENGINE_VERSION,
                "site_source": load_meta.get("source"),
                "site_count": load_meta.get("site_count"),
            },
            errors=errors,
        )
        _write_cache(email, result)
        return result
