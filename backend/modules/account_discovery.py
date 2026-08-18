from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from holehe.core import __version__ as _HOLEHE_VERSION
from holehe.core import get_functions, import_submodules

from ..config import settings
from ..core.http_client import build_client
from ..core.phone_extractor import mask_phone
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)
_BATCH_SIZE = 20

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
    if result.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
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


def _make_finding(result: dict[str, Any]) -> dict[str, Any]:
    domain = result.get("domain") or ""
    profile_url = f"https://{domain}" if domain else None

    meta: dict[str, Any] = {}
    if result.get("emailrecovery"):
        meta["email_recovery"] = result["emailrecovery"]
    if result.get("phoneNumber"):
        meta["phone_hint"] = mask_phone(result["phoneNumber"])
    if result.get("others"):
        meta["extras"] = result["others"]
    if result.get("emailrecovery") or result.get("phoneNumber"):
        meta["high_value"] = True

    return {
        "platform": result.get("name", "unknown"),
        "profile_url": profile_url,
        "metadata": meta,
        "confidence": "high",
        "source": "account_discovery",
    }


def _holehe_platform_name(fn: Any) -> str:
    """Best-effort platform label for a Holehe probe function."""
    module = getattr(fn, "__module__", "") or ""
    if module:
        return module.rsplit(".", 1)[-1]
    return getattr(fn, "__name__", None) or "unknown"


class AccountDiscoveryModule(BaseModule):
    name = "account_discovery"
    description = (
        "Probe 120+ platforms via Holehe to detect account existence. "
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

        funcs = get_functions(import_submodules("holehe"))
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        rate_limited: list[str] = []
        not_found_count = 0

        batches = [
            funcs[i : i + _BATCH_SIZE]
            for i in range(0, len(funcs), _BATCH_SIZE)
        ]

        probe_failures: list[str] = []

        async with build_client(timeout=15.0, follow_redirects=True) as client:
            for idx, batch in enumerate(batches):
                out_lists: list[list[dict[str, Any]]] = [[] for _ in batch]
                coros = [fn(email, client, out) for fn, out in zip(batch, out_lists)]
                gathered = await asyncio.gather(*coros, return_exceptions=True)

                for fn, exc_or_none, out in zip(batch, gathered, out_lists):
                    if isinstance(exc_or_none, Exception):
                        # Individual Holehe site probes break as sites change.
                        # Isolate and attribute them instead of surfacing bare,
                        # unlabelled exception text (e.g. "" or "'found'").
                        platform = _holehe_platform_name(fn)
                        detail = str(exc_or_none).strip() or type(exc_or_none).__name__
                        probe_failures.append(f"{platform}: {detail}")
                        continue
                    for r in out:
                        if r.get("rateLimit"):
                            rate_limited.append(r.get("name", "unknown"))
                        elif r.get("exists") is True:
                            findings.append(_make_finding(r))
                        elif r.get("exists") is False:
                            not_found_count += 1

                if idx < len(batches) - 1 and settings.request_delay_ms > 0:
                    await asyncio.sleep(settings.request_delay_ms / 1000.0)

        if rate_limited:
            errors.append(
                f"Rate-limited by {len(rate_limited)} platform(s): "
                + ", ".join(rate_limited)
            )
        if probe_failures:
            errors.append(
                f"{len(probe_failures)} platform probe(s) errored: "
                + ", ".join(probe_failures[:10])
                + (" ..." if len(probe_failures) > 10 else "")
            )

        # Per-site probe failures and rate limits are expected noise across 120+
        # platforms; the module ran meaningfully as long as any probe returned a
        # definitive result. Only a total washout is a real failure.
        had_results = bool(findings) or not_found_count > 0
        status = ModuleStatus.SUCCESS if had_results else ModuleStatus.FAILED

        result = ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "platforms_checked": len(funcs),
                "platforms_confirmed": len(findings),
                "platforms_rate_limited": len(rate_limited),
                "platforms_not_found": not_found_count,
                "holehe_version": _HOLEHE_VERSION,
            },
            errors=errors,
        )
        _write_cache(email, result)
        return result
