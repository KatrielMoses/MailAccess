from __future__ import annotations

import asyncio
import logging
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)


def _user_scanner_version() -> str:
    try:
        return version("user-scanner")
    except PackageNotFoundError:
        return "unknown"


def _scan_email_sync(email: str) -> list[dict[str, Any]]:
    """Run user-scanner email sweep (sync). Uses scan_email() when exported."""
    try:
        from user_scanner import scan_email

        return scan_email(email)
    except ImportError:
        pass

    import asyncio

    from user_scanner.core import engine as us_engine

    def _run() -> list[dict[str, Any]]:
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(us_engine.check_all(email, is_email=True))
        finally:
            loop.close()
        return [r.to_dict() for r in results]

    return _run()


class UserScannerModule(BaseModule):
    name = "user_scanner"
    description = (
        "Probe 205+ platforms for email registration via user-scanner. "
        "Enable via ENABLE_USER_SCANNER=true."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        if not settings.enable_user_scanner:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_USER_SCANNER=true to run this module"],
            )

        try:
            raw = await asyncio.to_thread(_scan_email_sync, email)
        except Exception as exc:
            _LOG.exception("user_scanner failed for %s", email)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"user-scanner error: {exc}"],
            )

        registered = [r for r in raw if r.get("status") == "Registered"]
        not_registered = sum(1 for r in raw if r.get("status") == "Not Registered")

        findings: list[dict[str, Any]] = []
        for result in registered:
            metadata: dict[str, Any] = {
                "category": result.get("category", ""),
                "reason": result.get("reason", ""),
                "source": "user_scanner",
            }
            # FIX 5A: preserve the per-platform ``extras`` (bio,
            # display_name, avatar_url, location, join_date,
            # follower_count, website, ...). These are already fetched
            # by user-scanner at zero extra network cost; previously the
            # whole dict was discarded.
            extras = result.get("extras")
            if extras:
                metadata["profile_extras"] = extras
            findings.append({
                "platform": result.get("site_name", "unknown"),
                "profile_url": result.get("url"),
                "metadata": metadata,
                "confidence": "high",
            })

        status = ModuleStatus.SUCCESS
        errors: list[str] = []
        error_count = sum(1 for r in raw if r.get("status") == "Error")
        if error_count and not findings:
            status = ModuleStatus.PARTIAL if not_registered else ModuleStatus.FAILED
        elif error_count:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "platforms_checked": len(raw),
                "platforms_confirmed": len(findings),
                "platforms_not_registered": not_registered,
                "user_scanner_version": _user_scanner_version(),
            },
            errors=errors,
        )
