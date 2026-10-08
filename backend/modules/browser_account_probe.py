"""Headless-browser email-existence probes (email-first + forgot-password oracles).

Complements the HTTP ``account_discovery`` module for platforms whose existence
signal only appears in a JS-driven flow. Uses Playwright (optional dep). Inert
unless ``mailaccess[browser]`` is installed, so default installs are unaffected.

Safety:
* email-first oracles send NO email — on by default (``enable_browser_probes``).
* forgot-password oracles EMAIL the subject — run ONLY when
  ``enable_forgot_password_probes`` is set (see config), and every such run
  reports how many reset emails it triggered.
"""
from __future__ import annotations

import logging
from typing import Any

from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)


class BrowserAccountProbeModule(BaseModule):
    name = "browser_account_probe"
    email_linked = True
    description = (
        "Headless-browser email-existence oracles (email-first login + "
        "forgot-password) for platforms with JS-only signals."
    )

    async def run(self, email: str, *, force: bool = False, **_: Any) -> ModuleResult:
        if not getattr(settings, "enable_browser_probes", True):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_BROWSER_PROBES=true to run browser oracles"],
            )

        from ..core.browser_oracle import (
            ORACLES, probe_all, xenforo_browser_oracles,
        )

        allow_intrusive = bool(
            getattr(settings, "enable_forgot_password_probes", False)
        )
        oracles = [o for o in ORACLES if allow_intrusive or not o.intrusive]
        # The 131 XenForo login-error oracles are heavy (one browser page each), so
        # they're opt-in — enable for a thorough sweep that beats Cloudflare.
        if getattr(settings, "enable_browser_xenforo", False):
            oracles += xenforo_browser_oracles()
        if not oracles:
            return ModuleResult(status=ModuleStatus.SKIPPED,
                                errors=["No browser oracles enabled"])

        try:
            results = await probe_all(email, oracles)
        except RuntimeError as exc:
            # Playwright / browser not installed — skip, don't fail.
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=[str(exc)])
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(status=ModuleStatus.FAILED,
                                errors=[f"browser probe error: {exc}"])

        findings: list[dict[str, Any]] = []
        confirmed = not_found = inconclusive = errored = 0
        intrusive_emails_sent = 0
        for o in oracles:
            verdict = results.get(o.domain, "inconclusive")
            if verdict == "exists":
                confirmed += 1
                if o.intrusive:
                    intrusive_emails_sent += 1
                findings.append({
                    "platform": o.domain,
                    "url": o.url,
                    # A browser oracle is a single, uncorroborated signal — surface
                    # it as an unverified lead, never a confirmed account.
                    "confidence": "medium",
                    "verification": "unverified",
                    "metadata": {"flow": o.flow, "method": "browser-oracle",
                                 "intrusive": o.intrusive},
                })
            elif verdict == "not_exists":
                not_found += 1
            elif verdict == "error":
                errored += 1
            else:
                inconclusive += 1

        errors: list[str] = []
        if intrusive_emails_sent:
            errors.append(
                f"⚠ INTRUSIVE: forgot-password probes emailed the subject a "
                f"password-reset on {intrusive_emails_sent} platform(s)."
            )

        coverage_complete = (errored == 0 and inconclusive == 0)
        if findings:
            status = ModuleStatus.SUCCESS if coverage_complete else ModuleStatus.PARTIAL
        elif not_found > 0 and coverage_complete:
            status = ModuleStatus.SUCCESS_EMPTY
        else:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "oracles_run": len(oracles),
                "confirmed": confirmed,
                "not_found": not_found,
                "inconclusive": inconclusive,
                "errored": errored,
                "intrusive_emails_sent": intrusive_emails_sent,
                "engine": "browser-oracle/1.0",
            },
            errors=errors,
        )
