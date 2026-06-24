from __future__ import annotations

import logging
import time
from typing import Any

from ..config import settings
from ..core.intelx_client import (
    IntelxAuthError,
    IntelxClient,
    IntelxCreditsError,
    IntelxError,
    IntelxRateLimitError,
    IntelxRecord,
    IntelxTimeoutError,
)
from ..core.platform_health import get_health_db
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_MEDIA_LABELS: dict[int, str] = {
    1: "paste",
    2: "paste_user",
    3: "forum",
    4: "forum_board",
    5: "forum_thread",
    6: "forum_post",
    7: "forum_user",
    13: "tweet",
    14: "url",
    15: "pdf",
    16: "word",
    17: "excel",
    18: "powerpoint",
    19: "picture",
    20: "audio",
    21: "video",
    22: "container",
    23: "html",
    24: "text",
}


def _media_label(media: int) -> str:
    return _MEDIA_LABELS.get(media, f"unknown({media})")


class IntelxLookupModule(BaseModule):
    name = "intelx_lookup"
    description = (
        "Email leak/paste/darknet correlation via IntelligenceX "
        "(https://intelx.io). Requires a free-tier API key — set INTELX_API_KEY "
        "or configure intelx_api_key in settings. Free tier has rate limits; "
        "commercial use requires a paid license."
    )
    requires_key = True
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_intelx_lookup or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "intelx_lookup disabled — set ENABLE_INTELX_LOOKUP=true "
                    "to enable email leak correlation via IntelligenceX"
                ],
            )

        api_key = settings.intelx_api_key or _get_env("INTELX_KEY")
        if not api_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "intelx_lookup requires an API key — sign up at "
                    "https://intelx.io/signup and set INTELX_API_KEY or INTELX_KEY, "
                    "or configure intelx_api_key"
                ],
            )

        from ..core.disposable_domains import is_disposable_email

        if is_disposable_email(email):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["intelx_lookup skipped — disposable email domain"],
            )

        base_url = settings.intelx_base_url or _get_env("INTELX_BASE_URL") or "https://2.intelx.io"
        buckets = settings.intelx_buckets or ["leaks.public", "pastes"]
        max_results = settings.intelx_max_results or 50
        health = get_health_db()
        if not await health.should_probe_async("intelx:search"):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["intelx_lookup skipped — health DB marked search as unhealthy"],
            )

        client = IntelxClient(api_key=api_key, base_url=base_url)
        started_at = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        records_fetched = 0
        try:
            records = await client.search(
                term=email,
                buckets=buckets,
                max_results=max_results,
            )
            records_fetched = len(records)
            findings = [_record_to_finding(record, email) for record in records]
            await health.record_probe_async(
                platform="intelx:search",
                domain=None,
                outcome="hit" if records else "miss",
                latency_ms=int((time.monotonic() - started_at) * 1000),
                content_length=records_fetched,
            )
        except IntelxAuthError as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"intelx_lookup: invalid API key — {exc}"],
            )
        except IntelxCreditsError as exc:
            errors.append(f"intelx_lookup: out of credits — {exc}")
        except IntelxRateLimitError as exc:
            errors.append(f"intelx_lookup: rate limited after retries — {exc}")
        except IntelxTimeoutError as exc:
            errors.append(f"intelx_lookup: search timed out — {exc}")
        except IntelxError as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"intelx_lookup: API error — {exc}"],
            )
        finally:
            await client.aclose()

        return ModuleResult(
            status=ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "source": "intelx",
                "selector": email,
                "buckets": buckets,
                "records_fetched": records_fetched,
                "max_results_cap": max_results,
                "findings_count": len(findings),
            },
            errors=errors,
        )


def _record_to_finding(record: IntelxRecord, email: str) -> dict[str, Any]:
    confidence = "high"
    fp_warnings: list[str] = []
    local = email.split("@", 1)[0] if "@" in email else ""

    from ..core.common_names import is_common_username

    if local and is_common_username(local):
        confidence = "low"
        fp_warnings.append("common_username_no_corroboration")

    finding: dict[str, Any] = {
        "platform": f"intelx:{record.bucket}",
        "profile_url": f"https://intelx.io/?s={record.systemid}",
        "username": None,
        "confidence": confidence,
        "metadata": {
            "source": "intelx",
            "bucket": record.bucket,
            "media": record.media,
            "media_label": _media_label(record.media),
            "name": record.name,
            "date": record.date,
            "xscore": record.xscore,
            "systemid": record.systemid,
            "storageid": record.storageid,
            "accesslevel": record.accesslevel,
            "selector": email,
        },
    }
    if fp_warnings:
        finding["metadata"]["fp_warnings"] = fp_warnings
    return finding


def _get_env(name: str) -> str | None:
    import os

    return os.environ.get(name)
