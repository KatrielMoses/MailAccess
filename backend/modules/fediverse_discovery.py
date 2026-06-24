from __future__ import annotations

import asyncio
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "fediverse_instances.json"
_CONCURRENCY = 5
_PER_INSTANCE_TIMEOUT = 5.0
_MAX_INSTANCES = 50


@lru_cache(maxsize=1)
def _load_instances() -> tuple[str, ...]:
    try:
        data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            logger.warning("fediverse_instances.json: expected list, got %s", type(data).__name__)
            return ()
        return tuple(s for x in data if (s := str(x).strip()))
    except FileNotFoundError:
        logger.warning("fediverse_instances.json not found at %s", _DATA_FILE)
        return ()
    except Exception as exc:
        logger.warning("fediverse_instances.json load failed: %s", exc)
        return ()


async def _probe_instance(
    client: httpx.AsyncClient,
    instance: str,
    localpart: str,
) -> dict[str, Any] | None:
    """Return a finding dict if profile exists, None for 404, raises on error."""
    url = f"https://{instance}/.well-known/webfinger"
    params = {"resource": f"acct:{localpart}@{instance}"}
    try:
        resp = await client.get(url, params=params, timeout=_PER_INSTANCE_TIMEOUT)
    except Exception as exc:
        logger.debug("fediverse probe %s: %s", instance, exc)
        raise

    if resp.status_code == 404:
        return None

    if resp.status_code != 200:
        logger.debug("fediverse probe %s: HTTP %s", instance, resp.status_code)
        raise httpx.HTTPStatusError(
            f"HTTP {resp.status_code}", request=resp.request, response=resp
        )

    try:
        data = resp.json()
    except Exception:
        return None

    self_link: str | None = None
    subject = data.get("subject")
    for link in data.get("links") or []:
        if isinstance(link, dict) and link.get("rel") == "self":
            self_link = link.get("href")
            break

    if not self_link:
        self_link = f"https://{instance}/@{localpart}"

    return {
        "platform": f"mastodon:{instance}",
        "profile_url": self_link,
        "username": f"{localpart}@{instance}",
        "confidence": "medium",
        "metadata": {
            "source": "fediverse_webfinger",
            "instance": instance,
            "localpart": localpart,
            "self_link": self_link,
            "subject": subject,
        },
    }


class FediverseDiscoveryModule(BaseModule):
    name = "fediverse_discovery"
    description = (
        "Probe popular Fediverse instances via WebFinger to find accounts matching "
        "the target email's local-part."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_fediverse_discovery or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "fediverse_discovery disabled — set ENABLE_FEDIVERSE_DISCOVERY=true to enable"
                ],
            )

        localpart = email.split("@")[0].lower().strip()
        if not localpart or len(localpart) > 30:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={
                    "instances_probed": 0,
                    "profiles_found": 0,
                    "instances_404": 0,
                    "instances_errored": 0,
                    "instances": [],
                    "localpart": localpart,
                },
            )

        instances = _load_instances()[:_MAX_INSTANCES]
        if not instances:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={
                    "instances_probed": 0,
                    "profiles_found": 0,
                    "instances_404": 0,
                    "instances_errored": 0,
                    "instances": [],
                    "localpart": localpart,
                },
            )

        sem = asyncio.Semaphore(_CONCURRENCY)
        instances_probed = 0

        async def _bounded_probe(
            client: httpx.AsyncClient, instance: str
        ) -> dict[str, Any] | None:
            nonlocal instances_probed
            async with sem:
                instances_probed += 1
                return await _probe_instance(client, instance, localpart)

        async with httpx.AsyncClient(timeout=_PER_INSTANCE_TIMEOUT) as client:
            tasks = [_bounded_probe(client, inst) for inst in instances]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[dict[str, Any]] = []
        instances_errored = 0
        instances_404 = 0
        for r in raw_results:
            if isinstance(r, BaseException):
                instances_errored += 1
            elif r is None:
                instances_404 += 1
            else:
                findings.append(r)

        if not findings and instances_probed > 0 and instances_errored == instances_probed:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["all instances errored — could not determine Fediverse presence"],
                metadata={
                    "instances_probed": instances_probed,
                    "profiles_found": 0,
                    "instances_404": instances_404,
                    "instances_errored": instances_errored,
                    "instances": list(instances),
                    "localpart": localpart,
                },
            )

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "instances_probed": instances_probed,
                "profiles_found": len(findings),
                "instances_404": instances_404,
                "instances_errored": instances_errored,
                "instances": list(instances),
                "localpart": localpart,
            },
        )
