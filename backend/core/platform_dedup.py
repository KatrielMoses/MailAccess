from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from ..modules.base import ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

KNOWN_SUBDOMAIN_PREFIXES: frozenset[str] = frozenset(
    {
        "www",
        "api",
        "m",
        "cdn",
        "static",
        "account",
        "secure",
        "login",
        "app",
        "blog",
        "community",
        "help",
        "support",
        "store",
        "shop",
        "forum",
        "dev",
        "stage",
        "test",
        "admin",
        "status",
    }
)

MODULE_SOURCE_TAGS: dict[str, str] = {
    "whatsmyname": "wmn",
    "blackbird_platforms": "wmn",
    "maigret_platforms": "maigret",
    "sherlock_platforms": "sherlock",
    "nexfil_platforms": "nexfil",
    "username_pivot": "pivot",
    "fediverse_discovery": "fediverse",
    "github_code_search": "github",
    "pastebin_search": "pastebin",
    "gravatar_lookup": "gravatar",
}

ENUMERATION_SOURCES = frozenset({"wmn", "maigret", "sherlock", "nexfil"})
DERIVATIVE_SOURCES = frozenset({"pivot", "fediverse"})

# Tiebreak priority when multiple modules report the same platform. Lower
# number wins. The most strictly vetted definitions (whatsmyname / wmn) are
# kept over the broadest-but-shallowest (maigret / sherlock / nexfil /
# blackbird) so the surviving finding reflects the most trustworthy source.
# Unknown sources sort to the end (priority 99) so they only win when no
# known source is in the tie.
SOURCE_PRIORITY: dict[str, int] = {
    "whatsmyname": 0,
    "wmn": 0,
    "holehe": 1,
    "user_scanner": 2,
    "maigret": 3,
    "maigret_platforms": 3,
    "sherlock": 4,
    "sherlock_platforms": 4,
    "nexfil": 4,
    "nexfil_platforms": 4,
    "blackbird": 4,
    "blackbird_platforms": 4,
}


def dedup_key(profile_url: str) -> str:
    parsed = urlparse(profile_url)
    host = parsed.hostname if parsed.netloc else parsed.path.split("/", 1)[0]
    host = (host or "").lower().removesuffix(".")
    if not host:
        return ""

    labels = host.split(".")
    while len(labels) > 1 and labels[0] in KNOWN_SUBDOMAIN_PREFIXES:
        labels.pop(0)
    return ".".join(labels)


def _normalize_source(finding: dict[str, Any], module_name: str) -> list[str]:
    sources = finding.get("sources")
    if isinstance(sources, list) and all(isinstance(source, str) for source in sources):
        return [source.strip().lower() for source in sources if source.strip()]

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        metadata_source = metadata.get("source")
        if isinstance(metadata_source, str) and metadata_source.strip():
            return [metadata_source.strip().lower()]

    normalized_module = module_name.lower()
    return [MODULE_SOURCE_TAGS.get(normalized_module, normalized_module)]


def _is_dual_confirmed(sources: set[str]) -> bool:
    enumeration_sources = sources & ENUMERATION_SOURCES
    if len(enumeration_sources) >= 2:
        return True
    return bool(enumeration_sources and sources & DERIVATIVE_SOURCES)


def deduplicate_platform_findings(results: dict[str, ModuleResult]) -> dict[str, int]:
    """Merge duplicate platform findings by normalized profile domain."""
    groups: dict[str, list[tuple[str, int, dict[str, Any]]]] = {}
    for module_name, result in results.items():
        if module_name not in MODULE_SOURCE_TAGS:
            continue
        for index, finding in enumerate(result.findings):
            if not isinstance(finding, dict):
                continue
            url = str(finding.get("profile_url") or "")
            key = dedup_key(url) if url else ""
            if key:
                groups.setdefault(key, []).append((module_name, index, finding))

    wmn_hits = len(results.get("whatsmyname", ModuleResult(status=ModuleStatus.SUCCESS)).findings)
    maigret_hits = len(
        results.get("maigret_platforms", ModuleResult(status=ModuleStatus.SUCCESS)).findings
    )
    dual_confirmed = 0
    remove: set[tuple[str, int]] = set()

    for key, rows in groups.items():
        sources = {
            source
            for module_name, _index, finding in rows
            for source in _normalize_source(finding, module_name)
        }
        if len(sources) > 2:
            logger.warning(
                "platform_dedup: %s has %d sources: %s",
                key,
                len(sources),
                sorted(sources),
            )
        if not _is_dual_confirmed(sources):
            continue

        dual_confirmed += 1
        rows = sorted(
            rows,
            key=lambda item: (
                SOURCE_PRIORITY.get(item[0], 99),
                item[0],
                item[1],
            ),
        )
        keep_module, keep_index, keep_finding = rows[0]
        alternate_urls = []
        for module_name, index, finding in rows[1:]:
            remove.add((module_name, index))
            url = finding.get("profile_url")
            if isinstance(url, str) and url and url != keep_finding.get("profile_url"):
                alternate_urls.append(url)
        metadata = (
            deepcopy(keep_finding.get("metadata"))
            if isinstance(keep_finding.get("metadata"), dict)
            else {}
        )
        metadata["dual_confirmed"] = True
        if alternate_urls:
            metadata["alternate_urls"] = sorted(set(alternate_urls))
        keep_finding["metadata"] = metadata
        keep_finding["sources"] = sorted(sources)
        keep_finding["confidence"] = "high"
        remove.discard((keep_module, keep_index))

    for module_name, result in results.items():
        if not result.findings:
            continue
        result.findings = [
            finding
            for index, finding in enumerate(result.findings)
            if (module_name, index) not in remove
        ]

    unique_platforms = len(
        {
            dedup_key(str(finding.get("profile_url") or ""))
            for result in results.values()
            for finding in result.findings
            if isinstance(finding, dict) and finding.get("profile_url")
        }
    )

    stats = {
        "wmn_hits": wmn_hits,
        "maigret_hits": maigret_hits,
        "dual_confirmed": dual_confirmed,
        "unique_platforms": unique_platforms,
    }
    for name in ("whatsmyname", "maigret_platforms"):
        result = results.get(name)
        if result is not None:
            result.metadata = {**(result.metadata or {}), **stats}
    return stats
