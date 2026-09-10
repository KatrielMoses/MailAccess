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
    "username_platforms": "username_platforms",
    "username_pivot": "pivot",
    "fediverse_discovery": "fediverse",
    "github_code_search": "github",
    "pastebin_search": "pastebin",
    "gravatar_lookup": "gravatar",
}

# The unified username-platform sweep is the single enumeration source; a platform
# is dual-confirmed when a derivative source (pivot / fediverse) independently
# corroborates the same profile domain.
ENUMERATION_SOURCES = frozenset({"username_platforms"})
DERIVATIVE_SOURCES = frozenset({"pivot", "fediverse"})

# Tiebreak priority when multiple modules report the same platform. Lower number
# wins; unknown sources sort to the end (priority 99) so they only win when no
# known source is in the tie.
SOURCE_PRIORITY: dict[str, int] = {
    "username_platforms": 3,
}


def dedup_key(profile_url: str) -> str:
    """Normalized registrable host (subdomain prefixes stripped). Platform-level key."""
    parsed = urlparse(profile_url)
    host = parsed.hostname if parsed.netloc else parsed.path.split("/", 1)[0]
    host = (host or "").lower().removesuffix(".")
    if not host:
        return ""

    labels = host.split(".")
    while len(labels) > 1 and labels[0] in KNOWN_SUBDOMAIN_PREFIXES:
        labels.pop(0)
    return ".".join(labels)


def account_key(finding: dict[str, Any]) -> str:
    """Canonical ACCOUNT identity — the correct merge key.

    Two profiles on the *same* host but for *different* accounts
    (``example.com/alice`` vs ``example.com/bob``) are genuinely different
    identities and must never be merged into one. Keying on the host alone (as
    ``dedup_key`` does) collapsed them and dual-confirmed a false identity while
    erasing the other account's evidence. Identity is therefore
    ``(normalized host, account handle)``, where the handle is the finding's
    ``username`` when present (robust across mirror URLs of the same account) and
    otherwise the profile URL's path. Falls back to the bare host only when neither
    a handle nor a path exists.
    """
    url = str(finding.get("profile_url") or "")
    host = dedup_key(url)
    if not host:
        return ""
    username = finding.get("username")
    if isinstance(username, str) and username.strip():
        ident = username.strip().lower().lstrip("@")
        if ident:
            return f"{host}/{ident}"
    path = urlparse(url).path.strip("/").lower()
    if path:
        return f"{host}/{path}"
    return host


def _normalize_source(finding: dict[str, Any], module_name: str) -> list[str]:
    sources = finding.get("sources")
    if isinstance(sources, list) and all(isinstance(source, str) for source in sources):
        return [source.strip().lower() for source in sources if source.strip()]

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        metadata_source = metadata.get("source")
        if isinstance(metadata_source, str) and metadata_source.strip():
            raw = metadata_source.strip().lower()
            # R7 (S3): the LIVE module writes its own name as the source label
            # (e.g. ``username_pivot``), but the corroboration classes are keyed
            # by the canonical TAG (``pivot``). Normalize a module-name label
            # through MODULE_SOURCE_TAGS so the live path classifies exactly like
            # the fixtures (which pass the tag directly) — a pivot is derivative,
            # so it can't act as an independent enumeration confirmation.
            return [MODULE_SOURCE_TAGS.get(raw, raw)]

    normalized_module = module_name.lower()
    return [MODULE_SOURCE_TAGS.get(normalized_module, normalized_module)]


def _is_dual_confirmed(sources: set[str]) -> bool:
    enumeration_sources = sources & ENUMERATION_SOURCES
    if len(enumeration_sources) >= 2:
        return True
    return bool(enumeration_sources and sources & DERIVATIVE_SOURCES)


def deduplicate_platform_findings(results: dict[str, ModuleResult]) -> dict[str, int]:
    """Merge duplicate observations of the *same account*, keeping distinct accounts apart.

    Grouping is by :func:`account_key` (host + handle), so two different accounts on
    one host are never collapsed. Only genuine duplicate observations of a single
    account merge, and when they do the merged sources/URLs/warnings are preserved,
    not erased.
    """
    groups: dict[str, list[tuple[str, int, dict[str, Any]]]] = {}
    for module_name, result in results.items():
        if module_name not in MODULE_SOURCE_TAGS:
            continue
        for index, finding in enumerate(result.findings):
            if not isinstance(finding, dict):
                continue
            key = account_key(finding)
            if key:
                groups.setdefault(key, []).append((module_name, index, finding))

    username_hits = len(
        results.get("username_platforms", ModuleResult(status=ModuleStatus.SUCCESS)).findings
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
        merged_warnings: list[str] = []
        for module_name, index, finding in rows[1:]:
            remove.add((module_name, index))
            url = finding.get("profile_url")
            if isinstance(url, str) and url and url != keep_finding.get("profile_url"):
                alternate_urls.append(url)
            # Preserve the merged observation's false-positive warnings — dropping a
            # loser must never silently erase its caveats.
            loser_meta = finding.get("metadata")
            if isinstance(loser_meta, dict):
                warns = loser_meta.get("fp_warnings")
                if isinstance(warns, list):
                    merged_warnings.extend(str(w) for w in warns)
        metadata = (
            deepcopy(keep_finding.get("metadata"))
            if isinstance(keep_finding.get("metadata"), dict)
            else {}
        )
        metadata["dual_confirmed"] = True
        # RC1 (Output-Trust): dual confirmation is INDEPENDENT corroboration — the
        # account is no longer a bare speculative localpart guess. Promote its
        # verification so downstream consumers (graph/brief/score) may treat it as
        # a real account. An open false-positive caveat still blocks the confidence
        # promotion below (handled by ``all_warnings``).
        metadata["verification"] = "confirmed"
        metadata["speculative"] = False
        if alternate_urls:
            metadata["alternate_urls"] = sorted(set(alternate_urls))
        # Union all fp_warnings across the merged observations so a low-confidence
        # caveat on any observation survives the merge.
        existing_warnings = metadata.get("fp_warnings")
        all_warnings = sorted(
            {str(w) for w in (existing_warnings or []) if isinstance(existing_warnings, list)}
            | set(merged_warnings)
        )
        if all_warnings:
            metadata["fp_warnings"] = all_warnings
        keep_finding["metadata"] = metadata
        keep_finding["sources"] = sorted(sources)
        # Dual-confirmation raises confidence to "high" only when no unresolved
        # false-positive warning is outstanding; an open caveat (common username,
        # disposable domain, …) must not be overridden by corroboration alone.
        if not all_warnings:
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
        "username_hits": username_hits,
        "dual_confirmed": dual_confirmed,
        "unique_platforms": unique_platforms,
    }
    result = results.get("username_platforms")
    if result is not None:
        result.metadata = {**(result.metadata or {}), **stats}
    return stats
