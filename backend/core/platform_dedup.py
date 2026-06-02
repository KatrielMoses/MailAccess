from __future__ import annotations

from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from ..modules.base import ModuleResult, ModuleStatus


def dedup_key(profile_url: str) -> str:
    parsed = urlparse(profile_url)
    host = (parsed.netloc or parsed.path.split("/", 1)[0]).lower()
    host = host.removeprefix("www.")
    if host.startswith("api."):
        return host[4:]
    return host


def deduplicate_platform_findings(results: dict[str, ModuleResult]) -> dict[str, int]:
    """Merge duplicate WMN/Maigret platform findings by profile domain."""
    groups: dict[str, list[tuple[str, int, dict[str, Any]]]] = {}
    for module_name, result in results.items():
        if module_name not in {"whatsmyname", "maigret_platforms", "username_pivot"}:
            continue
        for index, finding in enumerate(result.findings):
            if not isinstance(finding, dict):
                continue
            url = str(finding.get("profile_url") or "")
            key = dedup_key(url) if url else ""
            if key:
                groups.setdefault(key, []).append((module_name, index, finding))

    wmn_hits = len(results.get("whatsmyname", ModuleResult(status=ModuleStatus.SUCCESS)).findings)
    maigret_hits = len(results.get("maigret_platforms", ModuleResult(status=ModuleStatus.SUCCESS)).findings)
    dual_confirmed = 0
    remove: set[tuple[str, int]] = set()

    for _key, rows in groups.items():
        sources = {module for module, _index, finding in rows for module in _finding_sources(module, finding)}
        if not {"wmn", "maigret"}.issubset(sources):
            continue
        dual_confirmed += 1
        rows = sorted(rows, key=lambda item: (item[0] != "whatsmyname", item[0], item[1]))
        keep_module, keep_index, keep_finding = rows[0]
        alternate_urls = []
        for module_name, index, finding in rows[1:]:
            remove.add((module_name, index))
            url = finding.get("profile_url")
            if isinstance(url, str) and url and url != keep_finding.get("profile_url"):
                alternate_urls.append(url)
        metadata = deepcopy(keep_finding.get("metadata")) if isinstance(keep_finding.get("metadata"), dict) else {}
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

    unique_platforms = len({
        dedup_key(str(finding.get("profile_url") or ""))
        for result in results.values()
        for finding in result.findings
        if isinstance(finding, dict) and finding.get("profile_url")
    })

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


def _finding_sources(module_name: str, finding: dict[str, Any]) -> list[str]:
    sources = finding.get("sources")
    if isinstance(sources, list):
        normalized = [str(src).lower() for src in sources if str(src).strip()]
    else:
        normalized = []
    meta = finding.get("metadata")
    if isinstance(meta, dict) and meta.get("source"):
        normalized.append(str(meta["source"]).lower())
    normalized.append("maigret" if module_name == "maigret_platforms" else "wmn")
    return normalized
