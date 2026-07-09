from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PersonName:
    first_name: str | None
    last_name: str | None
    full_name: str
    confidence: float
    source_module: str


_GENERIC_NAMES = frozenset({"admin", "administrator", "user", "info"})
_INVALID_NAME_RE = re.compile(r"[@.\d]")
_SPACE_RE = re.compile(r"\s+")


def _clean_name(value: str) -> str:
    return _SPACE_RE.sub(" ", value.strip())


def _is_valid_name(value: str) -> bool:
    name = _clean_name(value)
    if len(name.replace(" ", "")) < 4:
        return False
    if _INVALID_NAME_RE.search(name):
        return False
    parts = name.split(" ")
    if len(parts) < 2:
        return False
    if any(part.lower() in _GENERIC_NAMES for part in parts):
        return False
    return True


def _split_name(value: str) -> tuple[str | None, str | None, str]:
    full_name = _clean_name(value)
    parts = full_name.split(" ")
    first = parts[0] if parts else None
    last = parts[-1] if len(parts) > 1 else None
    return first, last, full_name


def _normalized(value: str) -> str:
    return _clean_name(value).lower()


def _iter_module_payloads(collected_findings: Any) -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(collected_findings, dict):
        items = collected_findings.items()
    else:
        items = enumerate(collected_findings or [])

    for key, result in items:
        module_name = str(key)
        if isinstance(result, dict):
            module_name = str(
                result.get("module_name") or result.get("module") or module_name
            )
            findings = result.get("findings")
            if isinstance(findings, list):
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    yield module_name, finding
                    metadata = finding.get("metadata")
                    if isinstance(metadata, dict):
                        yield module_name, metadata
            finding_payload = result.get("data", result)
            if isinstance(finding_payload, dict):
                yield module_name, finding_payload
                metadata = finding_payload.get("metadata")
                if isinstance(metadata, dict):
                    yield module_name, metadata
            metadata = result.get("metadata") or result.get("run_metadata")
            if isinstance(metadata, dict):
                yield module_name, metadata
            continue

        module_name = getattr(result, "name", module_name)
        metadata = getattr(result, "metadata", None)
        if isinstance(metadata, dict):
            yield module_name, metadata

        findings = getattr(result, "findings", [])
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            yield module_name, finding
            finding_metadata = finding.get("metadata")
            if isinstance(finding_metadata, dict):
                yield module_name, finding_metadata


def _candidate_values(module_name: str, payload: dict[str, Any]) -> Iterable[tuple[str, float]]:
    module = module_name.lower()

    if module == "ghunt":
        value = payload.get("display_name")
        if isinstance(value, str):
            yield value, 0.95
        return

    if module == "gravatar":
        value = payload.get("display_name")
        if isinstance(value, str):
            yield value, 0.90
        return

    if module in {"hibp", "haveibeenpwned", "breachdirectory", "breach_deep"}:
        value = payload.get("registrant_name")
        if isinstance(value, str):
            yield value, 0.85
        return

    if module == "whois_lookup":
        value = payload.get("registrant_name")
        if isinstance(value, str):
            yield value, 0.80
        return

    if module in {
        "social",
        "social_links",
        "whatsmyname",
        "account_discovery",
        "user_scanner",
        "username_pivot",
        "google_search",
    }:
        for key in ("display_name", "full_name", "real_name", "name"):
            value = payload.get(key)
            if isinstance(value, str):
                yield value, 0.70
        return

    if module == "emailrep":
        value = payload.get("name")
        if isinstance(value, str):
            yield value, 0.65


def extract_names(collected_findings: Any) -> list[PersonName]:
    """Extract up to three likely real names from collected module findings."""
    by_name: dict[str, PersonName] = {}

    for module_name, payload in _iter_module_payloads(collected_findings):
        for raw_name, confidence in _candidate_values(module_name, payload):
            if not _is_valid_name(raw_name):
                continue
            first, last, full_name = _split_name(raw_name)
            key = _normalized(full_name)
            candidate = PersonName(
                first_name=first,
                last_name=last,
                full_name=full_name,
                confidence=confidence,
                source_module=module_name,
            )
            existing = by_name.get(key)
            if existing is None or candidate.confidence > existing.confidence:
                by_name[key] = candidate

    return sorted(
        by_name.values(),
        key=lambda item: (-item.confidence, item.full_name.lower()),
    )[:3]
