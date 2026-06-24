from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

_ALIAS_PATH = Path(__file__).resolve().parents[2] / "data" / "breach_aliases.json"
_BREACH_MODULES = frozenset({"hibp", "breachdirectory", "breach_deep", "xposedornot"})
logger = logging.getLogger(__name__)

# Real breach names settle in 1-2 passes; 10 keeps adversarial inputs bounded.
_MAX_STRIP_ITERATIONS = 10

_TRANSPORT_KEYS = frozenset(
    {
        "module_name",
        "platform",
        "source",
        "url",
        "profile_url",
        "link",
        "confidence",
        "severity",
        "metadata",
    }
)

_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_YEAR_SUFFIX_RE = re.compile(r"(?:[\s._-]*\(?((?:19|20)\d{2})\)?)+$", re.IGNORECASE)
_GENERIC_SUFFIX_RE = re.compile(
    r"(?:[\s._-]*(?:data\s+)?(?:breaches?|breach|leaks?|leak|dump(?:ed)?|"
    r"incidents?|compromise|exposure|collections?|lists?|logs?|threat(?:\s+data)?|dataset))+?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BreachIdentity:
    canonical_id: str
    canonical_name: str
    matched_alias: str | None = None


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _normalize_key(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _extract_host(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    text = re.sub(r"\s+", "", text)
    if "://" in text:
        from urllib.parse import urlparse

        parsed = urlparse(text)
        host = parsed.netloc or parsed.path.split("/", 1)[0]
        if host:
            return host
        return None
    if "/" in text:
        host = text.split("/", 1)[0]
        if host:
            return host
    if "." in text and " " not in text:
        return text
    return None


def _strip_noise(value: str) -> str:
    text = value.strip()
    if not text:
        return text

    current = text
    for _ in range(_MAX_STRIP_ITERATIONS):
        next_value = _YEAR_SUFFIX_RE.sub("", current).strip(" ._-()[]{}")
        if next_value != current:
            current = next_value
            continue
        next_value = _GENERIC_SUFFIX_RE.sub("", current).strip(" ._-()[]{}")
        if next_value != current:
            current = next_value
            continue
        break
    return current.strip()


def _candidate_keys(value: Any) -> set[str]:
    if value is None:
        return set()
    text = str(value).strip()
    if not text:
        return set()

    candidates: set[str] = set()
    for variant in (text, _strip_noise(text)):
        if variant:
            candidates.add(_normalize_key(variant))

    host = _extract_host(text)
    if host:
        for variant in (host, _strip_noise(host)):
            if variant:
                candidates.add(_normalize_key(variant))

    return {candidate for candidate in candidates if candidate}


def _merge_lists(left: list[Any], right: list[Any]) -> list[Any]:
    merged: list[Any] = []
    for item in left + right:
        if any(existing == item for existing in merged):
            continue
        merged.append(deepcopy(item))
    return merged


def _merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = deepcopy(left)
    for key, value in right.items():
        if _is_empty(value):
            continue
        if key not in merged or _is_empty(merged[key]):
            merged[key] = deepcopy(value)
            continue
        existing = merged[key]
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _merge_dicts(existing, value)
        elif isinstance(existing, list) and isinstance(value, list):
            merged[key] = _merge_lists(existing, value)
        elif isinstance(existing, list):
            merged[key] = _merge_lists(existing, [value])
        elif isinstance(value, list):
            merged[key] = _merge_lists([existing], value)
        # Keep the richer existing scalar on conflicts.
    return merged


def _detail_score(value: Any) -> int:
    if _is_empty(value):
        return 0
    if isinstance(value, dict):
        return sum(_detail_score(item) for item in value.values())
    if isinstance(value, list):
        return sum(_detail_score(item) for item in value)
    return 1


def _normalized_detail(payload: dict[str, Any]) -> dict[str, Any]:
    detail: dict[str, Any] = {}
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        detail = _merge_dicts(detail, metadata)

    for key, value in payload.items():
        if key in _TRANSPORT_KEYS or key == "metadata":
            continue
        if _is_empty(value):
            continue
        if key in detail and isinstance(detail[key], dict) and isinstance(value, dict):
            detail[key] = _merge_dicts(detail[key], value)
        elif key in detail and isinstance(detail[key], list) and isinstance(value, list):
            detail[key] = _merge_lists(detail[key], value)
        elif key not in detail or _is_empty(detail[key]):
            detail[key] = deepcopy(value)
    return detail


def _breach_candidates(payload: dict[str, Any]) -> list[Any]:
    metadata = payload.get("metadata")
    meta = metadata if isinstance(metadata, dict) else {}

    fields = [
        meta.get("breach_name"),
        meta.get("breach_id"),
        meta.get("breach_source"),
        meta.get("name"),
        meta.get("title"),
        meta.get("site"),
        meta.get("domain"),
        payload.get("breach_name"),
        payload.get("breach_id"),
        payload.get("breach_source"),
        payload.get("name"),
        payload.get("title"),
        payload.get("site"),
        payload.get("domain"),
    ]
    return [value for value in fields if isinstance(value, (str, int, float))]


@lru_cache(maxsize=1)
def _load_catalog() -> tuple[dict[str, str], dict[str, str]]:
    if not _ALIAS_PATH.exists():
        logger.warning(
            "breach alias catalog missing; normalization running in degraded mode: %s", _ALIAS_PATH
        )
        return {}, {}

    raw = json.loads(_ALIAS_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("breach alias catalog must be a list")

    canonical_name_by_id: dict[str, str] = {}
    alias_to_id: dict[str, str] = {}

    domains: dict[str, int] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip().lower()
        if domain:
            domains[domain] = domains.get(domain, 0) + 1

    for item in raw:
        if not isinstance(item, dict):
            continue
        canonical_id = _normalize_key(
            str(item.get("canonical_id") or item.get("name") or item.get("canonical_name") or "")
        )
        if not canonical_id:
            continue

        canonical_name = str(
            item.get("canonical_name") or item.get("title") or item.get("name") or ""
        ).strip()
        if not canonical_name:
            canonical_name = canonical_id
        canonical_name_by_id[canonical_id] = canonical_name

        aliases: set[str] = set()
        for candidate in (
            item.get("canonical_name"),
            item.get("name"),
            item.get("title"),
        ):
            aliases.update(_candidate_keys(candidate))

        raw_aliases = item.get("aliases")
        if isinstance(raw_aliases, list):
            for alias in raw_aliases:
                aliases.update(_candidate_keys(alias))

        domain = str(item.get("domain") or "").strip().lower()
        if domain and domains.get(domain, 0) == 1:
            aliases.update(_candidate_keys(domain))

        for alias in aliases:
            alias_to_id[alias] = canonical_id

    if not alias_to_id:
        logger.warning(
            "breach alias catalog is empty or invalid; normalization running in degraded mode: %s",
            _ALIAS_PATH,
        )

    return alias_to_id, canonical_name_by_id


def resolve_breach_identity(
    payload: dict[str, Any], module_name: str | None = None
) -> BreachIdentity | None:
    """Return the canonical identity for a breach finding, or None if it is not breach-related."""
    if not isinstance(payload, dict):
        return None

    if payload.get("source") == "breach_confirmed":
        return None
    if module_name and module_name.lower() == "hudson_rock":
        return None

    # Only process findings with at least one breach-specific indicator.
    # "name" is included because modules like HIBP store breach names under
    # the generic "name" field in metadata rather than "breach_name".
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    _has_breach_indicator = any(
        bool(src.get(k))
        for src in (payload, meta)
        for k in ("breach_name", "breach_id", "breach_source", "name")
    )
    if not _has_breach_indicator:
        return None

    alias_to_id, canonical_name_by_id = _load_catalog()
    candidates = _breach_candidates(payload)

    for candidate in candidates:
        for key in _candidate_keys(candidate):
            canonical_id = alias_to_id.get(key)
            if canonical_id:
                return BreachIdentity(
                    canonical_id=canonical_id,
                    canonical_name=canonical_name_by_id.get(canonical_id, str(candidate).strip()),
                    matched_alias=str(candidate),
                )

    # Fall back to a stable normalized key so unknown breaches still dedupe cleanly
    # across sources when they use the same breach name.
    fallback_value = next(
        (str(candidate).strip() for candidate in candidates if str(candidate).strip()), ""
    )
    if not fallback_value:
        return None

    cleaned = _strip_noise(fallback_value) or fallback_value
    canonical_id = _normalize_key(cleaned)
    if not canonical_id:
        return None

    return BreachIdentity(
        canonical_id=canonical_id,
        canonical_name=cleaned,
        matched_alias=fallback_value,
    )


def _confidence_rank(value: Any) -> int:
    return _CONFIDENCE_RANK.get(str(value).strip().lower(), 0)


def _severity_rank(value: Any) -> int:
    return _SEVERITY_RANK.get(str(value).strip().lower(), 0)


def _top_level_detail(payload: dict[str, Any]) -> dict[str, Any]:
    detail = _normalized_detail(payload)
    # Keep a few transport-ish fields in the merged metadata when they carry
    # useful breach context.
    for key in ("platform", "source", "url", "profile_url", "link", "confidence", "severity"):
        value = payload.get(key)
        if not _is_empty(value):
            detail.setdefault(key, deepcopy(value))
    return detail


def _best_url(payload: dict[str, Any]) -> str | None:
    for key in ("url", "profile_url", "link"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    meta = payload.get("metadata")
    if isinstance(meta, dict):
        for key in ("reference_url", "domain"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                if key == "domain" and "://" not in value:
                    return f"https://{value.strip().lstrip('/')}"
                return value.strip()
    return None


def _best_breach_name(payload: dict[str, Any], identity: BreachIdentity) -> str:
    meta = payload.get("metadata")
    if isinstance(meta, dict):
        for key in ("breach_name", "name", "title"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    for key in ("breach_name", "name", "title"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return identity.canonical_name


def _merge_group(rows: list[dict[str, Any]], identity: BreachIdentity) -> dict[str, Any]:
    ranked: list[
        tuple[tuple[int, int, int, int], dict[str, Any], dict[str, Any], str, str | None]
    ] = []
    ordered_sources: list[str] = []
    ordered_ids: list[str] = []
    source_breach_names: list[str] = []
    for index, row in enumerate(rows):
        payload = row.get("data") if isinstance(row.get("data"), dict) else row
        if not isinstance(payload, dict):
            payload = {}
        module_name = str(row.get("module_name") or payload.get("source") or "").strip()
        detail = _top_level_detail(payload)
        source_breach_name = _best_breach_name(payload, identity)
        if source_breach_name and source_breach_name not in source_breach_names:
            source_breach_names.append(source_breach_name)
        confidence = _confidence_rank(
            row.get("data", {}).get("confidence")
            if isinstance(row.get("data"), dict)
            else payload.get("confidence")
        )
        severity = _severity_rank(
            row.get("data", {}).get("severity")
            if isinstance(row.get("data"), dict)
            else payload.get("severity")
        )
        score = (severity, confidence, _detail_score(detail), -index)
        ranked.append((score, row, payload, module_name, _best_url(payload)))
        if module_name and module_name not in ordered_sources:
            ordered_sources.append(module_name)
        existing_sources = payload.get("sources")
        if isinstance(existing_sources, list):
            for src in existing_sources:
                if src and isinstance(src, str) and src not in ordered_sources:
                    ordered_sources.append(src)
        row_id = row.get("id")
        if isinstance(row_id, str) and row_id.strip():
            ordered_ids.append(row_id)

    if not ranked:
        return {}

    ranked.sort(key=lambda item: item[0], reverse=True)
    representative_row = ranked[0][1]
    representative_payload = ranked[0][2]
    representative_url = ranked[0][4]

    merged_detail: dict[str, Any] = {}
    best_confidence = "none"
    best_severity = "low"

    for _score, row, payload, _module_name, url in sorted(
        ranked, key=lambda item: item[0], reverse=True
    ):
        detail = _top_level_detail(payload)
        merged_detail = _merge_dicts(merged_detail, detail)
        confidence = (
            str(payload.get("confidence") or row.get("confidence") or "none").strip().lower()
        )
        severity = str(payload.get("severity") or row.get("severity") or "low").strip().lower()
        if _confidence_rank(confidence) > _confidence_rank(best_confidence):
            best_confidence = confidence
        if _severity_rank(severity) > _severity_rank(best_severity):
            best_severity = severity
        if representative_url is None and url:
            representative_url = url

    merged_detail = _merge_dicts(
        merged_detail,
        {
            "canonical_breach_id": identity.canonical_id,
            "canonical_breach_name": identity.canonical_name,
            "breach_name": identity.canonical_name,
            "source_breach_names": source_breach_names,
            "sources": ordered_sources,
            "source_modules": ordered_sources,
        },
    )
    if ordered_ids:
        merged_detail = _merge_dicts(merged_detail, {"source_finding_ids": ordered_ids})

    final_row = deepcopy(representative_row)
    target = final_row["data"] if isinstance(final_row.get("data"), dict) else final_row

    target["platform"] = identity.canonical_name
    target["breach_name"] = identity.canonical_name
    target["breach_id"] = identity.canonical_id
    target["source"] = (
        representative_row.get("module_name") or representative_payload.get("source") or "breach"
    )
    target["confidence"] = (
        best_confidence if best_confidence != "none" else target.get("confidence", "high")
    )
    target["severity"] = (
        best_severity if best_severity != "low" else target.get("severity", "medium")
    )
    target["sources"] = ordered_sources
    target["metadata"] = merged_detail

    if representative_url:
        target["url"] = representative_url

    for key in (
        "breach_date",
        "breached_date",
        "domain",
        "data_classes",
        "exposed_data",
        "pwn_count",
        "exposed_records",
        "password_risk",
        "added_date",
        "description",
        "reference_url",
        "logo",
        "risk",
    ):
        value = merged_detail.get(key)
        if not _is_empty(value):
            target[key] = deepcopy(value)

    return final_row


def collapse_breach_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse breach-event duplicates across module findings.

    Non-breach findings are passed through untouched.
    """
    passthrough: list[tuple[int, dict[str, Any]]] = []
    grouped: dict[str, dict[str, Any]] = {}

    for index, finding in enumerate(findings):
        row = deepcopy(finding) if isinstance(finding, dict) else finding
        if not isinstance(row, dict):
            passthrough.append((index, {"data": row}))
            continue

        payload = row.get("data") if isinstance(row.get("data"), dict) else row
        module_name = (
            str(row.get("module_name") or payload.get("source") or "").strip()
            if isinstance(payload, dict)
            else ""
        )
        identity = resolve_breach_identity(
            payload if isinstance(payload, dict) else {}, module_name
        )
        if identity is None:
            passthrough.append((index, row))
            continue

        bucket = grouped.setdefault(
            identity.canonical_id,
            {
                "identity": identity,
                "rows": [],
                "first_index": index,
            },
        )
        bucket["rows"].append(row)
        bucket["first_index"] = min(bucket["first_index"], index)

    merged_rows: list[tuple[int, dict[str, Any]]] = passthrough[:]
    for bucket in grouped.values():
        merged_rows.append(
            (bucket["first_index"], _merge_group(bucket["rows"], bucket["identity"]))
        )

    merged_rows.sort(key=lambda item: item[0])
    return [row for _index, row in merged_rows]


def is_breach_finding(finding: dict[str, Any]) -> bool:
    payload = finding.get("data") if isinstance(finding.get("data"), dict) else finding
    if not isinstance(payload, dict):
        return False
    module_name = str(finding.get("module_name") or payload.get("source") or "").strip()
    return resolve_breach_identity(payload, module_name) is not None
