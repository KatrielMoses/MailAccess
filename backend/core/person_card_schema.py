"""Frozen output schema for the UC5 person card (``report["person_card"]``).

This is the contract the website (UC6) is built on — changing a field name or type after
UC6 starts is expensive. Validation is dependency-free: :func:`validate_person_card`
returns a list of human-readable errors (empty when the card conforms). ``EXAMPLE`` is a
fully synthetic card (``sampleperson``) that must always validate.
"""

from __future__ import annotations

from typing import Any

SCHEMA_VERSION = 1

# Field spec per object. A type may be: a python type, a tuple of types (any-of), the
# string "str?" / "int?" for optional-or-None, a {"list": <spec>} for arrays, or a nested
# dict spec. ``None`` as a value means the key may be absent.
_LOCATION = {"city": "str?absent", "region": "str?absent", "country_code": "str?absent", "sources": int}
_PERSON_CARD_SPEC: dict[str, Any] = {
    "schema_version": int,
    "subject": {"type": str, "value": str},
    "names": {
        "primary": (str, type(None)),
        "variants": {"list": {"name": str, "source": str}},
    },
    "locations": {
        "primary": {"__nullable_object__": _LOCATION},
        "also_seen": {"list": _LOCATION},
        "countries": {"list": str},
    },
    "photos": {"list": {"url": str, "source": str, "kind": str}},
    "timeline": {"first_seen": "str?absent", "last_seen": "str?absent"},
    "accounts": {"list": {
        "platform": str, "handle": (str, type(None)), "url": (str, type(None)),
        "modules": {"list": str}, "confidence": str,
        "tier": (str, type(None)), "in_aggregates": bool,
    }},
    "links": {"list": str},
    "handles": {"list": str},
    "counts": {
        "accounts": int, "linked_to_subject": int, "photos": int,
        "names": int, "locations": int,
    },
}

SUBJECT_TYPES = ("email", "username")


def _check(value: Any, spec: Any, path: str, errors: list[str]) -> None:
    if isinstance(spec, dict) and "list" in spec and set(spec) == {"list"}:
        if not isinstance(value, list):
            errors.append(f"{path}: expected list, got {type(value).__name__}")
            return
        for i, item in enumerate(value):
            _check(item, spec["list"], f"{path}[{i}]", errors)
        return
    if isinstance(spec, dict) and "__nullable_object__" in spec:
        if value is not None:
            _check_object(value, spec["__nullable_object__"], path, errors)
        return
    if isinstance(spec, dict):
        _check_object(value, spec, path, errors)
        return
    if spec == "str?":
        if value is not None and not isinstance(value, str):
            errors.append(f"{path}: expected str or None, got {type(value).__name__}")
        return
    if spec == "str?absent":
        if value is not None and not isinstance(value, str):
            errors.append(f"{path}: expected str, got {type(value).__name__}")
        return
    types = spec if isinstance(spec, tuple) else (spec,)
    # bool is a subclass of int — guard so a bool never satisfies an int field.
    if int in types and bool not in types and isinstance(value, bool):
        errors.append(f"{path}: expected int, got bool")
        return
    if not isinstance(value, types):
        want = "/".join(getattr(t, "__name__", str(t)) for t in types)
        errors.append(f"{path}: expected {want}, got {type(value).__name__}")


def _check_object(value: Any, spec: dict[str, Any], path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object, got {type(value).__name__}")
        return
    for key, sub in spec.items():
        optional_absent = sub == "str?absent"
        if key not in value:
            if not optional_absent:
                errors.append(f"{path}.{key}: missing")
            continue
        _check(value[key], sub, f"{path}.{key}", errors)
    for key in value:
        if key not in spec:
            errors.append(f"{path}.{key}: unexpected field")


def validate_person_card(card: Any) -> list[str]:
    """Human-readable schema violations; empty list means the card conforms."""
    if card is None:
        return []  # a run with no accounts may carry a null card; that is allowed
    errors: list[str] = []
    _check_object(card, _PERSON_CARD_SPEC, "person_card", errors)
    if isinstance(card, dict):
        subj = card.get("subject")
        if isinstance(subj, dict) and subj.get("type") not in SUBJECT_TYPES:
            errors.append(f"person_card.subject.type: must be one of {SUBJECT_TYPES}")
        if card.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"person_card.schema_version: expected {SCHEMA_VERSION}")
    return errors


EXAMPLE: dict[str, Any] = {
    "schema_version": 1,
    "subject": {"type": "email", "value": "sampleperson@example.com"},
    "names": {
        "primary": "Sample Person",
        "variants": [{"name": "S. Person", "source": "GitHub"}],
    },
    "locations": {
        "primary": {"city": "Testcity", "region": "Sampleregion", "country_code": "IN", "sources": 3},
        "also_seen": [{"country_code": "US", "sources": 1}],
        "countries": ["IN", "US"],
    },
    "photos": [{"url": "https://cdn.example.test/avatar.png", "source": "GitHub", "kind": "avatar"}],
    "timeline": {"first_seen": "2019-01-01T00:00:00Z", "last_seen": "2026-02-01T00:00:00Z"},
    "accounts": [
        {"platform": "GitHub", "handle": "sampleperson",
         "url": "https://github.com/sampleperson", "modules": ["username_platforms"],
         "confidence": "medium", "tier": "core", "in_aggregates": True},
        {"platform": "Adobe", "handle": None, "url": "https://adobe.com",
         "modules": ["account_discovery"], "confidence": "medium",
         "tier": None, "in_aggregates": True},
    ],
    "links": ["https://sampleperson.example.test"],
    "handles": ["linkedin:sample-person"],
    "counts": {"accounts": 2, "linked_to_subject": 2, "photos": 1, "names": 2, "locations": 2},
}
