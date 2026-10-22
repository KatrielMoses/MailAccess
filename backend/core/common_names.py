from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_CORPUS_PATH = Path(__file__).resolve().parents[2] / "data" / "common_names.json"
_SEPARATORS_RE = re.compile(r"[\s._-]+")
_common_names: set[str] | None = None
_normalized_names: set[str] | None = None


def _normalize_username(text: str) -> str:
    return _SEPARATORS_RE.sub("", text.strip().lower())


def _load_names() -> tuple[set[str], set[str]]:
    global _common_names, _normalized_names

    if _common_names is not None and _normalized_names is not None:
        return _common_names, _normalized_names

    names: set[str] = set()
    try:
        payload: Any = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
        raw_names = payload.get("names") if isinstance(payload, dict) else None
        if not isinstance(raw_names, list):
            raise ValueError("common-names corpus must contain a names list")
        names = {
            name.strip().lower()
            for name in raw_names
            if isinstance(name, str) and name.strip()
        }
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        names = set()

    _common_names = names
    _normalized_names = {_normalize_username(name) for name in names}
    return _common_names, _normalized_names


def is_common_name(text: str) -> bool:
    if not text or not text.strip():
        return False
    names, _ = _load_names()
    return text.strip().lower() in names


def is_common_username(text: str) -> bool:
    if not text or not text.strip():
        return False
    names, normalized_names = _load_names()
    lowered = text.strip().lower()
    return lowered in names or _normalize_username(lowered) in normalized_names


def is_specific_handle(handle: str) -> bool:
    """UC7.3: True when a handle is distinctive enough that, for a freemail subject, its
    Class-2 matches are plausibly the owner — rather than a bare common-first-name
    collision (``john``, ``sarah``) that behaves like a domain role. Distinctive =
    contains a digit, a separator (a compound like ``jane.doe``), ends in a known name
    (a ``first``+``last`` concatenation like ``janedoe``), or is a long single
    token. A bare common first name / dictionary word scores LOW. No network: the
    bundled common-names corpus is the only source."""
    s = (handle or "").strip().lower()
    core = _SEPARATORS_RE.sub("", s)
    if not core:
        return False
    if any(c.isdigit() for c in s):      # jdoe88
        return True
    if s != core:                        # a separator → compound (jane.doe, j-doe)
        return True
    if is_common_username(core):         # bare common first name / dictionary word
        return False
    names, _ = _load_names()
    for i in range(3, len(core) - 2):    # first+last concatenation (jane+doe, john+smith)
        if core[:i] in names or core[i:] in names:
            return True
    return len(core) >= 10               # long, distinctive single token
