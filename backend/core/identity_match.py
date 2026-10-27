"""Shared identity-match helpers: trusted handles, known names and the name-match rule.

Used by the profile-phase modules that attach a profile to the subject (social_discovery,
username_pivot). Pure functions over the ``collected`` module results; no I/O.
"""

from __future__ import annotations

import re
from typing import Any

# UC7.2: handles that come from the email-anchored spine (a Class-1 account proves the
# email owns it — e.g. the GitHub login from a commit-email match). These are trusted to
# seed a handle guess; a bare local-part sweep handle is not (that guessed
# linkedin.com/in/<localpart> and surfaced a stranger).
CLASS1_HANDLE_MODULES = frozenset(
    {"github_commits", "github_domain_commits", "github_code_search", "keybase",
     "account_discovery", "google_account_intel", "gravatar"}
)


def iter_findings(collected: dict[str, Any]):
    """``(module, finding)`` for every dict finding in the collected results."""
    for module, result in (collected or {}).items():
        for f in getattr(result, "findings", None) or []:
            if isinstance(f, dict):
                yield module, f


def spine_handles(collected: dict[str, Any]) -> list[str]:
    """Lower-cased handles from Class-1 (email-anchored) findings, in order, deduplicated."""
    out: list[str] = []
    for module, f in iter_findings(collected):
        if module not in CLASS1_HANDLE_MODULES:
            continue
        meta = f.get("metadata") or {}
        h = str(f.get("username") or meta.get("profile_username") or "").strip().lower()
        if h and h not in out:
            out.append(h)
    return out


def _words(name: Any) -> list[str]:
    return [w for w in re.split(r"[^a-z]+", str(name or "").lower()) if w]


def known_names(collected: dict[str, Any]) -> list[str]:
    """Names already found for this person: commit authors, parsed profile names."""
    from ..modules.linkedin_serp import _find_confirmed_name

    names: list[str] = []
    try:
        name, _src = _find_confirmed_name(collected)
        if name:
            names.append(name)
    except Exception:  # noqa: BLE001
        pass
    for module, f in iter_findings(collected):
        meta = f.get("metadata") or {}
        if module == "github_commits" and meta.get("name"):
            names.append(str(meta["name"]))
        if module == "username_platforms" and meta.get("core") and meta.get("display_name"):
            names.append(str(meta["display_name"]))
    out = []
    for n in names:
        words = _words(n)
        if len(words) >= 2 and max(map(len, words)) > 1 and n not in out:
            out.append(n)
    return out


def names_match(a: Any, b: Any) -> bool:
    """First and last name agree (case-insensitive); middle names ignored; an initial
    matches a full first name."""
    wa, wb = _words(a), _words(b)
    if len(wa) < 2 or len(wb) < 2 or wa[-1] != wb[-1]:
        return False
    fa, fb = wa[0], wb[0]
    return fa == fb or (len(fa) == 1 and fb.startswith(fa)) or (len(fb) == 1 and fa.startswith(fb))
