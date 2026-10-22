"""UC7.3a — alternate-email recursive anchoring (bounded, depth 1).

When ``alternate_email`` discovered a linked address via a **Class-1** signal (a breach
record, a GitHub commit email, a Gravatar profile), that address is itself an
email-anchored anchor for the same person. Re-run the cheap, high-value Class-1
discovery (registration + Gravatar) on each such alternate email and merge the accounts
under one person, each tagged with the address that anchored it.

Bounded so it can never fan out: Class-1-sourced alternates only, de-duplicated, at most
``_MAX_ANCHORS`` addresses, and depth 1 — the alternates' own alternates are not followed.
Public, logged-out data only.
"""

from __future__ import annotations

from typing import Any

from .base import BaseModule, ModuleResult, ModuleStatus

_MAX_ANCHORS = 2
# Alternate-email discovery sources that are themselves Class-1 (email-anchored). A
# permutation guess is Class-2 and is never followed.
_CLASS1_ALT_SOURCES = frozenset({"github_commits", "gravatar_profile", "breach_record"})


def class1_alt_emails(primary: str, collected: dict[str, Any]) -> list[str]:
    """The Class-1-sourced alternate emails to re-anchor on (deduped, capped, != primary)."""
    result = (collected or {}).get("alternate_email")
    primary_l = (primary or "").lower().strip()
    out: list[str] = []
    for f in getattr(result, "findings", None) or []:
        if not isinstance(f, dict):
            continue
        meta = f.get("metadata") or {}
        disc = str(meta.get("discovered_email") or "").lower().strip()
        sources = {s for s in (meta.get("sources") or []) if s}
        if meta.get("source"):
            sources.add(meta["source"])
        if disc and "@" in disc and disc != primary_l and (sources & _CLASS1_ALT_SOURCES):
            if disc not in out:
                out.append(disc)
        if len(out) >= _MAX_ANCHORS:
            break
    return out


class AlternateEmailAnchorModule(BaseModule):
    name = "alternate_email_anchor"
    email_linked = True
    description = (
        "Re-anchor Class-1 discovery on alternate emails found via a Class-1 signal, "
        "merged under one person (UC7.3, bounded depth-1)."
    )
    requires_key = False

    async def run(self, email: str, collected: dict[str, Any] | None = None) -> ModuleResult:
        from ..core.evidence import signal_type_for
        from .account_discovery import AccountDiscoveryModule

        anchors = class1_alt_emails(email, collected or {})
        if not anchors:
            return ModuleResult(status=ModuleStatus.SUCCESS, findings=[],
                                metadata={"anchors": [], "anchor_count": 0})

        findings: list[dict[str, Any]] = []
        for alt in anchors:
            try:
                sub = await AccountDiscoveryModule().run(alt)
            except Exception:  # noqa: BLE001 - a bad anchor must not break the run
                continue
            for f in sub.findings or []:
                if not isinstance(f, dict):
                    continue
                meta = f.setdefault("metadata", {})
                # Provenance: which linked address anchored this account.
                meta["anchor_email"] = alt
                meta.setdefault("source", "account_discovery")
                f["email_linked"] = True
                # Preserve the Class-1 signal so the person card counts it on the spine
                # (the finding is recorded under this module, whose own signal is 'other').
                f.setdefault("trace", {})["signal_type"] = signal_type_for("account_discovery", f)
                findings.append(f)
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=findings,
                            metadata={"anchors": anchors, "anchor_count": len(anchors)})
