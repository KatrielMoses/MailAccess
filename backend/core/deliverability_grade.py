"""Phase 3D — the unified deliverability grade marketers gate sends on.

Collapses every verification signal into one taxonomy:

    Valid · Risky · Catch-all · Invalid · Unknown

fusing the Phase-3C non-SMTP score with the provider verifiers
(google/m365/yahoo), optional SMTP, and the disposable/role/catch-all flags. Two
non-negotiable rules from the brief:

* **Catch-all is a distinct, terminal grade.** A catch-all server accepts every
  address, so an accept there proves nothing — a catch-all accept must NEVER be
  graded Valid. Only a *per-mailbox* existence signal (an SMTP RCPT that is not
  the catch-all probe, a provider verifier that confirmed the specific mailbox,
  or a Phase-3E oracle) can lift a catch-all domain's address to Valid.
* **Never falsely Valid.** Without a confirming signal the grade degrades to
  Risky (probably deliverable, unconfirmed) or Unknown (genuinely
  undeterminable) — never Valid. Valid requires an affirmative per-mailbox
  confirmation (SMTP exists, provider verified, or a recent corpus-verified
  history).

Fusion precedence (highest wins): disposable/no-MX ⇒ Invalid → authoritative
negative ⇒ Invalid → per-mailbox confirmation ⇒ Valid → catch-all ⇒ Catch-all →
else derive from the 3C score.

The grade feeds the Phase-2D eligibility verdict (see ``eligibility.evaluate``):
Invalid and Catch-all can never be eligible for outreach regardless of
confidence, closing the loop left open in Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .deliverability_score import DeliverabilityScore

GRADE_VALID = "Valid"
GRADE_RISKY = "Risky"
GRADE_CATCH_ALL = "Catch-all"
GRADE_INVALID = "Invalid"
GRADE_UNKNOWN = "Unknown"

ALL_GRADES = (GRADE_VALID, GRADE_RISKY, GRADE_CATCH_ALL, GRADE_INVALID, GRADE_UNKNOWN)

# Grades that can never be sent to (consumed by eligibility to force non-eligible).
NON_SENDABLE_GRADES = frozenset({GRADE_INVALID, GRADE_CATCH_ALL})

# 3C score thresholds for the no-confirmation degradation path.
_RISKY_FLOOR = 0.70  # >= here ⇒ probably deliverable (unconfirmed) ⇒ Risky
_UNKNOWN_FLOOR = 0.40  # [floor, risky) ⇒ Unknown; below handled by Invalid rules

_PROVIDER_VERIFIED = frozenset({"verified"})
_PROVIDER_NEGATIVE = frozenset({"not_found"})
_SMTP_NEGATIVE = frozenset({"not_found"})


@dataclass
class DeliverabilityGrade:
    grade: str
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    score: float | None = None  # the 3C probability, surfaced alongside

    def as_dict(self) -> dict[str, Any]:
        return {
            "grade": self.grade,
            "reasons": self.reasons,
            "evidence": self.evidence,
            "score": round(self.score, 4) if self.score is not None else None,
        }


def grade_email(
    *,
    score: DeliverabilityScore | None = None,
    is_disposable: bool = False,
    mx_present: bool = True,
    is_role: bool = False,
    catchall: bool | None = None,
    smtp_status: str | None = None,
    smtp_exists: bool | None = None,
    provider_status: str | None = None,
    provider_name: str | None = None,
    mailbox_confirmed: bool = False,
    history_recent_verified: bool = False,
) -> DeliverabilityGrade:
    """Fuse all signals into one grade with evidence-backed reasons.

    ``mailbox_confirmed`` is the Phase-3E per-mailbox existence signal (a provider
    oracle confirming the specific mailbox on a catch-all domain). It is the only
    thing that can grade a catch-all address Valid.
    """
    p = score.score if score is not None else None
    evidence: dict[str, Any] = {
        "score": round(p, 4) if p is not None else None,
        "catchall": catchall,
        "smtp_status": smtp_status,
        "provider_status": provider_status,
        "provider_name": provider_name,
        "is_role": is_role,
        "mailbox_confirmed": mailbox_confirmed,
    }
    reasons: list[str] = []

    def done(grade: str) -> DeliverabilityGrade:
        return DeliverabilityGrade(grade=grade, reasons=reasons, evidence=evidence, score=p)

    smtp = str(smtp_status or "").lower()
    prov = str(provider_status or "").lower()

    # 1. Hard invalids — no mailbox can exist.
    if is_disposable:
        reasons.append("disposable/throwaway domain")
        return done(GRADE_INVALID)
    if not mx_present:
        reasons.append("no MX records — domain accepts no mail")
        return done(GRADE_INVALID)

    # 2. Authoritative negatives — a verifier said the mailbox does not exist.
    if smtp in _SMTP_NEGATIVE or smtp_exists is False:
        reasons.append("SMTP RCPT: mailbox does not exist")
        return done(GRADE_INVALID)
    if prov in _PROVIDER_NEGATIVE:
        reasons.append(f"provider verifier ({provider_name or 'provider'}): mailbox not found")
        return done(GRADE_INVALID)

    # 3. Per-mailbox confirmation ⇒ Valid. On a catch-all domain, ONLY these
    #    signals (never a bare accept) may reach Valid.
    smtp_confirmed = smtp_exists is True and smtp not in ("catch_all",)
    provider_confirmed = prov in _PROVIDER_VERIFIED
    if smtp_confirmed or provider_confirmed or mailbox_confirmed or history_recent_verified:
        if smtp_confirmed:
            reasons.append("SMTP RCPT confirmed the mailbox exists")
        if provider_confirmed:
            reasons.append(
                f"provider verifier ({provider_name or 'provider'}) confirmed the mailbox"
            )
        if mailbox_confirmed:
            reasons.append("provider existence oracle confirmed the mailbox (catch-all buster)")
        if history_recent_verified:
            reasons.append("recent corpus verification history: verified")
        if catchall and not (smtp_confirmed or provider_confirmed or mailbox_confirmed):
            # A recent history alone on a catch-all domain isn't per-mailbox proof
            # today — fall through to Catch-all rather than assert Valid.
            reasons.append("catch-all domain — history alone is not per-mailbox proof")
        else:
            if is_role:
                reasons.append("role mailbox (deliverable but shared)")
            return done(GRADE_VALID)

    # 4. Catch-all is terminal — a catch-all accept never yields Valid.
    if catchall:
        reasons.append("catch-all domain: server accepts all addresses; mailbox unprovable")
        return done(GRADE_CATCH_ALL)

    # 5. Graceful degradation from the 3C score (no confirming signal, no SMTP).
    if p is None:
        reasons.append("no deliverability signal available")
        return done(GRADE_UNKNOWN)
    if p >= _RISKY_FLOOR:
        reasons.append(f"non-SMTP score {p:.2f}: probably deliverable but unconfirmed")
        if is_role:
            reasons.append("role mailbox")
        return done(GRADE_RISKY)
    if p >= _UNKNOWN_FLOOR:
        reasons.append(f"non-SMTP score {p:.2f}: insufficient signal to grade")
        return done(GRADE_UNKNOWN)
    reasons.append(f"non-SMTP score {p:.2f}: weak infrastructure signal")
    return done(GRADE_INVALID)
