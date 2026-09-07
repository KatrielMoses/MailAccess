# Phase 3D — Unified deliverability grade

Collapses every verification signal into the one taxonomy marketers gate sends on:
**Valid · Risky · Catch-all · Invalid · Unknown**.

## What shipped

`backend/core/deliverability_grade.py` — `grade_email(...)` →
`DeliverabilityGrade(grade, reasons, evidence, score)`, fusing the 3C score with
the provider verifiers (google/m365/yahoo), optional SMTP, and the
disposable/role/catch-all flags. Set on every lead by the orchestrator
deliverability pass; surfaced in all exports (`deliverability_grade` +
`deliverability` detail) and the Lead API (`?grade=` filter, indexed
`contacts.deliverability_grade`).

**Fusion precedence** (highest wins): disposable/no-MX ⇒ Invalid → authoritative
negative (SMTP/provider not-found) ⇒ Invalid → per-mailbox confirmation ⇒ Valid →
catch-all ⇒ Catch-all → else derive from the 3C score (≥0.70 Risky, ≥0.40 Unknown).

## The two hard rules

- **Catch-all is terminal; a catch-all accept is never Valid.** A catch-all server
  accepts every address, so an accept proves nothing. Only a *per-mailbox* signal
  (a non-catch-all SMTP RCPT, a provider verifier that confirmed the mailbox, or a
  Phase-3E oracle) can lift a catch-all address to Valid.
- **Never falsely Valid.** Without a confirming signal the grade degrades to Risky
  (probably deliverable, unconfirmed) or Unknown — never Valid. Graceful
  degradation when no SMTP is available.

## Closing the Phase-2 loop

`eligibility.evaluate` gains a `deliverability_grade` parameter: an
`Invalid`/`Catch-all` grade forces `research-only` **regardless of confidence**
(they can never be eligible for outreach). `_row_eligibility` passes the lead's
grade, so outreach exports never carry an undeliverable address even at 0.99.

## Design decisions (exploration latitude)

- **Fusion precedence** as above — hard negatives first, per-mailbox confirmation
  before the catch-all terminal, score-derived last.
- **Risky vs Unknown boundary** — a high non-SMTP score with no confirmation is
  Risky (probably deliverable); a mid score is Unknown; below the floor with MX
  present is treated as weak-infra Invalid.
- **Provider-confirm-on-catch-all is policy-gated (3E)** — trusted as a bust only
  in authorized modes (see phase3e).

## Validation (done-when)

- `tests/test_deliverability_grade.py` (10) — incl. the asserted catch-all →
  never-Valid rule and the oracle-confirmed-catch-all → Valid exception.
- `tests/test_eligibility.py` policy suite — Invalid/Catch-all → `research-only`
  even at 0.99; Valid → eligible; Risky doesn't force-block; grade-absent preserves
  prior behavior. (Gated, kept off `eval/baseline/*`.)
- `tests/test_lead_export.py` — a Catch-all export row is `research-only`.

## Non-scope (respected)

No catch-all busting mechanics here (3E). No new verifiers.
