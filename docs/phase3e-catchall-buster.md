# Phase 3E — Catch-all handling & own-domain SMTP validation

Catch-all domains defeat SMTP RCPT (every address returns 250) — the #1 blind spot
marketers pay to solve. 3E addresses it **without depending on SMTP**, and gates
the mechanism to authorized modes.

## What shipped

`backend/core/catchall_buster.py` — a policy gate + a thin, guarded entrypoint over
the existing provider verifiers:

- `oracle_available(provider)` — a non-SMTP per-mailbox oracle exists for **M365**
  (`GetCredentialType`/autodiscover) and **Google Workspace**. (Yahoo's endpoint is
  a consumer-account check, not a tenant oracle — not a buster for business
  domains.)
- `is_bust_allowed(mode)` — delegates to
  `product_mode.active_mailbox_probing_allowed`, the single source of truth:
  permitted in `security-investigation` and `org-authorized-verification`,
  **blocked in `public-business-contact`** (active existence probing of arbitrary
  third-party mailboxes for cold outreach is not a lawful basis — the FTC line).
- `trust_provider_confirmation_on_catchall(mode, provider)` — the grade fuser's
  gate: a provider "verified" verdict lifts a *catch-all* address to Valid only
  with an oracle-capable provider **and** an authorized mode.
- `confirm_mailbox(email, provider, *, mode, verifier=…)` — runs the appropriate
  verifier, returning a per-mailbox `ExistenceSignal`; returns `blocked_by_mode`
  (without probing) in public mode and `no_oracle` for providers without one.

The orchestrator deliverability pass consumes this: on a catch-all domain, a
provider "verified" verdict becomes a `mailbox_confirmed` bust → grade Valid **only
when the mode permits**; in public mode it is neutralised and the address stays
graded Catch-all.

## Own-domain SMTP validation — deferred (documented)

The real SMTP + catch-all path is exercised in `org-authorized-verification` mode
against a domain the operator controls (lavellenetworks / rootaccess), run from a
host with outbound port 25. **The eval/dev host blocks port 25 (Phase-0 finding),
and no $0 outbound-25 host is currently available, so this live validation is
deferred** — as the brief permits. The product path (3C/3D) does not block on it:
grading degrades gracefully to the non-SMTP score + provider signals. When an
outbound-25 host is available, run a harvest with `--mode org-authorized-verification`
against the own domain; `smtp_verifier.check_catchall` + per-mailbox RCPT then
supply the SMTP-confirmed grade.

## The stripe catch-all question — answered

Phase-0 noted "stripe catch-all not detected," hypothesising it was because SMTP
never ran. **Confirmed:** catch-all detection is SMTP-dependent
(`smtp_verifier.check_catchall`), so with port 25 blocked the domain-level
`catchall_detected` stays `None` and no catch-all is asserted. Under 3C/3D this is
now *safe rather than silently wrong*: without an SMTP catch-all verdict, stripe
addresses are graded from the non-SMTP score + provider signals (Risky/Unknown) and
**never falsely Valid**; if/when SMTP runs (own-domain path) and flags catch-all,
they grade **Catch-all**, and a provider oracle can bust individual mailboxes in an
authorized mode. Definitive live confirmation awaits the deferred outbound-25 path.

## Validation (done-when)

- `tests/test_catchall_buster.py` (7): oracle only for M365/Google; bust blocked in
  public mode; trust requires oracle+authorized mode; `confirm_mailbox` short-
  circuits (no probe) in public mode, reports `no_oracle`, and confirms/refutes via
  an injected verifier (network-free).
- `tests/test_deliverability_grade.py` — oracle-confirmed catch-all → Valid; bare
  catch-all accept → Catch-all.
- Policy suite green (oracles blocked in public-business-contact where required).

## Non-scope (respected)

No raising the 10-probe SMTP cap. No dictionary generation. No new providers.
