# Phase 2C — Lawful-public-data gate

Consumes the 2B classification to actually **enforce** it at the dispatch choke
points. In `public-business-contact` mode only lawfully-published business
contacts and authorized user-supplied data are collected; the security-only
behaviors — account-reset probing, breach/credential sources, personal-email
pivots, private-profile inference, and active mailbox probing for growth — are
blocked. `org-authorized-verification` additionally permits active verification
against the operator's own domain. **Security-investigation is unchanged** (its
allowlist is "everything", so every gate below is a no-op there — zero regression).

## Enforcement

**Investigate** — gated at the one universal module-execution point,
`_phase_runner.run_one_module`, and **above** the `force`/opt-in bypass: a
mode-policy denial is not something `--force` or an `enable_modules` flag may
override. A denied module returns `SKIPPED` with `skip_reason="policy_mode"`.
`PrimaryPhase` also prunes denied modules up front so they never instantiate.
Mode is threaded engine → `phase.run(mode=…)` → `_runner_kwargs` → `_run_and_record`
→ `run_one_module`.

**Harvest** — the mode is translated into `skip_modules` in `run_domain_harvest`:
`blocked_modules(mode)` (the allowlist complement) is unioned into the effective
skip set, and the runtime scheduler already emits `SKIPPED` for skipped modules.
Empty for security-investigation.

**`reset_prober` (defense in depth)** — reset probing only runs via `breach_deep`,
which the classification already blocks outside security. As an independent
second guard, `reset_prober.probe` refuses (returns `None`) whenever the active
mode is not security-investigation. The active mode is carried on a task-local
`contextvar` (`product_mode.set_active_mode`), set in `run_one_module` and
`run_domain_harvest`; contextvars copy per asyncio task, so the marker doesn't
leak across sibling module tasks.

## The candidate-generation vs. dictionary-attack boundary (the FTC line)

The non-negotiable principle (Doc-1 #6): generating a candidate address from an
**independently-evidenced person** + an observed/corpus pattern is permitted;
**un-evidenced dictionary permutation** and **active mailbox probing for growth**
are not a lawful basis for cold outreach. The mechanism:

- **Un-evidenced permutation** (`permutation_discovery`) is a classification
  block — *public-only*: blocked in public-business-contact, permitted in
  org-authorized-verification (against your own domain) and security. Evidenced
  pattern generation (`pattern_and_verify`) stays allowed.
- **Active mailbox probing** is blocked in public mode by forcing
  `enable_smtp = False` in `run_domain_harvest`
  (`active_mailbox_probing_allowed(mode)` is `False` only for public).
- **`is_evidenced_candidate(evidence, mode)`** formalizes the emission threshold:
  outside public mode generation is unrestricted; in public mode a generated
  candidate must trace to a real, independently-observed person
  (name/LinkedIn/employee source), else it is dropped.

## Policy status on every observation

`build_observation` now stamps `source_policy_status` from the collection mode
(the gate guarantees only mode-appropriate sources ran, so the mode fixes the
lawful basis): `unreviewed` (security — unchanged), `lawful-public` (public),
`authorized-supplied` (org). 2D's eligibility reads this; anything not so marked
never enters lead output.

## Validation (done-when)

`tests/test_policy_modes.py` (11): a blocked module is `SKIPPED` in lead-gen and
`force` cannot override it; an allowed module runs; security runs everything;
`blocked_modules(public)` contains the breach/personal/permutation set and is
empty for security; active-probing gate; permutation public-only-blocked; the
evidenced-candidate rule; `reset_prober` refuses (no network) outside security;
per-mode policy status stamped on an observation. `gate check` green (0 NEW; a
wall-clock concurrency flake `test_both_tracks_run_concurrently`, independent of
this change, was added to `eval/baseline/known-flaky.txt`).

## Non-scope (respected)

Does not change security-investigation behavior. Does not compute the export
eligibility verdict (2D) — 2C governs collection, 2D governs export.
