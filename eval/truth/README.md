# Phase 0 — Gold Evaluation Corpus (`truth/`)

Hand-verified ground truth for the frozen Phase 0 target set, so precision /
recall / freshness / attribution / calibration are computable in the scorecard
(`eval/harness/score.py`).

## Access & handling

**Authorized evaluation only. LOCAL. Never distributed. Never seeded into any
tool cache and never `--contribute`d.** Everything in this directory is
gitignored **except** this README and `_schema/`. The filled label files
(`*.email.yaml`, `*.domain.yaml`) stay on the evaluator's machine.

## How to label

1. One file per target, named `<target_id>.email.yaml` or `<target_id>.domain.yaml`
   where `<target_id>` matches `eval/targets.yaml`.
2. Copy the matching template from `_schema/` and fill it in.
3. **Label only what you can independently verify.** Everything else stays
   `unknown` — never guess. Record *how* you verified each label (evidence) and
   whether it's current (freshness).
4. The three domain files (the harvest targets) must be sanity-checked by a
   **second reviewer** before the gold set is considered done (per the brief).

## Division of labor (important)

The **tool** may be run against every target by the harness — that is authorized
evaluation and its outputs land (locally) in `eval/scorecards/`. But the
**truth labels are human-verified by the evaluator**: identifying a real person
or confirming a breach for a third party is manual work that must be
independently checked, not machine-generated. For third-party targets you cannot
independently verify, the correct label is `unknown`; the scorecard treats
those targets as "yield/latency only" and reports precision/recall/Brier as
`null` with `truth_status: no_truth`. That is the expected baseline state and is
honest — it is not a harness failure.

## What each metric needs from truth

| Scorecard metric | Truth field(s) required |
|---|---|
| Precision (harvest) | `known_contacts[].email` (TP) + `false_positive_emails` (FP) |
| Recall (harvest) | `known_contacts[].email` |
| Pattern correctness | `email_pattern` |
| Catch-all correctness | `catch_all` |
| Brier (harvest) | labelled emails + tool's `confidence_label` |
| Per-source FP rate | `false_positive_emails` + tool's `found_by_modules` |
| Person-field precision (3A) | `known_contacts[].name` / `.title` |
| Seniority accuracy (3B) | `known_contacts[].title` + `.seniority` |
| Deliverability Brier (3C) | `known_contacts[].currently_deliverable` (or `.deliverability_outcome`) |
| Name correctness (investigate) | `identity.real_name` |
| Precision (investigate) | `accounts[].verdict` |

See `../docs/0B-gold-corpus.md` for the full procedure and the
confidence→probability mapping used for Brier.
