# 0B — Gold Evaluation Corpus (truth labels)

**Goal:** hand-verified ground truth for the 8 frozen targets so precision /
recall / freshness / attribution / calibration are computable in the 0C
scorecard. This is careful manual work: **label only what you can independently
verify; mark everything else `unknown` — never guess a label.**

## Where it lives

`eval/truth/` — one file per target, `<target_id>.email.yaml` or
`<target_id>.domain.yaml`. **Authorized evaluation only, LOCAL, gitignored.**
Only `README.md` and `_schema/` are committed. Never distributed, never seeded
into any tool cache, never `--contribute`d.

Generate empty stubs to fill:

```bash
uv run python -m eval.harness.init_truth
```

## Division of labor (what the harness does vs the human)

* The **harness may run the tool against every target** — that is authorized
  evaluation; outputs land locally in `eval/scorecards/`.
* The **truth labels are verified by a human evaluator.** Identifying a real
  person, or confirming a specific breach, for a **third party** is manual work
  that must be independently checked — it is deliberately *not* machine-generated
  here. Where you cannot independently verify, the label stays `unknown`, and the
  scorecard reports that target as yield/latency-only (`truth_status:
  no_truth`). That is the correct, honest baseline state.

This matters for the target spread: the two own-domain corporate emails and
own-domain harvest domains are directly verifiable by the operator. The free
personal, educational, and large-company (Stripe) targets involve third-party
data — label only the parts you can stand behind with evidence, leave the rest
`unknown`.

## What to label

### Per email (investigate)  — `_schema/email.example.yaml`

* `identity.real_name` (+ your manual `name_confidence` and how you verified it).
* `accounts[]` — for each account/profile the tool surfaces, `verdict:
  true_positive | false_positive | unknown` with evidence. TP = truly the same
  person; FP = collision / wrong person.
* `breaches[]` — which breach/exposure claims are real (`verdict: real | false |
  unknown`) with evidence.
* Freshness note on each label (is it current?).

### Per domain (harvest) — `_schema/domain.example.yaml`

* `known_contacts[]` — a hand-verified set of real, currently-deliverable
  business contacts (name / title / email) that genuinely exist. **Not
  exhaustive, but correct** — this is the "known-good" reference recall is
  measured against.
* `email_pattern` — the true pattern (`{first}`, `{first}.{last}`, …). Must match
  the tool's `summary.confirmed_pattern` token format to score correct.
* `catch_all` — verify **independently** (critical for the large target; a
  catch-all domain answers SMTP RCPT for any localpart). Record how you verified.
* Title correctness + `title_source` (attribution) per contact.
* `false_positive_emails[]` — addresses the tool is known to surface wrongly
  (collisions / wrong-person / stale), used as explicit FP labels for precision.

## Confidence → probability mapping (calibration)

The scorecard maps the tool's confidence to a probability for the Brier score.
See `0C-scorecard-harness.md` for the harvest tier table (CONFIRMED 0.95 / LIKELY
0.80 / MEDIUM 0.60 / LOW 0.30). Document any change to this mapping here so
cross-phase Brier scores stay comparable.

## Second-reviewer sign-off

Per the brief, at least the **3 domain** truth files must be sanity-checked by a
second reviewer before the gold set is "done". Record the reviewer + date in each
domain file's `notes:` field.

## Done-when

- [ ] Every target has a truth file with explicit TP / FP / `unknown` labels +
      verification evidence. *(stubs generated; human verification pending)*
- [ ] The 3 domain files are second-reviewer sanity-checked.

> Status: schema, templates, stub generator, and scorer support are complete and
> committed. Populating the labels with verified values is the evaluator's manual
> step and is intentionally left to a human — see "Division of labor" above.
