# Phase 2D — Eligibility ≠ confidence

"Technically likely deliverable" (research **confidence**) and "eligible for
outreach" (a **policy** decision) are separate questions (Doc-1 #8). A
high-confidence address can still be personal, suppressed, or collected under the
wrong mode. Export therefore requires **both** a confidence threshold **and** a
policy verdict — this is the export-side complement to 2C's collection-side gate.

## The verdict

`backend/core/eligibility.py` — `Eligibility` ∈ `{eligible, review, suppressed,
research-only}`, computed by `evaluate(*, mode, policy_status, suppressed,
confidence, threshold?, review_floor?)` from:

- **suppression** (2A) — an objection wins outright → `suppressed`;
- **mode + `source_policy_status`** (2C) — `security-investigation` output is
  research, not outreach → `research-only`; data without a lawful-public /
  authorized-supplied basis → `research-only`;
- **confidence** (1E / harvest score) vs a **configurable per-mode threshold** —
  `≥ threshold` → `eligible`; in `[review_floor, threshold)` → `review`;
  below the floor → `research-only`; no score → `review`.

Thresholds are config (`eligibility_confidence_threshold_public` = 0.7,
`…_org` = 0.6, `eligibility_review_floor` = 0.4). A confidence *label* (the
harvest 4-tier `CONFIRMED/LIKELY/MEDIUM/LOW`) maps to a score when no numeric
score is present.

**Orthogonal to confidence:** the verdict never mutates the score. `EligibilityVerdict`
carries the confidence it was computed against, and both are surfaced
independently on every record — two records with identical confidence but
different policy get different verdicts.

## Export controls

- **Every exportable record carries its verdict + reasoning.** Each harvest
  email row in `format_harvest_json_export` gains `eligibility` +
  `eligibility_reason` (alongside, not replacing, `confidence_score`); the
  investigate report gains a top-level `eligibility` in `enrich_report`.
- **Outreach exports emit only `eligible`** (and `review` only when explicitly
  requested). `eligibility.filter_outreach(rows, include_review=…)` drops
  everything else — `research-only` and `suppressed` are never returned in any
  configuration.

## Validation (done-when)

`tests/test_eligibility.py` (11): the four verdicts and their bands; org
threshold below public; missing-confidence → `review`; the verdict surfaces but
never mutates confidence (identical scores, different policy → different
verdicts); label/number score coercion; `filter_outreach` never emits
`research-only`/`suppressed`; a public-mode harvest export where every row carries
a verdict, a strong address is `eligible`, a weak one `research-only`, and the
outreach filter keeps only the eligible; a security-mode export where even a 0.99
address is `research-only`. `gate check` green (0 NEW).

## Non-scope (respected)

No new confidence math (Phase 4). No deliverability grade yet (Phase 3 D1 —
eligibility will consume it once it exists; until then it uses current confidence
+ policy).
