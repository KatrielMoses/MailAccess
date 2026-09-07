# Phase 3B — Title & seniority inference

"VPs and above" is a primary paid-tool lead filter. 3B maps a free-text
`job_title` onto a seniority band + a coarse department, deterministically and
explainably.

## What shipped

`backend/core/seniority_classifier.py` — `classify_title(title)` →
`SeniorityClassification(band, department, matched_term, reason, is_ambiguous)`.

- **Bands:** `c-level`, `vp`, `director`, `manager`, `ic`, `unknown`.
- **Lexicon-pattern** approach (same shape as `industry_vocabulary.json` /
  `role_prefixes.json`), word-boundary regexes; no ML (Phase 4 may calibrate).
- Wired into the pipeline via `lead_person` (fills `HarvestedEmail.seniority` from
  the resolved `job_title`) and exposed on the Lead + as an export/filter
  dimension (`seniority` CSV column, `person.seniority`, the `?seniority=` API
  filter, and an indexed `contacts.seniority` column).

## Design decisions (exploration latitude)

- **Highest band wins** when a title carries several tokens ("VP of Engineering" →
  `vp` band, `engineering` department).
- **Ambiguous / unrecognised → `unknown`, never a forced band.** A bare
  "Principal" / "Lead" / "Executive" returns `unknown` with `is_ambiguous=True`;
  a non-English or unknown title returns `unknown` (the English lexicon simply
  doesn't match — it degrades to unknown rather than guessing). This upholds 3A's
  evidence-or-null contract for the derived field.
- **`president` disambiguation** — "President" is C-level *except* inside "Vice
  President" / SVP / EVP (a dedicated negative-lookbehind pattern), so
  "Vice President, Sales" resolves to `vp`, not `c-level`.
- **Explainable & deterministic** — every result records the matched term and a
  reason; the same input always yields the same output.

## Validation (done-when)

- `tests/test_seniority_classifier.py` (12): each band; highest-band-wins;
  department detection; ambiguous → `unknown`+flagged; international/unrecognised →
  `unknown`; empty; determinism; explainability.
- Seniority accuracy is scored in the scorecard by running the classifier against
  labelled titles (`known_contacts[].title` vs `.seniority`) — `no_truth`/null
  until labels land.

## Non-scope (respected)

No ML (Phase 4). No org-chart clustering (Phase 7 B3).
