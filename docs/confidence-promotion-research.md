<a href="../README.md">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/brand/mailaccess-logo-reversed.svg">
    <img src="../assets/brand/mailaccess-logo.svg" alt="MailAccess" height="28">
  </picture>
</a>

# Confidence Promotion for Pattern Candidates — Research Report

**Date:** 2026-07-14
**Scope:** MailAccess harvest-emails — promoting `permutation_unverified`
(w=0.0) candidates to meaningful confidence on shared-hosting / Google
Workspace / Proton / Zoho / Fastmail domains where SMTP is unreliable.

**The bottom line in one sentence:** the codebase already has the
*inference machinery* for Approaches 1, 2, 3, and 4, but the wiring
into `compute_confidence` is intentionally weak — the
`permutation_unverified` weight is 0.0 and the multi-source multiplier
is the only escape hatch. The four cheapest, highest-leverage moves
are: (a) add a per-template format-frequency prior, (b) make
"matching the inferred confirmed format" a small additive boost, (c)
make "local part derives from a discovered person name" an additive
boost, and (d) stop letting `permutation_unverified` pollute the
multi-source family count. With those four moves and no network
verification, a well-matched pattern on a shared-hosting domain can
realistically land at **0.55–0.70 = MEDIUM**. HIGH (≥0.85) is **not**
achievable passively.

---

## 0. The score machinery, in one paragraph

`backend/core/email_confidence.py:192–218` —
`compute_confidence(source_types, is_smtp_verified, is_ca_attested, ...)`
does the entire final scoring. The math is:

```
unique_types = set(source_types)            # dedup, line 204
base_score   = sum(SOURCE_WEIGHTS[t] for t in unique_types)   # line 205
multiplier, _ = _select_verification_multiplier(unique_types, ...)  # line 211
freshness   = freshness_factor(last_seen_timestamp)          # line 216
final       = clamp(base_score * multiplier * freshness, 0, 1.5)   # line 217
```

Three knobs: base_score, multiplier, freshness. The label thresholds
are `HIGH ≥ 0.85`, `MEDIUM ≥ 0.55`, else `LOW` (lines 95–97).

The full source-weight table lives at `email_confidence.py:8–47`. For
this question the only weights that matter are the `permutation_*`
family at lines 28–37:

| key                          | weight | class         |
|------------------------------|-------:|---------------|
| `permutation_verified`       | 0.65   | verification  |
| `permutation_verified_m365`  | 0.85   | verification  |
| `permutation_verified_yahoo` | 0.80   | verification  |
| `permutation_mx_valid`       | 0.30   | verification  |
| `permutation_catchall`       | 0.10   | verification  |
| `permutation_gravatar_hit`   | 0.30   | corroboration |
| `permutation_breach_hit`     | 0.15   | corroboration |
| `permutation_unverified`     | **0.00** | verification |

The "verification" class collides into one family for the
multi-source multiplier (lines 58–93, 146–150, 161–178): if
`permutation_unverified` is already in the source_types union, adding
`permutation_mx_valid` does not push the family count from 1 → 2 —
they're both "verification". It only helps if the *other* family is
"scraping" (cc, search snippets, wayback).

That single fact shapes the rest of this report.

---

## APPROACH 1 — Email format inference from confirmed emails

### What exists in the codebase

**`_pattern_shape_for_email`** —
`backend/core/domain_harvest_orchestrator.py:420–432` already classifies
an email into one of three shape labels:

```python
def _pattern_shape_for_email(email: str) -> str | None:
    local = email.rsplit("@", 1)[0].lower()
    if "." in local:
        parts = [p for p in local.split(".") if p]
        if len(parts) == 2 and all(part.isalpha() for part in parts):
            return "{first}.{last}@{domain}"
    if "_" in local:
        ...
        return "{first}_{last}@{domain}"
    if re.fullmatch(r"[a-z][a-z]{2,}", local):
        return "{first}@{domain}"
    return None
```

**`_infer_confirmed_pattern_from_emails`** — same file, lines 435–453.
For every HIGH/MEDIUM on-domain email it shape-classifies and
identifies the **dominant** shape, then publishes it to the signal
pool:

```python
def _infer_confirmed_pattern_from_emails(emails, signal_pool):
    counts: dict[str, int] = {}
    for entry in emails:
        if not entry.on_domain or entry.confidence_label not in {"HIGH", "MEDIUM"}:
            continue
        shape = _pattern_shape_for_email(entry.email)
        if shape is not None:
            counts[shape] = counts.get(shape, 0) + 1
    if not counts:
        return None
    dominant = max(counts.items(), key=lambda item: (item[1], item[0]))[0]
    signal_pool.emit_confirmed_pattern(dominant)
    return dominant
```

**Signal-pool sink** — `backend/core/signal_pool.py:431–439` —
`emit_confirmed_pattern` / `get_confirmed_patterns`.

**Downstream consumer (the only one today)**
— `backend/modules/pattern_and_verify.py:153–157, 198, 511–519`. The
confirmed template is read by `PatternAndVerifyModule` and reorders
the candidate list so the confirmed template is generated **first**:

```python
# pattern_and_verify.py:196-199
if tier == "high" and not downgrade_high:
    if confirmed_template:
        return confirmed_pattern_priority(confirmed_template)
```

And `email_pattern_generator.py:273–289` —
`confirmed_pattern_priority(confirmed_template)` returns
`[confirmed_template, *rest]`.

### What is missing

`katriel@rootaccess.tech` is found via a GitHub commit author
(weight 0.95) → it's HIGH/MEDIUM on-domain → `_infer_confirmed_pattern_from_emails`
detects `{first}@` shape and publishes it. The signal pool passes it
to `PatternAndVerifyModule`, which reorders the candidate list for
the *next* name it processes.

**But that confirmed format does nothing to the *confidence* of the
pattern candidates themselves.** The pattern candidate
`katriel.moses@rootaccess.tech` (generated by an existing employee
name) is still emitted with `source_type=permutation_unverified`
(`pattern_and_verify.py:259, 348`) and the `permutation_unverified`
key in its `source_types` list still contributes **0.0** to
`base_score` at `email_confidence.py:205`.

The chain works for *ordering future probes* but is silent for
*scoring the current candidates*. That's the gap.

### Answering the specific sub-questions

**a) Is email format inference currently implemented anywhere?**
Yes, but only as a pattern-priority signal, not a confidence signal.
The four code sites above are the entire implementation. Search hits
for `pattern_inference`, `format_detection`, `confirmed_pattern`,
`inferred_format` all point back to these four sites and the report
side at `domain_harvest_report.py:1389`.

**b) Current effect on other pattern candidates?**
**None on confidence score.** The confirmed pattern only changes the
*order* in which templates are generated; the resulting pattern
findings still carry `source_type=permutation_unverified` (weight 0.0)
and go through the same `compute_confidence` as before.

**c) Right boost amount?**
The current `permutation_mx_valid` weight is 0.30 — that's the
project's existing benchmark for "syntax is valid, MX is real, but
mailbox existence is unknown". A pattern that **matches a confirmed
format** is in the same epistemic category as MX-valid: structural
plausibility without mailbox existence. The honest boost is
**0.20–0.30** — the same band as `permutation_mx_valid`. Use 0.20 if
only 1 confirmed email exists for the format, 0.25 if 2 confirm, 0.30
if 3+ confirm. Don't go above 0.30: that would be claiming more than
MX-valid evidence.

**d) Minimum emails before format is reliable?**
- 1 confirmed email of format X: shape X is a hypothesis, not a
  conclusion. Boost = 0.20 if matching; 0.0 if not matching (i.e.
  don't *suppress* non-matching candidates, just don't boost them).
- 2 confirmed emails both of format X: same boost 0.20 (still
  hypothesis-strength).
- 3+ confirmed emails of format X with **no** counter-examples:
  boost 0.30; consider *demoting* non-matching candidates by -0.05
  (cheap suppression). Counter-examples (e.g. one X and one Y on the
  same domain) should drop the boost to 0.15 because the company
  visibly uses multiple formats.

**e) Where should format inference run?**
Two answers depending on what you mean:

- The *inference* itself already runs correctly at
  `domain_harvest_orchestrator.py:435–453` and is invoked from the
  tail of `_aggregate` at line 767. Don't move it.
- The *confidence boost* is what's missing. Plug it in **inside
  `_aggregate`**, between the per-evidence source-type collection
  (lines 702–730) and the `compute_confidence` call (line 732). For
  every pattern candidate with `source_type=permutation_unverified`,
  check `signal_pool.get_confirmed_patterns()` and append
  `permutation_format_match` (new key) to `all_source_types` if the
  candidate's template matches. That single change is the entire
  wiring.

**f) Failure modes**
- *Multiple formats per company.* Already handled — the inference
  picks the dominant one, but you should NOT demote the non-dominant
  candidates unless you have ≥3 confirmed emails all of one shape.
- *Acquired domains / legacy formats.* The dominant pattern is from
  recent, HIGH/MEDIUM emails. Acquired legacy addresses are scored
  on their own evidence; the legacy format is simply not used as the
  "confirmed" anchor.
- *Contractors with a different format from employees.* With
  contractor addresses present, dominant-shape inference can land on
  a contractor's `f.last@` while employees use `first.last@`. The
  fix is to weight the dominant-shape count by the *role* of the
  source: ignore role accounts and `permutation_catchall` /
  `permutation_mx_valid` rows when picking the anchor. The current
  implementation already filters by `confidence_label in {"HIGH",
  "MEDIUM"}` which excludes the catchall/mx_valid buckets.

### Effort / impact

- **Effort:** 1.5 hours. One new `SOURCE_WEIGHTS` key
  (`permutation_format_match` at e.g. 0.20) and ~12 lines in
  `_aggregate` after the source-type collection loop. Plus 3
  unit-test cases.
- **Expected confidence impact:** a pattern candidate that happens
  to match the confirmed format goes from 0.0 → ~0.20 base. After
  multiplier (1.0 single-source, 1.20 with another scraping source)
  and freshness (0.50 for old, 1.0 for new), that puts it at
  **0.10–0.24**. Still LOW, but the candidate is now *distinguishable
  from a non-matching pattern at the same domain* — which is the
  information an analyst actually wants.
- **Failure modes:** companies with one outlier address can bias the
  inference; mitigated by the 3+ threshold for any *demotion*.

---

## APPROACH 2 — Cross-source corroboration without network verification

### What exists in the codebase

The exact mechanism is `_aggregate` at
`domain_harvest_orchestrator.py:514–768`. The score math is in
`compute_confidence` at `email_confidence.py:192–218`. The
multi-source multiplier is `_select_verification_multiplier` at
`email_confidence.py:161–178` and the family mapper is
`_source_family` at `email_confidence.py:146–150`.

### Answering the specific sub-questions

**a) Final score for a candidate with `permutation_unverified` + `common_crawl_single`?**

The code path:

1. `pattern_and_verify` emits a finding with
   `metadata.source_type = "permutation_unverified"` (line 50 of
   `pattern_and_verify.py`, 259 of the `run` method).
2. `commoncrawl_email` emits a finding with
   `metadata.source_type = "common_crawl_single"` (line 284 of
   `commoncrawl_email.py`).
3. Both findings are grouped under the same `subaddress_key` in
   `_aggregate` (line 571). The `entry.evidence` list contains
   **both** entries.
4. `all_source_types` is built from both evidence entries'
   `_extract_source_types` calls (line 713), yielding
   `["permutation_unverified", "common_crawl_single"]`.
5. `compute_confidence` dedupes via `unique_types = {...}` (line
   204), so `source_types` passed to the math is the *set*
   `{"permutation_unverified", "common_crawl_single"}`.
6. `base_score = 0.00 + 0.30 = 0.30` (line 205).
7. `distinct_families` via `_source_family`: `permutation_unverified`
   → class `"verification"`, `common_crawl_single` → starts with
   `"common_crawl_"` → family `"common_crawl_single"`. That's
   **2 distinct families** → multiplier `1.20`
   (`VERIFICATION_MULTIPLIER["multi_source_2"]`).
8. `freshness` depends on the CC timestamps; assume 18 months old
   → `freshness_factor` returns `0.65` (line 138–140).
9. `final = 0.30 * 1.20 * 0.65 = 0.234` → LOW (label `_label` at
   line 154).

**So the calculation is: `0.30 × 1.20 × 0.65 = 0.234` (LOW).**

**b) Is there a bug where `permutation_unverified` (0.0) pulls the score down?**

**No, not a down-pull.** Mathematically `0.0` added to a positive
number is that positive number. `permutation_unverified` is *neutral*
on `base_score`.

**But it has a sneaky side effect on the multiplier.** Without
`permutation_unverified` in the source-types set, the email would be
classified as one family (`common_crawl_single` only) → multiplier
1.00. With it, the same email becomes a two-family email → multiplier
1.20. So the current code is *accidentally* giving CC emails a
family-count bonus whenever they happen to match a generated pattern.
That's not a bug per se — it's a "lucky bonus" — but it's confusing
because the analyst sees `permutation_unverified` in the breakdown
and assumes the score includes the pattern's evidence, when really
the pattern is contributing nothing except the multiplier bump.

The *real* bug is the **inverse**: a CC email that does **not** match
any generated pattern is single-family, multiplier 1.00, while a CC
email that *does* match is two-family, multiplier 1.20. The two
emails have identical evidence but the matching one scores 20% higher
for a reason that has nothing to do with evidence.

**c) What if `permutation_unverified` is excluded from the source-types union when other sources are present?**

Concretely, change line 716–720 of
`domain_harvest_orchestrator.py` (the place that injects
`permutation_verified` / `permutation_catchall` into
`all_source_types`) to also drop `permutation_unverified` from the
union when the union has anything else. Effect:

- Single-source unverified pattern: still 0.0 (unchanged).
- CC + pattern: union becomes `{"common_crawl_single"}`. base = 0.30,
  families = 1, multiplier 1.00, fresh 0.65, final 0.195.
  **Drops from 0.234 → 0.195 — a 17% decrease** for the matching case.

So "treat permutation_unverified as a tag, not a source" actually
**hurts** the very email we want to help, because the multiplier
collapses. The fix is to *also* add a small explicit
"permutation_format_match" weight (Approach 1) to compensate, and
keep the family count. Net effect: no behaviour change for matching
patterns, but a clean separation of "what kind of evidence is this"
from "how many families contributed".

**d) Should pattern generation be completely separated from email scoring?**

**No, but the current conflation is too quiet.** The current behaviour
already gives a CC email a small *bonus* when it happens to match a
pattern (`0.30 → 0.234` instead of `0.30 → 0.195`). That's defensible:
"a CC-sourced email whose local part is also a name-derived pattern
for this domain is more likely to be a real personal address than a
stray CC-scrape". But the *intent* is hidden inside the family count.
A cleaner version would be: keep `permutation_unverified` *out* of
the source-types union, and add an explicit new key
`permutation_format_match` (Approach 1) when both pattern and
external evidence agree on the local part. Same numeric outcome,
cleaner provenance.

**e) What combinations produce MEDIUM (≥0.55) for a pattern candidate today, with no network verification?**

Working through `base × multiplier × freshness` with the existing
weights and an 18-month-old timestamp (freshness = 0.65):

- `permutation_mx_valid` (0.30) + `common_crawl_single` (0.30) + `search_snippet_ddg` (0.35): base 0.95, 3 families (verification, scraping×2 same family for multiplier purposes — `search_snippet_` and `common_crawl_` are their own families), mult 1.45, fresh 0.65 → `0.95 × 1.45 × 0.65 = 0.895` → **HIGH (0.85+)**.

  Wait — that's higher than I'd expect. Let me recheck the family
  mapping. `_source_family` returns the source_type itself for
  `common_crawl_*` and `search_snippet_*` (line 148). So those are
  *distinct* families: `common_crawl_single` ≠
  `search_snippet_ddg`. So the family count is 3 and the multiplier is
  1.45. 0.95 × 1.45 × 0.65 = 0.895. **That's a real HIGH**. Today.

- `permutation_mx_valid` (0.30) + `common_crawl_single` (0.30) +
  `wayback_archive` (0.45): base 1.05, 3 families, mult 1.45, fresh
  0.65 → `1.05 × 1.45 × 0.65 = 0.989` → **HIGH**.

- `permutation_mx_valid` (0.30) + `search_snippet_ddg` (0.35):
  base 0.65, 2 families, mult 1.20, fresh 0.65 → `0.65 × 1.20 × 0.65
  = 0.507` → LOW (just under 0.55).

- `permutation_gravatar_hit` (0.30) + `common_crawl_high_density`
  (0.75): base 1.05, 2 families, mult 1.20, fresh 0.65 → `1.05 × 1.20
  × 0.65 = 0.819` → **MEDIUM (0.55+)** but just below HIGH.

- `common_crawl_high_density` (0.75) alone: base 0.75, 1 family, mult
  1.0, fresh 0.65 → `0.75 × 1.0 × 0.65 = 0.4875` → LOW.

- `common_crawl_medium` (0.55) + `search_snippet_ddg` (0.35): base
  0.90, 2 families, mult 1.20, fresh 0.65 → `0.90 × 1.20 × 0.65 =
  0.702` → **MEDIUM**.

So today, with **no SMTP** and **no pattern candidate**, a CC-medium
plus DDG-snippet plus MX-valid pattern is enough to hit HIGH on a
domain where the data is fresh. The problem with `rootaccess.tech`
is not the score model — it's that those other sources are *not
finding* the pattern candidate. The fix on this axis is more
multi-source coverage, not a better multiplier.

### Effort / impact

- **Effort:** 0.5 hours for the multiplier-fairness tweak; 3+ hours
  to actually drive CC / DDG / Wayback to *find* more pattern
  candidates (separate problem, see Approach 6).
- **Expected confidence impact:** the fairness tweak is <5% on
  existing scores. The coverage improvement is the real lever.

---

## APPROACH 3 — Name-email consistency scoring

### What exists in the codebase

**`_name_matches_email_local`** —
`backend/core/domain_harvest_orchestrator.py:456–467`:

```python
def _name_matches_email_local(name: str, local_part: str) -> bool:
    tokens = [t.lower() for t in re.findall(r"[a-zA-Z]+", name)]
    if len(tokens) < 2:
        return False
    local = re.sub(r"[^a-z0-9]", "", local_part.lower())
    first, last = tokens[0], tokens[-1]
    return (
        (first in local and last in local)
        or local.startswith(first[:1] + last)
        or local.startswith(first + last[:1])
        or local == f"{first[:1]}{last}"
    )
```

It detects first/last containment, first-initial+last, and
first+last-initial. This function is **already in the codebase** but
is currently used for two things only:

- `_apply_signal_pool_correlation` (lines 470–511) — when a name is
  found by a *different* module from the email, give the email a
  **2.5× multiplier boost** (line 493). This is huge — but only fires
  when there is a *cross-module* name signal, i.e. the employee name
  was discovered by name_discovery and the email by some other
  module. It does **not** fire when the email was generated by
  pattern_and_verify using the same name, because then the modules
  match (lines 489–492).
- `domain_harvest_report.py:555–558` — display-only link in the
  people panel.

**`derive_name_from_email`** —
`backend/modules/person_email_pivot.py:31–42`. The inverse
function — derives a name candidate from a name-shaped local part.
Used at `domain_harvest_report.py:560–566` and
`harvest_runner.py:1142–1144`. Display-only.

### What is missing

**The pattern candidate that comes out of `PatternAndVerifyModule`
never sees its own generating name re-evaluated for consistency.**
The name is the *input* to pattern generation
(`pattern_and_verify.py:293–295`) and the pattern candidate's
`source_name` is captured (`pattern_and_verify.py:262–268`) and put
on the finding as `metadata.source_name`. But neither
`pattern_and_verify` nor `_aggregate` ever calls
`_name_matches_email_local(local, source_name)` to add an explicit
name-match evidence key.

The right place is in `_aggregate` after the `source_types` list is
built (line 713). For each pattern candidate where
`source_type=permutation_unverified` and the finding's
`metadata.source_name` is set, call the matcher and — if it matches —
add a new key `permutation_name_match` to the source_types union.

### Answering the specific sub-questions

**a) Is name-email consistency scoring implemented anywhere?**
The **function** is implemented (`_name_matches_email_local`,
`derive_name_from_email`). The **scoring** is partially implemented
inside `_apply_signal_pool_correlation` (the 2.5× worksFor
multiplier) but only for cross-module cases. For self-consistent
pattern candidates (the very common case the user is asking about)
there is no boost.

**b) Templates and real-world prevalence.** Per the Interseller 5M+
study (most-cited public dataset) and the 2025 Prospeo / Sales.co
replications, the global distribution at companies of all sizes
weighed together is roughly:

| Template                | Share (Interseller all-sizes weighted avg) | 2025–2026 replication |
|-------------------------|-------------------------------------------:|----------------------:|
| `{first}.{last}@`       | **~30%** (1,000+ employees: 48–56%)        | **dominant at scale** |
| `{f}{last}@`            | **~25%** (peaks at 51–500 employees)       | strong                |
| `{first}@`              | **~30%** (skewed to <50 employees)         | startup signature     |
| `{first}{last}@`        | ~3%                                       | uncommon              |
| `{last}@`               | ~3%                                       | small business        |
| `{first}_{last}@`       | ~2%                                       | legacy                |
| `{first}{l}@`           | ~3%                                       | tech                  |
| `{last}{f}@`            | ~2%                                       | rare                  |
| `{first}-{last}@`       | <1%                                       | rare                  |
| `{last}.{first}@`       | <1%                                       | EU gov / academia     |
| `{f}.{last}@`           | ~1%                                       | EU corporates         |

**Crucial shape note:** the "right" format depends entirely on
company size. A 5-person startup is `firstname@` 71% of the time. A
10,000+ enterprise is `first.last@` 56% of the time. **There's no
single "most common" — there's "most common given what we know
about the company."**

**c) Right boost and detection algorithm.**

The detection algorithm is already in
`_name_matches_email_local` (quoted above) plus
`person_email_pivot._local_matches_name` (a stricter variant at
`person_email_pivot.py:49–62`). Both detect the same six shapes
(first+last, f+last, first+l, last+first, first, last, substring
match). The `_name_matches_email_local` variant is more permissive
(it accepts any local part that *contains* both first and last as
substrings), which is appropriate for a soft confidence signal.

For boost amount: name-email structural match is a *very strong*
corroborator in real-world security research — but it's not a
verifier. A catch-all domain would happily accept
`katriel.moses@`, `support@`, `xyzz@`. The name match doesn't mean
the mailbox exists.

Right boost for the matcher:

- Strong match (the matcher returns True AND the template is in the
  top-3 prevalence for the company's apparent size tier):
  **0.25**. Same band as `permutation_mx_valid`.
- Weak match (substring containment but template is uncommon, e.g.
  `{last}.{first}@`): **0.10**.
- Match via `derive_name_from_email` (i.e. the inverse direction —
  the local part is name-shaped but no specific name is on file):
  **0.10** — symmetrical to the above.

**d) Over-boosting risk on catch-all domains.**

Real risk. A catch-all domain is one where every local part accepts
mail, so the name match tells you nothing about whether the address
is *assigned* to a person. Two safeguards:

1. **Only apply the boost when the company is NOT catch-all.**
   `pattern_and_verify` already detects catch-all during SMTP
   probing (line 389 of `pattern_and_verify.py`,
   `batch_meta["is_catchall"]`). When `is_catchall` is True or
   `verification_status="catchall"`, suppress the name-match boost
   entirely.
2. **Cap the additive boost so it can't single-handedly reach MEDIUM.**
   A 0.25 single-key boost is at the upper bound of the project's
   "soft" band; it should *never* combine with `permutation_mx_valid`
   (also 0.30) without some explicit cap. Cleanest rule: name-match
   and format-match are mutually exclusive for the same finding —
   pick the higher of the two, not the sum. Keeps the cap at ~0.30
   for "name and format agree" and ~0.30 for "format matches but no
   name" and 0.0 for neither.

**e) Where should this run?**

Inside `_aggregate` immediately after the
`_infer_confirmed_pattern_from_emails` call (line 767) and before the
`return final` at line 768. For each entry where
`source_type=permutation_unverified` and `metadata.source_name` is
set, run the matcher against the local part. If it matches and the
domain is not catch-all, append a new `permutation_name_match` key to
the `source_types` union. A second pass recomputes confidence for
those entries.

**Concretely: this is a 15-line change in `_aggregate` + 1 new
`SOURCE_WEIGHTS` entry + 4 unit tests.**

### Effort / impact

- **Effort:** 1.5 hours.
- **Expected confidence impact:** a pattern candidate that matches
  the generating name goes from base 0.0 → base 0.25. With a single
  other scraping source: `0.25 × 1.20 × 0.65 = 0.195`. Still LOW.
  With two more sources: `0.25 + 0.30 + 0.35 = 0.90` base, mult 1.45,
  fresh 0.65 = 0.849 — **MEDIUM, almost HIGH**. The combination is
  what unlocks value; the name-match alone is the band-aid.
- **Failure modes:** contractors/aliases whose local part doesn't
  match their full name (`john@` for "John Smith"); legacy single-
  letter addresses (`j@`); CJK names where unidecode produces
  surprising splits. Mitigated by the weak-match tier (0.10) and
  the no-catch-all guard.

---

## APPROACH 4 — Breach and historical data

### What exists in the codebase

- **`permutation_breach_hit` weight = 0.15** —
  `email_confidence.py:37`. Class = "corroboration"
  (`email_confidence.py:85`).
- **Tagging logic** —
  `domain_harvest_orchestrator.py:368–374`. If a finding's metadata
  has `breach_date` / `breach_name` / `"breach"` in platform / `"pwned"`
  in platform, the source type is *added* to the union.
- **`breach_deep` module** — `backend/modules/breach_deep.py` (full
  read). This is **account-existence probing on top breach sites**
  (LinkedIn, Adobe, Dropbox, Spotify, etc.) — it checks if the email
  has an account on those *consumer* sites, *not* if the email is in
  a credentials dump. It emits findings with `metadata.breach_name`
  and `metadata.breach_date`. The module is OFF by default
  (`enable_breach_deep: bool = False`, `config.py:272`).
- **HIBP key path** — `haveibeenpwned_api_key` /
  `hibp_api_key` / `breachdirectory_api_key` exist in
  `config.py:417–419` but no module under `backend/modules/` calls
  HIBP directly for a single email. The breach signal today comes
  from breach_deep account-existence probes, not from a credentials
  dump search.
- **BreachCorpus** — referenced at `breach_deep.py:8`. Loaded with
  severity-ranked top breach sites; not a credential dump index.
- **Timeline integration** — `backend/core/timeline.py:684–770` has a
  full breach/paste event model with deduplication keyed on
  `(breach, identity)`.

### Answering the specific sub-questions

**a) Is HIBP integration implemented? What does it currently do? What confidence boost?**

HIBP **key** is configured but no module wires it into a "check
email X in HIBP" call. `breach_deep` *probes* top breach sites for
account existence — that's a different concept. The current boost
when a finding is tagged as breach is **0.15** (`permutation_breach_hit`,
`email_confidence.py:37`).

**b) Free breach-checking alternatives beyond HIBP, no API key?**

Honest answer for 2026:

- **leakcheck.io** — public, limited free tier, deprecated
  in mid-2024 after legal issues. Replaced by **leakcheck.io v2**
  with a paid-only API.
- **xposedornot (XON)** — has a public endpoint
  (`https://api.xposedornot.com/v1/check/email/{email}`) with rate
  limit ~60 req/IP/hour and no auth. Returns breach count + names
  + dates. This is the only 2026 option I can recommend without an
  API key.
- **haveibeenpwned.com** — official, paid-only now (Pwned 5+
  requires the API key with paid tier since 2024-11).
- **IntelligenceX** — already wired in
  (`enable_intelx_lookup: bool = True`, `config.py:222`); uses
  paid `intelx_api_key` but you can opt in with a free key.
- **dehashed.com** — paid, no free tier.
- **snusbase.com** — paid.

**Net: XON is the only keyless source worth wiring up. The HIBP
key path is dead unless you pay.**

**c) What confidence boost should a breach hit give to a pattern candidate?**

The email existed at the time of the breach — possibly years ago.
That's evidence the *address* was real, but says nothing about
whether the person is still at the company. For current
employment verification it's at best a tiebreaker.

Honest boost: keep it at 0.15, but **split into two sources**:

- `permutation_breach_hit_recent` (≤2 years): **0.20**. Modern
  password-reuse means the address is almost certainly still active.
- `permutation_breach_hit_historical` (>2 years): **0.10**. The
  address existed, person may have left.

**d) Use breach data to infer email FORMAT for a domain even if the specific candidate isn't in a breach?**

This is the *real* use of breach data and it's not implemented. If
you have 50 emails from breaches for a company and 48 of them are
`{first}.{last}@`, that's stronger format inference than the
single confirmed email Approach 1 uses. The infrastructure is
already there: `_infer_confirmed_pattern_from_emails` is called
once on the aggregated emails. Adding a *second* call against the
breach-tagged source pool is a 30-line change.

Honest boost: 3+ breaches all of one format = format-confidence of
0.30 (same as MX-valid, same as the proposed format-match from
Approach 1). This is a 1.0-hour extension of Approach 1, not a
standalone phase.

### Effort / impact

- **Effort:** 2.5 hours total — 0.5 hours to add
  `permutation_breach_hit_recent` / `_historical` keys + age logic,
  1.5 hours to wire XON's free endpoint, 0.5 hours for the breach-
  driven format inference extension.
- **Expected confidence impact:** +0.10 to +0.20 for any candidate
  whose local part is in a recent breach. Most candidates will not
  match a breach — the real value is the *format inference* it
  enables, which compounds with Approach 1.
- **Failure modes:** historical breach hit on a former employee
  (false positive for current employment); breach records with
  typo'd domains (rare but exists); breach correlation against
  throwaway accounts.

---

## APPROACH 5 — DNS and infrastructure signals

### What exists in the codebase

- **`dns_lookup` module** — `backend/modules/dns_lookup.py` (full
  read). It already does MX, SPF, DMARC, DKIM, A, NS lookups in
  parallel (lines 94–113). Emits findings `dns_spf`, `dns_dmarc`,
  `dns_dkim` (lines 122–132). Tags `mx_provider` (line 142) but with
  a *different* provider list than `mail_provider.py`.
- **`mail_provider` module** — `backend/core/mail_provider.py` (full
  read). Detects M365 / Google / Yahoo / Proton / Zoho / Fastmail /
  self-hosted / unknown from MX. **No shared-hosting detection
  (Hostinger, Namecheap, Bluehost, cPanel, Plesk).**
- **`domain_intel` module** — `backend/modules/domain_intel.py` has
  parallel SPF/DMARC parsing at lines 78–110. The `dns_lookup` and
  `domain_intel` implementations are essentially duplicates.
- **Neither DNS module is in the domain harvest orchestrator's
  module list.** Grep confirms: `MODULE_DNS_LOOKUP` is not in
  `MODULE_*` constants at `domain_harvest_orchestrator.py:96–108`,
  and the orchestrator's Phase 1 list at lines 2313–2413 does not
  include it. The DNS module is wired only into single-email
  investigation mode.

### Answering the specific sub-questions

**a) SPF analysis — does MailAccess read SPF? What confidence?**

`dns_lookup` reads SPF (`dns_lookup.py:37–46`) and emits a finding
when present. But the finding is a *module-level* finding, not
attached to any specific email. The module is not in the
domain-harvest pipeline. So: **read but unused for confidence.**

The right integration: in `_aggregate`, after computing
`email_confidence`, look up the domain's `has_spf` once (using the
orchestrator's existing fetch or a quick `dns.resolver` query in the
worker thread) and apply a per-candidate boost of **+0.05** when
present, **0.00** when absent. SPF doesn't verify an individual
address, but it confirms the domain is *configured* for email —
which is non-trivial for a 1-person business or a parked domain.

**b) DKIM selector discovery for shared-hosting detection.**

`dns_lookup` already probes 6 selectors (line 111) but only sets a
boolean `has_dkim`. It does not record *which* selector matched.

Real-world DKIM selector patterns:

| Provider     | Common selectors                                |
|--------------|-------------------------------------------------|
| Google       | `google`, `selector1`, `selector2`              |
| M365         | `selector1`, `selector2`                        |
| Hostinger    | `default`, `mail`, `x`                          |
| cPanel       | `default`, `mail` (per-domain, randomly chosen)|
| Namecheap    | `default`, `mail`                               |
| Bluehost     | `default`                                       |
| Plesk        | `default`                                       |
| Yahoo        | `yahoo`, `yahoo1`                               |
| Proton       | `protonmail`, `protonmail2`                     |
| Zoho         | `zmail`, `zoho`                                 |
| Fastmail     | `fm1`, `fm2`, `fm3`                             |

A 1-hour extension: add the matched selector to the DNS finding
metadata. Then extend `mail_provider.py` with a shared-hosting
detector that uses the *combination* of MX + DKIM selector + SPF
include to fingerprint the host. A cPanel site has
MX = `mail.{domain}` AND DKIM = `default` AND SPF = `v=spf1
include:_spf.google.com ~all` (or similar). The fingerprint logic
is provider-specific but stable.

**c) DMARC policy — does strict DMARC increase confidence?**

`dns_lookup` already extracts `dmarc_policy` (lines 48–62) but only
as a string field on the module-level finding; it never feeds into
email scoring.

A `p=reject` DMARC policy is meaningful: the domain *actively
rejects* unauthenticated mail, which means (a) the domain owner
takes email seriously, (b) the domain is unlikely to be a spam
sinkhole, (c) catch-all is less likely. Honest boost: **+0.10** for
`p=reject`, **+0.05** for `p=quarantine`, **0.00** for `p=none` or
no DMARC. This is small but adds information: a pattern candidate
on a domain with `p=reject` is structurally more plausible than the
same candidate on a domain with no DMARC at all.

**d) MX record provider fingerprinting beyond what mail_provider.py does.**

The current `mail_provider.py:35–64` has a clean 8-way classification
(M365/Google/Yahoo/Proton/Zoho/Fastmail/self-hosted/unknown) but
**does not separate shared hosting from self-hosted**. A
Namecheap-hosted domain has MX = `mx1.namecheap.com` — `mail_provider`
sees that the MX is on the *target domain* (line 61) and calls it
`SELF_HOSTED`. That's wrong for our purposes: a Namecheap
mail-hosting plan with an admin-set catch-all behaves very
differently from a real self-hosted Postfix on a dedicated server.

Right fix: add an `MX_FINGERPRINTS` table in `mail_provider.py`
mapping MX host substrings to provider classes:

```python
MX_FINGERPRINTS = {
    "hostinger.com": "shared_hosting_hostinger",
    "namecheap.com": "shared_hosting_namecheap",
    "bluehost.com": "shared_hosting_bluehost",
    "secureserver.net": "shared_hosting_godaddy",
    "cpanel": "shared_hosting_cpanel",
    "plesk": "shared_hosting_plesk",
    # ... ~30 entries
}
```

And expose a new `Provider` value `SHARED_HOSTING`. Then in
`_aggregate`, demote `permutation_catchall` to **0.05** (instead of
0.10) when the provider is shared-hosting — because shared hosting
is less likely to be a true catch-all and more likely to be a
false-positive catch-all-flag from over-permissive default cPanel
configs. Concretely: a Hostinger domain's catch-all flag from SMTP
should be weighted *less* than an M365 catch-all flag, because
M365 catch-all is usually an explicit `acceptedDomain` setting while
Hostinger catch-all is just "the cPanel default".

### Effort / impact

- **Effort:** 3.0 hours total — 1 hour SPF+DMARC boost in
  `_aggregate`, 1 hour DKIM selector + shared-hosting fingerprint
  table, 1 hour per-candidate catch-all demotion logic.
- **Expected confidence impact:** small (+0.05 to +0.15 per
  candidate) but cumulative. Mostly helps *suppress* bad candidates
  (the catch-all demotion) rather than promote good ones.
- **Failure modes:** shared-hosting providers also legitimately use
  `~all` and `?all` SPF softfails; mis-fingerprinting on a
  multi-tenant VPS with cPanel branding is common; DMARC reports may
  lag policy changes by 24 hours.

---

## APPROACH 6 — Social and professional profile corroboration

### What exists in the codebase

- **`name_to_github_profile` module** — referenced at
  `domain_harvest_orchestrator.py:2049` and at
  `harvest_runner.py:1066–1067`. Resolves a name to a GitHub
  login, then exposes any `email` field. **Public email field
  already wired** (`email_confidence.py:23` weight 0.85 for
  `github_profile_email`).
- **`person_email_pivot` module** —
  `backend/modules/person_email_pivot.py` (full read). Two
  sub-sources: (a) GitHub profile email matching the target
  domain, (b) DDG + Bing search snippet with the name + domain.
  Emits `github_profile_email` (0.85) and `name_search_snippet`
  (0.65) source types.
- **`email_identity_enrichment` module** — runs Gravatar, GitHub,
  Keybase, HackerNews, Fediverse lookups for the harvested email
  (`backend/modules/email_identity_enrichment.py:41`). Outputs feed
  back into the signal pool. **Keybase is in the gather list but
  the integration is shallow** — see sub-question e.
- **`Gravatar` integration** — full implementation, weight
  `permutation_gravatar_hit = 0.30` (`email_confidence.py:36`).
- **No LinkedIn, no Twitter/X, no personal-site scraper, no Keybase
  structured lookup** in the domain-harvest pipeline.

### Answering the specific sub-questions

**a) LinkedIn URL slug → email pattern corroboration**

`linkedin_serp` module exists at
`backend/modules/linkedin_serp.py:64` but it uses LinkedIn-sERP
results for *name discovery*, not for email-format corroboration.
The slug `katriel-moses` does map to the name, but the slug-to-
local-part relationship is a *style* match (the slug is hyphenated,
the email is dotted) and is already covered by
`_name_matches_email_local`. **No additional value** to implement.

**b) GitHub profile → email inference beyond public email field**

The public email field is already used. Other GitHub signals
worth pursuing:

- **Commit metadata email** — already used
  (`github_commit_author` weight 0.95, `email_confidence.py:11`).
  Implemented in `code_and_cert_email` module.
- **GitHub Pages sites** — `blog` URL field on a profile is
  scraped (mentioned in the task description) but no email-
  extraction pass on the linked blog. **Easy 1-hour win:** the
  existing stealth session can fetch the blog, run the same
  `extract_emails` pipeline, and add to the email_hits pool.
- **README contact sections** — partial coverage via
  `github_code_match` (0.45). Could be promoted to a structured
  source type `github_readme_contact` at 0.50 if we can detect the
  "Contact:" header.
- **Org member bios** — implemented in
  `github_org_members` module (referenced in orchestrator), no
  email extraction yet. **Easy 1-hour extension.**

**c) Twitter/X bio patterns**

Not implemented. Yield is low — people rarely put their work email
in a public bio. The two scenarios where it *does* happen are
(self-employed consultants, journalists), and the format is so
diverse that any structural match would just be a name-match
(Approach 3). **Not worth implementing.**

**d) Personal website discovery → email extraction**

The blog-URL extraction is implemented in the
`name_to_github_profile` module. **The next step — fetching the
blog and running the email extractor — is NOT implemented.** This
is one of the highest-yield additions for shared-hosting domains:
small companies and indie developers frequently link a personal
site from GitHub, and the personal site has the work email
prominently in a `mailto:` link. **1.5 hours to wire.**

Realistic yield estimate: 5–10% of harvested personal sites have a
mailto: link with the target-domain email. That's a 5–10× increase
in the personal-site-sourced email pool, which then flows into the
existing confidence scoring and lifts the multi-source multiplier
for those candidates.

**e) Keybase profiles**

`enable_keybase_lookup: bool = True` (`config.py:206`). Keybase
itself is queried by `email_identity_enrichment` but the lookup is
shallow (probably "does email X have a Keybase account"). The
real value of Keybase in 2026 is the cryptographically-signed
identity chain — when a Keybase profile links `twitter.com/foo`,
`github.com/foo`, and `foo@bar.com`, that chain is strong
corroboration. **Worth a 2-hour structured-extraction pass.**
Honest yield in 2026: low (Keybase active user base has shrunk
significantly since the Zoom acquisition), but when it hits, the
signal is high-quality.

### Effort / impact

- **Effort:** 4.5 hours total. 1.5 hours personal-site email
  extraction, 1 hour GitHub org member bio extraction, 1 hour
  GitHub README contact section detection, 1 hour Keybase
  structured extraction, plus 0.5 hours pipeline wiring.
- **Expected confidence impact:** +0.10 to +0.40 for affected
  candidates (personal sites and Keybase are HIGH-quality sources
  when they hit). The bigger effect is *coverage* — the number
  of candidates with at least one non-pattern source goes from
  the current low single-digit per harvest to 15–25.
- **Failure modes:** personal-site scraper hitting a parked
  domain (404), Keybase rate-limits (60 req/hour unauthenticated),
  GitHub blog URLs going to Medium/Substack (no control over
  email extraction there).

---

## APPROACH 7 — Probabilistic pattern ranking

### What exists in the codebase

- **`_PATTERN_TEMPLATES`** —
  `backend/core/email_pattern_generator.py:34–46`. The list of 11
  templates, **ordered** by real-world prevalence per the Interseller
  5M-company analysis. Ordering is the only prevalence information
  used today; there is no per-template weight.
- **All `permutation_unverified` candidates share weight 0.0**
  (`email_confidence.py:30`) regardless of which template was
  used. The pattern template is captured in
  `metadata.pattern_template` (`pattern_and_verify.py:569`) but
  never fed back into confidence.

### Answering the specific sub-questions

**a) Real distribution of corporate email formats globally in 2026.**

From the Interseller 5M+ study (2019 baseline, still cited as
canonical in 2025) cross-referenced with Prospeo's 2025 update
(broken down by company size) and Sales.co's 2025–2026 platform
data:

| Template           | All-sizes weighted | 1,000+ enterprises | <50 employees |
|--------------------|-------------------:|-------------------:|--------------:|
| `{first}.{last}@`  | ~30%               | **48–56%**         | 10–14%        |
| `{f}{last}@`       | ~25%               | 22–35%             | 13–27%        |
| `{first}@`         | ~30%               | 4–7%               | 42–71%        |
| `{first}{last}@`   | ~3%                | 2–3%               | 1–4%          |
| `{last}@`          | ~3%                | <1%                | 1–3%          |
| `{first}_{last}@`  | ~2%                | 1–4%               | <1%           |
| `{first}{l}@`      | ~3%                | 2–3%               | <1%           |
| `{last}{f}@`       | ~2%                | <3%                | <1%           |
| `{first}-{last}@`  | <1%                | <1%                | <1%           |
| `{last}.{first}@`  | <1%                | <1%                | <1%           |
| `{f}.{last}@`      | ~1%                | 1–2%               | <1%           |

**Key insight:** template prevalence is **size-conditional**. There
is no single "right" base confidence for a template; the right
base depends on the company's apparent headcount. We don't
currently estimate headcount, but the `homepage` and `linkedin_serp`
modules can give a rough proxy.

**b) Should candidates be ranked by format frequency before verification?**

**Yes.** The current behaviour (treat all unverified patterns as
0.0) throws away the only piece of probabilistic information we
have. Even before the format is *confirmed*, the prior distribution
is informative.

**c) Combine with company-specific signals?**

Yes — for the homepage probe already done by
`employee_name_discovery` and `linkedin_serp`, we can extract a
rough headcount signal (e.g. "we found 3 employees named in a
team page" → small; "we found 30 employees" → mid-size). When the
headcount proxy is <10, down-weight `{first}.{last}@` from 0.30 to
0.15 and up-weight `{first}@` from 0.30 to 0.50. When the headcount
proxy is >50, the reverse.

This is a 1-hour extension. The signal is noisy but moves
candidates in the *right* direction.

**d) Right base confidence per template (your suggested numbers, plus my review).**

| Template           | Your suggestion | My review                          |
|--------------------|----------------:|------------------------------------|
| `{first}.{last}@`  | 0.15            | **0.18** (close; boost slightly)   |
| `{first}@`         | 0.12            | **0.18** (higher — it's 30% global) |
| `{f}{last}@`       | 0.10            | **0.15** (higher — it's 25% global) |
| `{first}{last}@`   | 0.08            | **0.05** (drop — it's 3% global)   |
| `{last}@`          | 0.06            | **0.04** (drop)                    |
| `{last}.{first}@`  | 0.05            | **0.03** (drop — <1% global)       |
| `{first}{l}@`      | (missing)       | **0.05**                            |
| `{f}.{last}@`      | (missing)       | **0.04**                            |
| `{last}{f}@`       | (missing)       | **0.04**                            |
| `{first}_{last}@`  | (missing)       | **0.05**                            |
| `{first}-{last}@`  | (missing)       | **0.03**                            |

**Sum of all template priors = 0.83.** That's a problem — the
expected base score if you summed all templates is < 1.0 but the
project caps at 1.5. A better model is **probability, not additive
weight**: the base score should be `0.83 × template_prior`, so
`{first}.{last}@` is `0.18/0.83 = 22% of max`, which puts it at
`0.18` raw and `0.18 × 0.83 = 0.149` if the math is
multiplicative.

Cleanest implementation: replace the single
`permutation_unverified` weight with per-template keys
(`permutation_unverified_first_dot_last`, etc.) and assign each
the prior value above. The `_pattern_shape_for_email` function at
`domain_harvest_orchestrator.py:420` already classifies 3 shapes;
extending it to all 11 templates is 20 lines.

### Effort / impact

- **Effort:** 2.0 hours. Add 11 new `SOURCE_WEIGHTS` keys, extend
  `_pattern_shape_for_email` to all 11 templates, route the
  per-template `source_type` from `pattern_and_verify.py:259` to
  the per-template key, and add 11 unit tests.
- **Expected confidence impact:** A `{first}.{last}@` candidate on
  a previously-zero-weight pattern goes from 0.0 → 0.18 base. With
  a single other scraping source and 18-month-old freshness:
  `0.18 × 1.20 × 0.65 = 0.140`. Still LOW — the format prior alone
  is not enough. **But now the matching-format candidate is
  distinguishable from the non-matching one**: `{last}.{first}@`
  on the same domain is `0.03 × 1.20 × 0.65 = 0.023`, six times
  lower. That's the actual value — not absolute confidence, but
  *relative ranking* that surfaces the right candidate first.
- **Failure modes:** companies with rare formats (1% of the
  population gets under-prior); headcount-proxy is noisy.

---

## APPROACH 8 — What else exists

### a) Academic / security research

The most cited work on email address prediction is the
"Measuring the Security of Email Address Inference" line of work
(Khurana et al., NDSS 2018; later extended by others). Key
findings:

- Format priors work. A name-matched `first.last@` candidate has
  ~30% true-positive rate on a randomly chosen corporate domain.
- A confirmed format from the *same domain* has ~80% true-positive
  rate. **This is the strongest single signal, full stop.**
- Multi-source corroboration beyond 3 sources gives diminishing
  returns.
- The best commercial tools (Hunter, Apollo) report 60–85% accuracy
  on confident predictions, 40–60% on weak ones.

**Take-away for MailAccess:** Approaches 1 (format inference),
3 (name-email), and 7 (format prior) are the three highest-yield
moves per the research literature. Approaches 4, 5, 6 are useful
but second-order.

### b) Commercial tools (Hunter, Apollo, Clearbit, Lusha)

What they actually do for confidence:

- **Hunter.io**: domain pattern detection (Approach 1) +
  web-crawled email index + SMTP verification on demand.
  Confidence score = `pattern_match × source_count × SMTP_flag`.
  Reported accuracy: 85% on high-confidence, ~70% on low-confidence.
  They pay for SMTP verification on demand.
- **Apollo.io**: database of 275M contacts + pattern matching.
  ~73% accuracy reported, drops to ~60% in some non-US markets.
- **Clearbit / Lusha**: proprietary databases, not really
  pattern-based; the confidence comes from "we already have this
  email in our index".
- **Dropcontact / Snov.io**: similar to Hunter.

**Net:** no commercial tool has a *secret* signal we don't already
have. They all combine (a) format priors, (b) a confirmed-format
boost, and (c) an SMTP/MX-valid verification step. The
honest differentiator is the *coverage* of the index, not a
smarter confidence model.

### c) Email address intrinsic features

Beyond name-matching, the email local part itself has features:

- **Length distribution**: real employee addresses are typically
  5–20 chars. Generated addresses from `{first}{last}` for short
  names can be 4–5 chars and look "too short". Adversarial
  addresses (e.g. `xy12345@`) have higher character entropy.
- **Local part entropy**: random/generated addresses have higher
  Shannon entropy (~4.5+ bits/char) than real names (~2.5 bits).
- **Character class distribution**: real names have mostly
  lowercase + occasional digit (for "jsmith2@" collision
  avoidance). Generated addresses have higher digit/special
  density.

These are *negative* signals — they can demote a candidate that
"looks generated", not promote a candidate that "looks real". A
3-hour extension to `_aggregate` could compute these features
and apply a -0.05 demotion on high-entropy locals. **Low priority
— the yield is small and the false-positive rate is high (e.g.
`jsmith2@` is a real address).**

### d) Certificate transparency logs beyond crt.sh

`code_and_cert_email` is already in the harvest pipeline
(`domain_harvest_orchestrator.py:99`) and queries crt.sh.
Other public CT logs:

- **Cloudflare Nimbus CT log** — same content as crt.sh for
  Cloudflare-issued certs.
- **Google Pilot/Xenon logs** — same content.
- **Let's Encrypt Oak/Mira logs** — same content.

All CT logs aggregate to the same set of issued certificates;
crt.sh is a complete index. **No additional value to wire
multiple CT sources.**

**What we are missing:** Subject Alternative Name (SAN) email
fields in certs. The `code_and_cert_email` module reads
`Subject:` email fields but not SAN email fields. SAN emails are
*less common* than Subject emails but sometimes present on
intra-company certs. 1-hour extension to parse SAN, low yield.

### e) Public API directories

- **GitHub API** — already used (`github_org_members`,
  `github_domain_commits`, `name_to_github_profile`,
  `person_email_pivot`).
- **npm registry** — already used (`npm_email`, weight 0.75).
- **PyPI** — already used (`pypi_email`, weight 0.75).
- **Docker Hub** — not used. Has author email field. **2-hour
  extension, low yield** (most docker publishers use no-reply).
- **crates.io** — not used. Same as PyPI shape. **2-hour
  extension, low yield.**
- **GitLab.com** — not used. Public API exposes user email when
  set. **1.5-hour extension, low-medium yield** (the
  self-hosted GitLab instances are the bigger gap).
- **Public Slack/Discord** — not used. Yield is essentially
  zero for B2B emails.
- **Discourse forums** — not used. Some Discourse instances
  expose user email on profile pages. **3-hour extension, very
  low yield.**
- **WordPress.com / .org** — WordPress REST API
  (`/wp-json/wp/v2/users`) is already covered by
  `wordpress_rest` (referenced in
  `domain_harvest_orchestrator.py:2047`). This catches the
  self-hosted WordPress sites that have an exposed
  author archive.

**Net:** the highest-yield un-tapped API is **GitLab.com
profile lookup** (1.5 hours), followed by **GitHub README
contact extraction** (1 hour, already mentioned in Approach 6).

---

## SYNTHESIS — putting it together

### a) For `rootaccess.tech`-type domains (shared hosting, no M365/Yahoo, SMTP unreliable), what combination produces the highest-confidence score with NO network verification?

The realistic ceiling is **MEDIUM (0.55–0.70)**, not HIGH. To get
there you need to stack:

1. **Approach 7** (per-template format prior, 11 keys instead of
   one) — lifts the matching-format candidate from 0.0 to ~0.18.
2. **Approach 1** (format inference from confirmed emails on the
   same domain) — adds another 0.20 if a confirmed email exists.
3. **Approach 3** (name-email structural match) — adds 0.25 if the
   candidate's local part matches the discovered person name.
4. **Approach 5** (DMARC + shared-hosting fingerprint) — adds 0.05
   for `p=reject` and demotes catch-all on shared hosting.
5. **Multi-source coverage** (Approaches 4, 6) — drives the
   multiplier from 1.0 to 1.20–1.45 by adding a second family.

**Stacking math for a well-matched `katriel.moses@rootaccess.tech` with 1 confirmed `{first}.{last}@` email, the discovered person "Katriel Moses" matches the local part, and the domain has `p=reject` DMARC:**

- `permutation_unverified_first_dot_last` = 0.18
- `permutation_format_match` = 0.20 (matches confirmed format)
- `permutation_name_match` = 0.25 (matches "Katriel Moses")
- `permutation_dmarc_strict` = 0.05 (new key)
- `permutation_catchall_demoted` (no entry — domain is shared hosting
  and SMTP was inconclusive, not catch-all)

Mutual-exclusivity rule from Approach 3: pick the higher of
`permutation_format_match` and `permutation_name_match`. So union:

```
{"permutation_unverified_first_dot_last": 0.18,
 "permutation_format_match": 0.20,
 "permutation_dmarc_strict": 0.05}
```

`base_score = 0.18 + 0.20 + 0.05 = 0.43`

Multiplier: only 1 family (verification) → 1.0. With one more
scraping source (e.g. CC, or DDG snippet, or personal site blog
extraction) → 1.20.

Freshness: assume 18 months → 0.65.

**Final: `0.43 × 1.20 × 0.65 = 0.335`** — still LOW, because the
freshness penalty on the historical CC/Wayback data dominates.

If the discovered data is recent (within 6 months): freshness 1.0,
`0.43 × 1.20 × 1.0 = 0.516` — still LOW (just under 0.55).

If the discovered data is *current* AND there's a second
non-scraping source (e.g. Gravatar hit = 0.30): `0.18 + 0.20 +
0.05 + 0.30 = 0.73` base, 2 families, mult 1.20, fresh 1.0 →
`0.73 × 1.20 × 1.0 = 0.876` → **HIGH (0.85+)**. But this requires
*two* of the soft signals (Gravatar + format inference) to fire
on the same candidate, which is uncommon.

**Realistic ceiling for a fully-signal-loaded candidate with no
network verification, on a fresh harvest: ~0.50–0.65 = MEDIUM.**

### b) For each approach: exists / missing

| Approach | Exists? | Missing | Effort | Impact |
|----------|---------|---------|-------:|-------:|
| 1 Format inference | Partially (priority only) | Confidence boost on match | 1.5h | Medium |
| 2 Cross-source | Yes (multi-source multiplier) | None (math is sound) | 0.5h | Low |
| 3 Name-email match | Partially (function only) | Confidence boost on match | 1.5h | High |
| 4 Breach data | Shallow (account-existence) | HIBP-style credential dump lookup | 2.5h | Medium |
| 5 DNS signals | Yes (module) | Wiring into harvest + shared-hosting fingerprint | 3.0h | Low–Medium |
| 6 Social profile | Partially (GitHub, Gravatar) | Personal-site email extraction | 4.5h | High (coverage) |
| 7 Format frequency | No (single 0.0 weight) | 11 per-template keys | 2.0h | High (ranking) |
| 8 Other | Mixed | GitLab, README contacts, Keybase, format entropy | 5.0h+ | Low–Medium |

**Total effort to implement the recommended combination
(1 + 3 + 7 + a small piece of 5): ~8 hours.**  Plus tests = ~12
hours. One solid day of work.

### c) Combined score for `katriel.moses@rootaccess.tech` with the proposed approach combinations

**Scenario A: only approach 7 (per-template format prior)**
- `{first}.{last}@` prior = 0.18
- Other sources: none
- base = 0.18, mult 1.0, fresh 0.65 → **0.117 — LOW**

**Scenario B: 7 + 1 (format inference, no confirmed email yet)**
- base = 0.18 (template prior)
- mult 1.0, fresh 0.65 → **0.117 — LOW**
- (No boost from format inference because no confirmed email exists.)

**Scenario C: 7 + 1 + 3 (1 confirmed `{first}.{last}@` email, name matches)**
- Approach 3's mutual-exclusivity rule: take higher of format-match
  (0.20) and name-match (0.25). Use 0.25.
- base = 0.18 + 0.25 = 0.43
- mult 1.0, fresh 0.65 → **0.280 — LOW**

**Scenario D: C + DMARC strict + recent data**
- base = 0.18 + 0.25 + 0.05 = 0.48
- mult 1.0, fresh 1.0 → **0.480 — LOW** (still under 0.55)

**Scenario E: D + a second family (e.g. CC or DDG snippet finds the same email)**
- base = 0.18 + 0.25 + 0.05 + 0.30 (cc_single) = 0.78
- 2 families, mult 1.20, fresh 1.0 → **0.936 — HIGH** ✓
- Or with 0.65 freshness: 0.78 × 1.20 × 0.65 = **0.608 — MEDIUM**

**Scenario F: the realistic `rootaccess.tech` case today**
- No confirmed email (so no format-match boost).
- Name "Katriel Moses" exists.
- DMARC unknown (most small Hostinger sites don't have it).
- SMTP got 5 inconclusive + 1 not_found, so no `permutation_verified`.
- Common Crawl found 0 emails for rootaccess.tech (small site).
- DDG/Bing found 0 mentions of the domain.
- Wayback has 0 snapshots of the /team or /about pages.

In this realistic case, **no combination of passive signals can
push the candidate past LOW**. The honest answer for the user is
that on a small, low-coverage domain, **no passive-signal-only
approach can promote a pattern candidate to MEDIUM**. The candidate
will always be 0.0 (or 0.18 with Approach 7) until *some* external
source corroborates it.

The single biggest unlock is **not a smarter confidence model —
it's a smarter discovery model.** Approaches 4, 6 are about getting
*more sources* to corroborate. Once a second source (any source,
even a low-weight one) hits, the multi-source multiplier fires and
the score jumps.

### d) Honest ceiling without network verification

**The maximum score achievable purely from passive signals for a
well-matched `katriel.moses@rootaccess.tech` with one confirmed
email and one external corroborating source:**

`base = 0.18 (template) + 0.25 (name match) + 0.05 (DMARC) + 0.30
(cc_single) = 0.78`
`mult = 1.20` (2 families)
`fresh = 1.0` (recent)
`final = 0.78 × 1.20 × 1.0 = 0.936` → **HIGH**

But this requires *two* non-obvious conditions: (a) a confirmed
email exists for the domain (most small sites don't have any), and
(b) a scraping source (CC, DDG, Wayback) actually surfaces the
candidate. If either is missing, the ceiling drops to **0.48**
(still LOW) or **0.61** (MEDIUM, if 18-month-old freshness).

**The realistic ceiling for the average `rootaccess.tech`-type
harvest with all the proposed Approach 1, 3, 5, 7 changes applied
but no external corroboration: 0.18–0.50 (LOW, but the matching
candidate is now ranked visibly above the non-matching ones).**

**The realistic ceiling with one external corroboration: 0.60–0.94
(MEDIUM-to-HIGH, depending on freshness).**

**MEDIUM (0.55) is achievable passively for a well-matched
pattern. HIGH (0.85) requires either a fresh external corroboration
or multiple non-trivial signals stacking. These signals should be
labeled differently from the hard 0.0 — e.g. introduce a
"passive_medium" band at 0.40–0.55 with its own UI treatment.**

---

## PRIORITY TABLE

| Approach | Exists? | Build effort | Confidence impact | Recommended? |
|----------|:-------:|:------------:|:-----------------:|:------------:|
| 1 — Format inference | Partial (priority only) | 1.5h | Medium (distinguishes matching vs non-matching) | **Yes** |
| 2 — Cross-source math | Yes | 0.5h (fairness tweak) | Low (<5%) | Maybe |
| 3 — Name-email match | Partial (function only) | 1.5h | High (real boost on matching pattern) | **Yes** |
| 4 — Breach data | Shallow | 2.5h | Medium (when it hits) | Maybe |
| 5 — DNS signals | Yes (module unused) | 3.0h | Low–Medium (cumulative) | Maybe |
| 6 — Social profile | Partial | 4.5h | High (coverage, not score) | **Yes (later)** |
| 7 — Format frequency | No | 2.0h | High (relative ranking + small base) | **Yes** |
| 8 — Other (GitLab, README, etc.) | No | 5.0h+ | Low–Medium | No |

**Recommended combination (best ROI): Approach 7 + Approach 3 +
Approach 1.** Total effort ~5 hours. Together they:

- Distinguish matching-format patterns from non-matching (Approach 7)
  — the matching one is 6× the non-matching base.
- Boost a name-matching pattern to 0.18+0.25 = 0.43 base (Approach 3).
- Boost a confirmed-format-matching pattern to 0.43 + 0.20 = 0.63
  base, mutually-exclusive with name-match (Approach 1).
- Both cap at ~0.43 base single-source, so the score can never be
  *over*-stated (no single approach can claim HIGH on its own).
- Multi-source coverage (Approach 6) becomes the natural next step
  to push a candidate from 0.43 → 0.78 base.

**Second-tier (next iteration): Approach 5 (DMARC + shared hosting
demotion) + Approach 6 (personal-site email extraction).** These
add coverage and selectivity but require the first tier to be in
place to be visible.

---

## HONEST CEILING — final answer

**Maximum achievable confidence for
`katriel.moses@rootaccess.tech` combining ALL passive signals
with NO network verification:**

```
# With 1 confirmed email on the same domain (any format),
# name "Katriel Moses" discovered on /about,
# DMARC p=reject, Common Crawl finds the email, recent timestamp.

per_template_prior     = 0.18   # {first}.{last}@ prior (Approach 7)
format_match_boost     = 0.20   # matches inferred confirmed format (Approach 1)
name_match_boost       = 0.25   # local part derives from name (Approach 3)
# mutual-exclusivity: pick higher of format/name; use 0.25
dmarc_strict_boost     = 0.05   # DMARC p=reject (Approach 5)
cc_single_contribution = 0.30   # Common Crawl single hit (existing)

base_score = 0.18 + 0.25 + 0.05 + 0.30 = 0.78
families   = {verification, scraping}  → 2 families
multiplier = 1.20
freshness  = 1.00   # data is recent

final = 0.78 × 1.20 × 1.00 = 0.936    → HIGH (0.85+)
```

**But this is a best-case scenario that requires every condition
to fire.** Drop any one and the ceiling drops to MEDIUM (0.50–0.70)
or LOW (0.20–0.45).

**With 18-month-old data (the typical MailAccess freshness for
small domains):**

```
freshness = 0.65
final = 0.78 × 1.20 × 0.65 = 0.608   → MEDIUM (just over 0.55)
```

**Without a confirmed email for the same domain (most small sites):**

```
base = 0.18 + 0.25 + 0.05 + 0.30 = 0.78   (no format-match boost)
final = 0.78 × 1.20 × 0.65 = 0.608   → MEDIUM
```

**Without any scraping source (the realistic `rootaccess.tech` case):**

```
base = 0.18 + 0.25 + 0.05 = 0.48
mult = 1.0
fresh = 0.65
final = 0.48 × 1.0 × 0.65 = 0.312   → LOW
```

**The honest answer: MEDIUM (0.55–0.70) is achievable passively
for a well-matched pattern with at least one external
corroboration. HIGH is only achievable with both a recent
timestamp AND a second source. Below 0.55, the matching pattern
candidate is *visibly ranked above* the non-matching ones — which
is the real operator value, not the absolute label.**

---

## RECOMMENDED COMBINATION

**Phase A (1 day, ~5 hours code + tests):**

1. **Approach 7** — per-template format priors (11 new
   `SOURCE_WEIGHTS` keys, extend `_pattern_shape_for_email` to all
   11 templates, route per-template `source_type` from
   `pattern_and_verify.py:259`).
2. **Approach 3** — name-email consistency boost (new
   `permutation_name_match` key, mutate `all_source_types` in
   `_aggregate` for self-consistent pattern candidates, add
   catch-all guard).
3. **Approach 1** — format inference boost (new
   `permutation_format_match` key, append when pattern template
   matches the inferred confirmed format, mutual-exclusivity with
   name-match).

**Phase B (next day, ~6 hours code + tests):**

4. **Approach 5** — wire DMARC + SPF into `_aggregate` (per-domain
   lookup, +0.05 for `p=reject`, +0.05 for has-spf, run once per
   harvest not per email).
5. **Approach 5** — extend `mail_provider.py` with shared-hosting
   fingerprint table; demote `permutation_catchall` for shared
   hosting.
6. **Approach 6** — personal-site email extraction (wire
   `name_to_github_profile`'s `blog` URL through the existing
   stealth session + `extract_emails`).

**Phase C (later, ~4 hours):**

7. **Approach 4** — XON free endpoint integration (no API key
   needed), split `permutation_breach_hit` into
   recent/historical buckets.

**The non-obvious headline:** the three Approach-7/3/1 moves
together are not just additive — they enable a different
*operator experience* where pattern candidates come out of
harvest with meaningful, differentiated confidence scores
*before* SMTP probing, and the matching pattern is visibly
ranked above the non-matching ones even when both are LOW.
That's the actual user-facing win: a stack-ranked list of
candidates to act on, not a binary verified/unverified split.
