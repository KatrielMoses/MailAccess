# Phase 0 — First Baseline Findings (v0.14.4, keyless-default)

Observations from the first harness runs against the authorized own-domain
targets. These are the "before" numbers; later phases report against the same
scorecard shape. (Full artifacts live under `eval/scorecards/<run_id>/`, gitignored.)

## Harvest — `rootaccess.tech` (keyless, isolated)

- **Yield:** 48 unique emails — **all LOW tier** (CONFIRMED/LIKELY/MEDIUM = 0/0/0, LOW = 48).
  Keyless surfaces raw addresses but confirms none.
- **Deliverability:** `smtp_verification_used = true`, but 0 verified / 0 not-found /
  0 inconclusive — SMTP RCPT produced no verdicts (port 25 egress almost certainly
  blocked on this host). Catch-all: not detected. Pattern: none confirmed.
- **Latency:** ~468 s wall. 12 modules ran (commoncrawl_email, wayback, code_and_cert,
  email_search_dork, npm/pypi_email, public_surface_sweeper, public_forge,
  package_ecosystems, subdomain_intel, pgp_domain_email, github_org_members);
  `github_org_members` and `ripe_stat_asn` skipped.
- **Resilience:** DuckDuckGo returned HTTP 202 CAPTCHA/block for dork queries — the
  known search-engine fragility (Pillar E in the requirements brief).

## Investigate — `lavellenetworks.com` corporate email (keyless, isolated)

- **Result:** does **not complete within the tool's own hard 120 s completion cap**
  (`cli/main.py` `_MAX_POLL_ATTEMPTS = 60 × 2 s`), so the CLI returns exit code 3
  ("server unavailable") with no report. Reproduced twice (~133–140 s wall).
- **Root cause (baseline observation, not a harness bug):** the default module set
  includes `maigret_platforms` (opt-in but ON by default) plus many live
  platform-probing modules; collectively they exceed 120 s under live conditions.
  The 120 s cap is not CLI-configurable at v0.14.4.
- The harness records this correctly as `ok=false, exit_code=3, timed_out=false`
  (the tool self-terminated; the harness did not).

### Investigate scoring path — validated separately

Because the full default investigate exceeds 120 s, the investigate **scoring path**
was validated with a restricted fast module set (`--modules gravatar`) against an
own-domain email: the `--output json` report carries all fields the scorer reads
(`findings` [129], `module_runs`, `exposure_score` [14], `risk_level` [low],
`confirmed_name` ["Katriel"], `name_confidence`, `credential_risk_score`).
`score_investigate` produced `name_correct=true` and `precision=0.5` against a
synthetic 1-TP/1-FP truth — confirming the end-to-end investigate → scorecard path.

## Harness correctness fixes made during bring-up

- **Encoding:** the harness read child output as Windows cp1252 and crashed on the
  tool's UTF-8 box-drawing bytes (`UnicodeDecodeError`). Fixed to
  `encoding="utf-8", errors="replace"`.
- **Keyless manifest:** the manifest reported the harness parent's keys/opt-ins.
  Fixed so a keyless run reports `keys_present = {}` and opt-in toggles = code
  defaults (what the tool actually saw).
- **Contamination guard:** investigate aborts if `127.0.0.1:8000` is already in use,
  so it can't latch onto a foreign (keyed) server.

## Open baseline questions for later phases

- Investigate's 120 s cap makes the *default* investigate un-baselinable end-to-end
  on a live host — a later phase should make the completion budget configurable, or
  the harness should pin a fast module set for the investigate baseline.
- SMTP verdicts are empty when port 25 is blocked; the deliverability baseline needs
  a port-25-open host or the SMTP-less scoring path (requirements Pillar D3).
