# MailAccess 0.14.5 — Per-Phase Validation Checklist (live-path)

Legend: ✅ pass · ❌ fail · ⚠️ partial/caveat · ⏳ pending live run · ⏭️ deferred/optional

## 0. Preconditions
- ✅ `uv sync --extra dev` clean (143 pkgs resolved, exit 0), Python 3.10.6, uv 0.12.9
- ⏳ Gate baseline refresh (snapshot running)
- ❌/⏳ Truth labels: still empty stubs — need owner sign-off (blocker for quality metrics)
- ✅ v0.14.4 capstone baseline present (8 targets × 3 runs, both pipelines, keyless)

## 1. Substrate & migrations
- ✅ Alembic fresh→head (0001–0009)
- ✅ Existing v0.14.4 DB (rev 0002) → head, seeded row survives (no data loss)
- ✅ downgrade→base→re-apply clean
- ✅ Schema matches ORM (autogenerate produced empty up/down)
- ✅ Async Postgres driver documented correctly (.env.example + self-hosting.md); live connect = optional
- ⏳ 1B budget / 1C ledger / 1D corpus / 1E conflict — live-path

## Code-level invariants (confirmed by Read; live/test confirmation pending)
- ✅ 3D catch-all terminal → GRADE_CATCH_ALL; never Valid without per-mailbox oracle (deliverability_grade.py:152-155); test_catchall_accept_is_never_valid asserts it
- ✅ 2C reset_prober guard: `if not is_security_mode(): return None` (reset_prober.py:213) — defense-in-depth outside gate
- ✅ 2F security.py: off-localhost no-key ⇒ refused; per-principal fixed-window quota → HTTP 429; LOCAL_HOSTS frozenset
- ✅ 3A evidence-or-null: person fields populated only when an evidenced claim resolves via 1E, else None (lead_person.py:13-18)
- ✅ 7A enrichment weights below native: apollo 0.28 / pdl 0.24 < 0.30 neutral < native (github 0.85-0.95, hunter 0.85, perm_verified 0.65)

- ✅ 2D eligibility: enum {eligible,review,suppressed,research-only}; suppressed→SUPPRESSED; Invalid/Catch-all→research-only; verdict independent of confidence; _OUTREACH_VERDICTS={ELIGIBLE} only (eligibility.py)
- ✅ 6B safe-artifact: exhaustive + fail-closed ("Unknown kind → NEVER"); contact-level→REVIEW_REQUIRED, distributable only if reviewed; PII-scan defense-in-depth downgrade (safe_artifact.py)
- ✅ 2E audit_log: sha256 hash chain (GENESIS→prev_hash), verify() reports broken_at_seq on tamper (audit_log.py) — live tamper test pending
- ✅ Exporters present: csv/json/maltego/markdown/pdf/prov/stix (7); orgchart json/html separate (7C)
- ✅ API routes: investigations/leads/maltego/graph/health/modules; leads has /{domain}, /{domain}/changes (6F), /verification-history

- ✅ 1E claim resolver: human+machine reasoning; losers retained (reasoning_data "beat" list) (claim_resolver.py)
- ✅ 5C discovery_confidence its own claim, never in contact-confidence vocabulary; noisy-OR (company_discovery.py)
- ✅ 6F change intel: likely_new_hire/likely_departure/verification_drift/likely_stale from consecutive-crawl diffs (change_intelligence.py)
- ✅ 4B metric suite (brier, per-source-FP) + gate refuses candidate raising per-source FP (calibration_metrics.py); 4D no promoted weights ⇒ hand-tuned stays (calibration.py)

## FIXES APPLIED (all verified; final gate check GREEN: 0 new vs baseline)
- ✅ BUG-1: added apollo/pdl to SOURCE_CLASS ("api") in email_confidence.py — test_source_class_mapping_complete green; no scoring regression
- ✅ BUG-2: test_aggressive_passes_true_to_dork pins cc_first=False via monkeypatch — green
- ✅ BUG-3: test_slow_module_gets_partial_result pins cc_first=False — green
- ✅ BUG-5 + BUG-4 (one root cause: cold-DB init race): corpus_store._ensure_schema() once-per-process guard on read_fresh_crawl + read_verification_history. Verified live: cold harvest 0 table errors, score_feature_snapshots 0→4. New regression test test_cold_db_read_first_ensures_schema_no_error (corpus suite 11 passed).
- ✅ ENV-1 harness hardening: pytest_baseline._run_one isolates TEMP/TMP/TMPDIR per file (gate robust to host temp ACLs)

## Live-path checks (all PASS)
- ✅ 1B budget (lavelle exit-0) + forced-low-budget partial (exit-0, modules truncated listed, no exit-3)
- ✅ 1C ledger (333 obs, full provenance) · 1D parity + 57× speedup · 1E reasoning
- ✅ 2E audit tamper detected (broken_at_seq=1) · 2F api_auth 9/9 · 4B calibrate (powered promotes / underpowered refuses)
- ✅ 3C score + 3D grade 100% coverage · 3A person evidence-or-null · 2D verdicts independent of confidence
- ✅ 4A capture accrues on live harvest (post-fix)

## VERDICT: GO for 0.14.5 (security clean, gate green, no default-mode regression, all found bugs fixed)

## Gate baseline (PRECONDITION) — CONTAMINATION FOUND & CORRECTED
- ⚠️ First snapshot (default TEMP) = 292 fail / 111 ruff / 3 hung. Diff vs old 279: 0 dropped out, 13 newly-baselined.
- ✅ Triaged all 13: 10 were ENVIRONMENTAL (ACL-broken pytest temp dir; pass with clean TEMP) — must NOT be baselined in.
- ⚠️ 3 genuine: BUG-1 (apollo/pdl missing from SOURCE_CLASS, real), BUG-2/BUG-3 (stale cc-first tests). See BUGS.md.
- ✅ Authoritative baseline (fixed harness, no workaround): **63 test / 111 ruff / 3 hung**. Vs old 279: 0 genuinely-new baselined in (all 63 ⊂ old 279); ~216 env-noise removed; 3 phase-feature tests fixed & dropped out.
- ✅ `gate check` GREEN: 63/63 (0 NEW, 0 fixed), ruff 111/111 (0 NEW), hung 3/3 (0 NEW).

## 8. Full-tool regression (test-level)
- ✅ Policy/governance suites: 111 passed (test_policy, test_policy_modes, test_product_mode, test_eligibility, test_suppression, test_governance) + 2 never-baseline (test_safe_artifact, test_corpus_contribution)
- ✅ Phase 3-7 feature suites: 179 passed (deliverability_grade/score, lead_person, seniority, lead_export, observation_ledger, corpus_store, claim_resolver, scoring_capture, promotion_gate, org_chart, change_intelligence, enrichment_waterfall, technographics, bulk_harvest, company_discovery, corpus_decay, corpus_distribution)
- ✅ Full gate green (above) = no new ruff/test/hang across the whole suite

## 7D dead code
- ✅ google_search/haveibeenpwned/subdomain_surface files gone; 80 modules registered; none of the 3 registered; imports clean; registry auto-discovery intact
