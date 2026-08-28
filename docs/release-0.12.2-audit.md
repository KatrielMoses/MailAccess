<a href="../README.md">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/brand/mailaccess-logo-reversed.svg">
    <img src="../assets/brand/mailaccess-logo.svg" alt="MailAccess" height="28">
  </picture>
</a>

# MailAccess 0.12.2 Audit Guide

## Purpose

Version 0.12.2 is an audit-preparation release. Its purpose is to support a
controlled comparison of MailAccess against Blackbird, Holehe, Maigret,
Sherlock, and theHarvester.

This release is not a claim that MailAccess will produce identical results to
those tools. Differences should be recorded and explained by source coverage,
probe semantics, authentication requirements, or false-positive controls.

## Scope

The comparison should cover:

- email existence and account-discovery results;
- username/platform discovery where the tools overlap;
- false positives and false negatives using known test accounts;
- endpoint failures, WAF blocks, redirects, and inconclusive results;
- runtime, request counts, and timeout behavior;
- output stability and reproducibility.

PDF generation is outside the scope of this release and should not be used as
an audit gate.

## Active email-existence sources

The current active direct email probes are:

| Platform | Probe status |
| --- | --- |
| Spotify | Active; JSON status markers |
| Eventbrite | Active; session/CSRF pre-check and JSON existence markers |
| Chess.com | Active; `isEmailAvailable` markers |
| Adobe | Active; authentication-methods response markers |
| El Mundo | Active; registration response markers |

The following sources are retained as documented definitions but disabled from
live scans because current verification found WAF blocks or stale/unreliable
response markers: Notion, NetShoes, OLX, Milanuncios, Picsart, and Imageshack.

## Recommended comparison protocol

Use the same input set, network conditions, proxy policy, timeout, and email
normalization for every tool. Run each input at least twice and preserve the
raw outputs.

For each tool, record:

| Field | Description |
| --- | --- |
| input | Exact email or username tested |
| tool/version | Tool and installed version |
| found | Normalized positive findings |
| not_found | Explicit negative findings |
| inconclusive | Timeout, WAF, redirect, CAPTCHA, or parser failure |
| errors | Exact error text |
| duration | Wall-clock runtime |

Do not count an inconclusive response as a negative result. Compare normalized
platform names and canonical account URLs, then inspect disagreements manually.

## MailAccess verification baseline

Before an audit run, execute:

```powershell
python -m pytest tests/test_pre_check.py tests/test_email_platforms.py tests/test_email_detector.py -q
ruff check backend/core/pre_check.py backend/core/maigret_detector.py backend/core/blackbird_detector.py backend/modules/maigret_platforms.py
```

The 0.12.2 baseline includes regression coverage for pre-check ordering,
cookie and CSRF propagation, optional pre-check behavior, email-definition
schema validation, disabled-source exclusion, and same-status JSON hit/miss
classification.

## Interpretation

MailAccess should be considered audit-ready when the baseline passes and the
comparison report separates confirmed hits, confirmed misses, and
inconclusive/error outcomes. It should not be called release-ready solely
because a third-party tool reports a different platform count.
