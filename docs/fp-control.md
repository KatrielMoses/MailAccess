# False-Positive and False-Negative Control

MailAccess applies the following controls before treating collected signals as
corroborated identity or credential-risk evidence.

## Contents

- [Common-Name Filter](#common-name-filter)
- [Disposable Domain Detection](#disposable-domain-detection)
- [Maigret Catch-All Detection](#maigret-catch-all-detection)
- [Detector Response Hardening](#detector-response-hardening)
- [Multi-Language Reset Signals](#multi-language-reset-signals)
- [Avatar pHash Clustering](#avatar-phash-clustering)
- [Bio Fuzzy Similarity](#bio-fuzzy-similarity)
- [Name Consensus](#name-consensus)
- [Platform Health](#platform-health)
- [Temporal Clustering and Shadow Profiles](#temporal-clustering-and-shadow-profiles)
- [Platform Deduplication](#platform-deduplication)
- [Credential Risk Calibration](#credential-risk-calibration)

## Common-Name Filter

Reduces false identity matches when a common name or username appears without
independent corroboration. The corpus and lookup helpers live in
`data/common_names.json` and `backend/core/common_names.py`; name-confidence caps
are applied in `backend/core/name_consensus.py`, while enumerators set confidence
to `low` and add `common_username_no_corroboration` to
`metadata.fp_warnings`. A name such as John Smith recovered from Gravatar may
therefore remain `probable` instead of becoming `confirmed`.

```json
{
  "username": "john.smith",
  "confidence": "low",
  "metadata": {
    "fp_warnings": ["common_username_no_corroboration"]
  }
}
```

## Disposable Domain Detection

Reduces false confidence in identifiers created on short-lived email providers.
The bundled corpus and helpers live in `data/disposable_domains.json` and
`backend/core/disposable_domains.py`; affected enumerator findings are lowered to
`confidence: "low"` and include `disposable_email_domain` in
`metadata.fp_warnings`. Investigation preflight also exposes the broader
`email_credibility.is_disposable` result.

```json
{
  "username": "analyst@mailinator.com",
  "confidence": "low",
  "metadata": {
    "fp_warnings": ["disposable_email_domain"]
  }
}
```

## Maigret Catch-All Detection

Prevents false hits from status-code platforms that return a valid profile page
for arbitrary usernames. `backend/modules/maigret_platforms.py` probes the 50
highest-ranked eligible platforms with each platform's `usernameUnclaimed` value
before the main sweep; a positive control is skipped and counted in
`metadata.catch_all_skipped` for that run.

```json
{
  "total_platforms_checked": 2180,
  "platforms_confirmed": 14,
  "catch_all_skipped": 3
}
```

## Detector Response Hardening

`backend/core/maigret_detector.py` applies `absenceStrs` to `status_code`
checks as well as body-match checks. Before pattern matching, it decodes HTML
entities so encoded failure text cannot become a false hit. A `200 OK` response
with less than 500 bytes of content is treated as inconclusive, and platform
definitions may raise that floor with `expected_content_length_min`.

## Multi-Language Reset Signals

Reduces false negatives when password-reset pages answer in a language other than
English. `data/reset_signals.json` contains English, German, French, Spanish,
and Portuguese success and failure phrases, and
`backend/core/reset_prober.py` detects the response script, decodes HTML entities
and URL encoding, then returns `true`, `false`, or `null`; `null` means blocked,
unreachable, or inconclusive rather than a confirmed miss.

```json
{
  "language_hint": "ES",
  "decoded_signal": "correo enviado",
  "classification": true
}
```

## Avatar pHash Clustering

Reduces false negatives caused by resized, recolored, or recompressed copies of the
same profile image. `backend/core/avatar_hasher.py` computes 64-bit perceptual
hashes and `backend/core/enrichment/avatar_clusters.py` groups hashes within a
Hamming distance of five; a cluster is corroborating evidence, not identity proof
by itself.

```json
{
  "phash": "8f0f0f0f0f0f0f0f",
  "platforms": ["github", "twitter", "reddit"],
  "cluster_size": 3
}
```

## Bio Fuzzy Similarity

Reduces false negatives when the same biography is reordered or lightly edited
across platforms. `backend/core/bio_similarity.py` strips URLs, normalizes text,
and uses RapidFuzz token-set similarity; `backend/core/enrichment/bio_clusters.py`
turns sufficiently similar observations into cluster evidence. The score is on a
0–100 scale and should be interpreted alongside platform and identity signals.

```json
{
  "platforms": ["github", "linkedin", "twitter"],
  "similarity_score": 94.1,
  "cluster_size": 3
}
```

## Name Consensus

Controls both false positives and false negatives from spelling variation, stale
signals, and non-Latin names. `backend/core/name_consensus.py` uses RapidFuzz
clustering, temporal decay, Unicode-aware normalization, and common-name caps;
interpret `name_confidence` as `confirmed`, `probable`, `possible`, or `unknown`
rather than as a binary identity assertion.

```json
{
  "confirmed_name": "Алексей Иванов",
  "name_confidence": "probable",
  "confidence_score": 2.18,
  "name_sources": ["github_profile", "orcid_profile"]
}
```

## Platform Health

Reduces repeat false positives and wasted probes from persistently noisy or broken
platform definitions. `backend/core/platform_health.py` stores probe history in
`~/.mailaccess/platform_health.db`. Platforms with more than 70% inconclusive
results after 50 probes are skipped; those above 40% after 30 probes are demoted
to Wave 2. Reliable Wave-2 platforms can be upgraded to Wave 1. Every action is
logged to `~/.mailaccess/platform_demotion.log`, and
`MAIGRET_FORCE_<PLATFORM>=true` overrides an automatic action.

```json
{
  "platform": "reset_prober:example.com",
  "hit_rate": 0.02,
  "consecutive_misses": 11,
  "health_skipped": 1
}
```

## Temporal Clustering and Shadow Profiles

Reduces false negatives where coordinated accounts or alternate-email profiles are
weak in isolation. `backend/core/enrichment/temporal_cluster.py` groups nearby
creation dates, while `backend/core/enrichment/shadow_profiles.py` pairs matching
multi-token display names on different non-anchor emails; shadow confidence is
`high` only when the username also matches, otherwise `medium`.

```json
{
  "primary_platform": "twitter",
  "shadow_platform": "steam",
  "display_name": "Jane Doe",
  "shared_username": "janedoe",
  "confidence": "high"
}
```

## Platform Deduplication

Prevents duplicate enumeration hits from inflating platform counts and distinguishes
independent corroboration from repeated collection. `backend/core/platform_dedup.py`
normalizes profile domains across WhatsMyName, Maigret, Sherlock, and Nexfil;
agreement from at least two enumeration sources sets
`metadata.dual_confirmed: true`, records `sources`, and raises confidence to
`high`. More than two agreeing sources also emit a warning so data overlap can be
reviewed.

```json
{
  "profile_url": "https://github.com/janedoe",
  "confidence": "high",
  "sources": ["maigret", "sherlock"],
  "metadata": {
    "dual_confirmed": true
  }
}
```

## Credential Risk Calibration

Reduces categorization false negatives and prevents weak signal volume from
dominating credential risk. `backend/core/credential_risk.py` matches exact
normalized platform and host-label tokens against the six-category
`data/service_categories.yaml` catalog, applies bounded component weights, and
forces a `CRITICAL` floor for infostealer evidence. Interpret the band with
`score_drivers` and `recommended_actions`, not as a standalone breach claim.

```json
{
  "credential_risk_score": 84,
  "credential_risk_band": "CRITICAL",
  "score_drivers": ["Infostealer evidence detected"],
  "recommended_actions": ["Reset exposed credentials and revoke active sessions"]
}
```
