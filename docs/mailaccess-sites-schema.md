# `data/mailaccess_sites.json` — unified site schema (v1)

> **Program-wide decision.** This schema is introduced in 0.15.0 as the single native
> corpus for all platform probing. Over the 0.15.0 de-vendor waves it **replaces** every
> legacy per-tool JSON list and remote fetch (and folds in `mailaccess-extra-sites.json`).
> It must therefore represent **both** check paradigms from day one:
>
> - **`email-existence`** — probe a site with an *email address* and read a
>   registered/not-registered signal.
> - **`username-url`** — probe a per-username profile URL and read a present/absent
>   signal.
>
> It is a deliberate **superset** of the existing `is_email_only` convention in
> `data/mailaccess-extra-sites.json` and of the legacy username site dicts, so those
> merge in with a field rename, not a redesign.

## Top-level shape

```jsonc
{
  "_meta": {
    "schema_version": 2,
    "source": "mailaccess",
    "description": "Unified MailAccess site corpus for email-existence and username-url probing.",
    "site_count": 5365,
    "provenance": "MailAccess-assembled compilation of publicly-observable account-existence facts (probe URL + existence marker per platform). Endpoints, markers and detection logic are original MailAccess implementations, verified live by the MailAccess probe engine. Not a copy of any third-party list.",
    "detection": "All rows route through the unified probe_detector across both check paradigms."
  },
  "sites": {
    "<id>": { /* site definition */ }
  }
}
```

`sites` is keyed by **`id`** (the canonical, stable slug). The key and the `id` field
must match.

## Site definition fields

### Identity & dedup (all paradigms)

| field | req | meaning |
|---|---|---|
| `id` | ✔ | canonical slug, matches the `sites` key (e.g. `"spotify"`). |
| `name` | ✔ | display label; becomes the finding `platform` value. **For email-existence sites this MUST equal the platform's canonical module name** so the finding shape is unchanged (non-breaking). |
| `domain` | ✔ | primary domain (e.g. `"spotify.com"`). |
| `dedup_key` | ✔ | **normalized domain** used for cross-source dedup once other tools merge in. Computed like `platform_dedup.dedup_key` (host, minus known subdomain prefixes). Multiple tool entries for one platform share this key. |
| `category` | ✔ | e.g. `music`, `social_media`, `forum`. |
| `check_type` | ✔ | **discriminator**: `"email-existence"` or `"username-url"`. |
| `attribution` |  | optional free-form provenance tag for a row's source wave. Unused by current rows (corpus-level provenance lives in `_meta.provenance`). |

### Probe definition (shared by both paradigms — reuses probe_detector/pre_check)

| field | meaning |
|---|---|
| `uri_check` | probe URL template. Placeholder is **`{email}`** for `email-existence`, **`{username}`** for `username-url`. Also accepts pre-check tokens (below). |
| `url` | human profile/site URL (used as the finding `profile_url`; falls back to `https://{domain}`). |
| `requestMethod` | `GET` \| `POST` \| `HEAD`. |
| `requestPayload` | dict → JSON/form body (engine picks JSON when a `Content-Type: application/json` header is present, else form), or a raw string body. Supports `{email}`/`{username}` + pre-check tokens. |
| `headers` | request headers. Supports pre-check token placeholders. |
| `flow` | *semantic only* — probe method: `register` \| `login` \| `password-recovery` \| `other`. Recovery-leaking sites use `password-recovery`. |

### Hit / miss classification (identical contract to `probe_detector.detect_hit`)

| field | meaning |
|---|---|
| `e_code` + `e_string` | EXISTS: HTTP status == `e_code` **and** `e_string` in body. |
| `m_code` + `m_string` | NOT-EXISTS: status == `m_code` **and** `m_string` in body. |
| `checkType` | alt to code/string pairs: `status_code` \| `message` \| `response_url` (username-url style). |
| `rate_limited_strings` | body markers that mean rate-limited/blocked → result `rateLimit=true`, `exists=None`. |

Anything not matching hit/miss/rate-limit is **inconclusive** (`exists=None`).

### Session bootstrap (extended `pre_check` — see below)

```jsonc
"pre_check": {
  "url": "https://site/login", "method": "GET",
  "extract_cookie": true, "cookie_name": "csrftoken",
  "extract_csrf": "meta[name='csrf-token']",       // arbitrary name now supported
  "extract_regex": { "my_post_key": "var my_post_key = \"([^\"]+)\"" }
}
```

Extracted values are usable anywhere in `uri_check` / `headers` / `requestPayload` as:
`{csrftoken_value}`, `{csrf_token}`, `{<cookie_name>_value}`, and **`{<regex_token_name>}`**.

### Field extraction (recovery hints — new)

`detect_hit` only returns hit/miss; recovery-leaking sites add `extract_fields`, applied
to the probe response **on a hit**:

```jsonc
"extract_fields": {
  "phone_hint":     { "source": "json", "path": "body.phones", "join": ", ", "mask": "phone" },
  "email_recovery": { "source": "json", "path": "body.emails", "join": ", ", "mask": "email" },
  "account_created":{ "source": "regex", "pattern": "...", "group": 1 }
}
```

- `source`: `json` (dot/int path into the parsed JSON) or `regex` (against body text).
- `mask`: `phone` \| `email` \| `none` — recovery hints are always stored **masked**.
- Output field names map onto the finding: `email_recovery`→`metadata.email_recovery`,
  `phone_hint`→`metadata.phone_hint`; anything else lands in `metadata.extras`.

### Bespoke logic & lifecycle

| field | meaning |
|---|---|
| `handler` | name of a native handler in `account_probe_handlers` for sites that can't be expressed declaratively (multi-request control-email, multi-step recovery relays, JS-blob token surgery). When set, the declarative probe fields are ignored (the handler owns the flow) except `id`/`name`/`domain`/`health_key`. |
| `recovery` | `true` if the site leaks recovery email/phone (drives `high_value` + is skippable via `--no-password-recovery`). |
| `high_value` | `true` to always flag the finding high-value. |
| `health_key` | platform key for `platform_health` (default `"account_discovery:{id}"`). Chosen so health stats line up across tools as they migrate onto shared ids. |
| `frequent_rate_limit` | hint that the site rate-limits aggressively. |
| `disabled` + `disabled_reason` | exclude from probing but keep the row (documents coverage of a dead/broken upstream site, same convention as `mailaccess-extra-sites.json`). |

## Forward-compatibility proof — a `username-url` row

The same schema represents a username profile probe with **no new machinery**
(`{username}` placeholder + `checkType`), demonstrating the superset property:

```jsonc
"github_username": {
  "id": "github_username", "name": "GitHub", "domain": "github.com",
  "dedup_key": "github.com", "category": "coding",
  "check_type": "username-url",
  "uri_check": "https://github.com/{username}",
  "url": "https://github.com/{username}",
  "requestMethod": "GET",
  "checkType": "status_code", "e_code": 200, "m_code": 404
}
```

## Dedup / merge rule (how Phases 3–8 join without collisions)

The **merge key is `dedup_key`** (normalized domain), and dedup is applied **within a
paradigm**:

- **Within `email-existence`** every `dedup_key` is unique (asserted in tests). When a tool
  contributes an email-existence site whose key already exists, it merges into that row
  (revive / replace / keep — see the Phase 2 audit).
- **Within `username-url`** every non-disabled `dedup_key` is likewise unique — mirrors and
  duplicates collapse to one row.
- **Across paradigms** an `email-existence` row and a `username-url` row for the **same**
  platform intentionally **coexist as two rows** sharing a `dedup_key` (e.g. `github` +
  `github_username`). They are collapsed at *runtime* by
  `platform_dedup.deduplicate_platform_findings`, which also rewards **dual confirmation** when
  two independent enumeration sources see the same platform. Merging them into one row would
  destroy that signal.

`methods: [...]` (forward option) — a single row *may* one day carry multiple probe methods
(an `email-existence` probe *and* a `username-url` probe) so runtime/health can select the best.
The loader tolerates its absence: **when `methods` is absent the top-level probe fields are the
sole method** (all current rows). As of Phase 3 no row uses `methods` — cross-paradigm overlaps
are separate rows (above) because that preserves dual-confirmation.

## Schema v2 (username-url corpus build-out)

`schema_version` is **2**. The change is purely **additive** (v1 rows are valid v2 rows):

- **Bulk `username-url` population.** ~4,900 sites are assembled as `username-url` rows.
  They exercise the richer detection fields already defined above: `presenseStrs` / `absenceStrs`
  (message markers), `errors` / `errorUrl` (error markers), `regexCheck` (username validity),
  `ignore403`, `protection` (bot-wall hint → Wave 2), `tags` + `alexaRank` (wave/confidence
  heuristics), and `usernameClaimed` / `usernameUnclaimed` (catch-all calibration).
- **Engine templates are pre-expanded.** Where families of ~2,500 sites share an engine
  (XenForo/phpBB/Discourse/…), the build step bakes each engine's markers/URL template into its
  member rows (and substitutes `{urlMain}`/`{urlSubpath}`), so **every row is self-contained** —
  there is no `engines` section in the corpus and the runtime detector needs no engine lookup.
- **Profile extraction is code-side, not schema.** Person-data (`display_name`/`bio`/`location`/
  `avatar_url`) is extracted from a hit page at probe time by `backend/core/profile_extractor.py`
  and attached to the finding's `metadata` — it is **not** a per-site field.

## Corpus reconciliation waves

The `username-url` corpus was built up in additive waves (no new fields at any step). Each wave
reconciled its incoming site definitions against the existing corpus by `dedup_key`:

- **Popular-site revival wave.** 57 rows previously carried as `disabled` are **revived** from a
  live probe spec, and 7 bare `status_code` rows are enriched with an endpoint-matched
  `absenceStrs` marker; redundant URL-form variants are skipped and 15 net-new rows added. Two
  code-side detection upgrades ship with this wave: a shared WAF/bot-wall guard
  (`backend/core/waf_fingerprints.py`) and templated-`errorUrl` username substitution in
  `probe_detector`.
- **Regional/forum wave.** 310 additional `username-url` sites are reconciled the same way: 17
  dead rows revived, 7 bare `status_code` rows enriched, redundant variants skipped, and 42 net-new
  **regional/forum** rows added (the long tail the general corpus under-covers). Their `error_code`
  is uniformly `[404]` (subsumed by `detect_hit`) and their remaining error/character-stripping
  quirks are all covered overlaps, so no net-new/revived row needs that machinery.
- **Two-marker wave.** A 737-site dataset is merged: 29 revived, **92 bare-`status_code` rows
  upgraded in place to the two-marker `e_code`/`m_code`/`e_string`/`m_string` scheme**
  (endpoint-matched), redundant rows skipped, 223 net-new. The **two-marker** detection (a hit needs
  the existence marker present AND the absence marker gone, from one response) is folded into
  `probe_detector.detect_hit`'s `e_code`/`m_code` branch, benefiting all 557 e/m rows at no extra
  request. `strip_bad_char` (username character stripping) is applied by `probe_platform`. The two
  legacy probe detectors were collapsed into the single `probe_detector`.

Final corpus: **5,365 sites**.

## Runtime fold (no schema/data change)

The `username_platforms` and `username_pivot` flows read the two-marker `username-url` rows directly
from the unified corpus (selected by their `e_code`/`m_code` signature). All legacy per-tool JSON
lists and on-disk caches are deleted; the corpus is the single source of truth.
