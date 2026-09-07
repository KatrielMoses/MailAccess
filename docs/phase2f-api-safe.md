# Phase 2F — API safe-by-default

Closes the open-by-default API surface (Doc-1 #19 / Doc-2 I3) before MailAccess is
ever exposed beyond localhost. Touches the API layer only, not the mode/policy
core, so it lands in parallel with the rest of Phase 2. Local CLI
`investigate`/`harvest` UX is unaffected.

## Auth mandatory off-localhost

`backend/api/middleware/auth.py` + `backend/api/security.py`:

- `/health` stays open (liveness).
- With **no** API key configured, the open bypass now applies **only** to local
  (loopback) callers — a **non-local** caller with no key configured is refused
  (`503`, "set MAILACCESS_API_KEY to expose MailAccess to non-local clients").
  Localness is determined from the request's client host (loopback / `testclient`).
- With a key configured it is enforced on every protected surface. The Maltego
  transform route (`/maltego/`) is **no longer bypassed** — its expensive
  full-investigation path now requires the key. The API key may be presented via
  the `X-API-Key` header or an `api_key` query param (for clients that can't set
  custom headers).

## Authenticated WebSocket

`BaseHTTPMiddleware` does not run for WebSocket connections, so the WS is
authenticated in its own handler (`backend/api/websocket.py`): with a key
configured it is required (query param or header); with no key, only local
callers may connect. An unauthenticated connection is closed with code `1008`.

## Per-principal quotas

`backend/api/security.py` — an embedded, in-process fixed-window `PrincipalQuota`
(no shared-infra dependency) caps how often a principal may trigger an
investigation. The principal is the API key (hashed to a short id) when present,
else the client host. `enforce_quota(request)` raises `429` when the window limit
is exceeded, wired into the two investigation-triggering endpoints
(`POST /api/investigate` and the Maltego route). Configurable:
`api_quota_enabled` (True), `api_quota_per_principal` (60),
`api_quota_window_seconds` (60).

## Safe CORS

`backend/main.py` — `allow_credentials` is now `"*" not in settings.cors_origins`:
a wildcard origin with credentials is unsafe (and spec-forbidden), so credentials
are only sent for an explicit origin allowlist.

## Validation (done-when)

`tests/test_api_auth.py` (9): localhost open without a key; a simulated remote
caller refused (`503`) without a key while `/health` stays open; the key enforced
on `/api` and on `/maltego` (header or query param); the per-principal quota
counting/resetting and `enforce_quota` raising `429`; the local/principal helpers;
and the CORS wildcard-vs-explicit credentials rule. `gate check` green (0 NEW).

## Non-scope (respected)

No full multi-tenant user model / RBAC / ownership columns (a hosted-tier
concern) — principal-based auth + quotas only. No change to local CLI UX.
