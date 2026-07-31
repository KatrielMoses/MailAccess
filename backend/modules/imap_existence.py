"""IMAP single-probe existence check — Phase 4.

One check per account.  Covers self-hosted and shared-hosting domains that
slip through the M365 / SMTP / provider-specific verifiers.  Many mail servers
return distinct error text for *wrong password* versus *nonexistent user* on an
IMAP ``LOGIN`` attempt; this module sends exactly one deliberately-invalid
``LOGIN`` per account and decodes the response.

Like :mod:`backend.modules.m365_active_intel`, a hard, per-process,
per-account one-probe guard (:func:`_guard_one_probe`) is enforced at the
module level — not at the caller, not configurable.  At one attempt per
account there is no lockout risk.

The check:

1. :func:`_guard_one_probe` — the same guard pattern as Phase 3.  If the
   account was already probed this process, return an inconclusive result.
2. Resolve an IMAP host: ``imap.{domain}`` / ``imaps.{domain}`` first, then
   the MX host (shared hosts frequently serve IMAP on the SMTP host).
3. Verify a candidate port (993 TLS, then 143 STARTTLS) is reachable before
   connecting; skip entirely when neither is open.
4. Connect, send one invalid ``LOGIN``, read the tagged response, send
   ``LOGOUT`` (without waiting) and close.
5. Classify the response text (:func:`classify_imap_response`).  When — and
   only when — the text is ambiguous, a response-timing heuristic breaks the
   tie.  A clear text signal is never overridden by timing.

Confidence contribution (mirrored in
:data:`backend.core.email_confidence.SOURCE_WEIGHTS`):

* ``imap_probe`` → 0.70
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
import uuid
from dataclasses import dataclass

_LOG = logging.getLogger(__name__)

# Source-type identifier mirrored in email_confidence.SOURCE_WEIGHTS.
SOURCE_IMAP = "imap_probe"

#: Confidence contributed by a decoded IMAP existence signal.
_EXISTS_CONFIDENCE = 0.70
_NOT_FOUND_CONFIDENCE = 0.75
#: Confidence when only the timing heuristic (not text) decided the verdict.
_TIMING_CONFIDENCE = 0.55

#: IMAP over implicit TLS, then STARTTLS.
_IMAP_TLS_PORT = 993
_IMAP_STARTTLS_PORT = 143

#: Response-timing threshold. A reply faster than this suggests a fast reject
#: (no mailbox lookup → not found); a slower reply suggests a lookup was
#: performed (→ exists). Only consulted when the text signal is ambiguous.
_FAST_RESPONSE_MS = 150.0

# ---------------------------------------------------------------------------
# text-signal phrase tables (lowercased substring match)
# ---------------------------------------------------------------------------
_NOT_FOUND_PHRASES: tuple[str, ...] = (
    "no such user",
    "no user",
    "unknown user",
    "user doesn't exist",
    "user does not exist",
    "invalid user",
    "user not found",
    "mailbox not found",
)
_EXISTS_PHRASES: tuple[str, ...] = (
    "authenticationfailed",
    "authentication failed",
    "invalid credentials",
    "login failed",
    "bad username or password",
)
_INCONCLUSIVE_PHRASES: tuple[str, ...] = (
    "unavailable",
    "too many connections",
    "[alert]",
)


# ---------------------------------------------------------------------------
# HARD REQUIREMENT — one-probe guard (module level, not configurable)
# ---------------------------------------------------------------------------
#: Every account, normalised to lowercase, that has already been probed this
#: process.  Never probe the same account twice.
_PROBED_ACCOUNTS: set[str] = set()


def _guard_one_probe(email: str) -> bool:
    """Return ``True`` the first time *email* is seen, ``False`` thereafter.

    Enforced at the module level so no caller can bypass it.  A ``False``
    result means the account was already probed this process and the check
    must return an inconclusive result immediately.
    """
    normalized = email.strip().lower()
    if normalized in _PROBED_ACCOUNTS:
        return False  # already probed, skip
    _PROBED_ACCOUNTS.add(normalized)
    return True


# ---------------------------------------------------------------------------
# result type
# ---------------------------------------------------------------------------
@dataclass
class ImapProbeResult:
    """Outcome of a single IMAP existence probe against one account."""

    email: str
    # exists | not_found | inconclusive
    status: str = "inconclusive"
    confidence: float = 0.0
    source_type: str | None = None
    detail: str | None = None
    host: str | None = None
    port: int | None = None
    elapsed_ms: float | None = None
    error: str | None = None

    @property
    def exists(self) -> bool | None:
        if self.status == "exists":
            return True
        if self.status == "not_found":
            return False
        return None


def _inconclusive(
    email: str,
    *,
    error: str | None = None,
    detail: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> ImapProbeResult:
    return ImapProbeResult(
        email=email,
        status="inconclusive",
        error=error,
        detail=detail,
        host=host,
        port=port,
    )


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
def classify_imap_response(
    response: str | None,
    elapsed_ms: float | None = None,
) -> tuple[str, float, str | None]:
    """Map an IMAP ``LOGIN`` response to ``(status, confidence, detail)``.

    Text signals are authoritative.  The response-timing heuristic is only
    consulted when the text is ambiguous (a bare ``NO`` with no explanatory
    phrase); a clear text signal is *never* overridden by timing.
    """
    if not response or not response.strip():
        # Server disconnected before responding.
        return "inconclusive", 0.0, "no_response"

    lowered = response.lower()

    # Inconclusive infrastructure signals win first — they say nothing about
    # the account either way.
    for phrase in _INCONCLUSIVE_PHRASES:
        if phrase in lowered:
            return "inconclusive", 0.0, phrase.strip("[]")
    if "* bye" in lowered or lowered.lstrip().startswith("bye"):
        return "inconclusive", 0.0, "bye_on_connect"

    # Clear text signals.
    for phrase in _NOT_FOUND_PHRASES:
        if phrase in lowered:
            return "not_found", _NOT_FOUND_CONFIDENCE, "text_not_found"
    for phrase in _EXISTS_PHRASES:
        if phrase in lowered:
            return "exists", _EXISTS_CONFIDENCE, "text_exists"

    # Ambiguous text (e.g. a bare "NO") — fall back to the timing heuristic.
    if elapsed_ms is None:
        return "inconclusive", 0.0, "ambiguous_no_timing"
    if elapsed_ms < _FAST_RESPONSE_MS:
        return "not_found", _TIMING_CONFIDENCE, "timing_fast_reject"
    return "exists", _TIMING_CONFIDENCE, "timing_slow_lookup"


# ---------------------------------------------------------------------------
# port reachability
# ---------------------------------------------------------------------------
async def _port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return ``True`` when a TCP connection to *host*:*port* succeeds."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        return False
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return True


# ---------------------------------------------------------------------------
# the probe
# ---------------------------------------------------------------------------
async def _imap_probe(
    host: str,
    port: int,
    email: str,
    *,
    timeout: float,
    use_ssl: bool,
) -> tuple[str, float]:
    """Send one invalid ``LOGIN`` and return ``(response_text, elapsed_ms)``.

    Raises on any transport/TLS/timeout failure so the caller can classify the
    outcome as inconclusive.  ``LOGOUT`` is sent best-effort after the login
    response is read; its own response is not awaited.
    """
    ssl_ctx = ssl.create_default_context() if use_ssl else None
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx),
        timeout=timeout,
    )
    try:
        greeting = await asyncio.wait_for(reader.readline(), timeout=timeout)
        greeting_text = greeting.decode("utf-8", "replace")
        if greeting_text.lstrip().upper().startswith("* BYE"):
            # Server closed the door on connect — nothing to probe.
            return greeting_text, 0.0

        if not use_ssl:
            # Best-effort STARTTLS upgrade on port 143.  If the server does not
            # support it we continue over plaintext — the invalid password is
            # throwaway garbage, so there is nothing sensitive to protect.
            await _try_starttls(reader, writer, timeout=timeout)

        tag = f"a{uuid.uuid4().hex[:8]}"
        password = f"invalid_{uuid.uuid4()}"
        command = f"{tag} LOGIN {email} {password}\r\n"
        start = time.perf_counter()
        writer.write(command.encode("utf-8"))
        await writer.drain()

        lines: list[str] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line:
                break
            decoded = line.decode("utf-8", "replace")
            lines.append(decoded)
            # A tagged completion (OK/NO/BAD) terminates the response.
            if decoded.lstrip().startswith(tag):
                break
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        with contextlib.suppress(Exception):
            writer.write(f"z{uuid.uuid4().hex[:6]} LOGOUT\r\n".encode())
        return "".join(lines), elapsed_ms
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _try_starttls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    timeout: float,
) -> None:
    """Attempt a STARTTLS upgrade on a plaintext (port 143) connection.

    Silently returns on any failure — the caller falls back to plaintext.
    """
    tag = f"s{uuid.uuid4().hex[:8]}"
    writer.write(f"{tag} STARTTLS\r\n".encode())
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not line.decode("utf-8", "replace").lstrip().startswith(tag):
        return
    if b"ok" not in line.lower():
        return
    loop = asyncio.get_running_loop()
    start_tls = getattr(loop, "start_tls", None)
    transport = writer.transport
    protocol = transport.get_protocol()
    if start_tls is None:
        return
    new_transport = await start_tls(
        transport, protocol, ssl.create_default_context(), server_side=False
    )
    # Rebind the reader/writer to the upgraded transport.
    protocol._stream_writer._transport = new_transport  # type: ignore[attr-defined]
    writer._transport = new_transport  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# host candidates
# ---------------------------------------------------------------------------
def _candidate_hosts(domain: str, mx_hosts: list[str] | None) -> list[str]:
    """Return IMAP host candidates in priority order (deduplicated)."""
    cleaned = (domain or "").strip().lower().rstrip(".")
    hosts: list[str] = []
    if cleaned:
        hosts.append(f"imap.{cleaned}")
        hosts.append(f"imaps.{cleaned}")
    for mx in mx_hosts or []:
        host = (mx or "").strip().lower().rstrip(".")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


# ---------------------------------------------------------------------------
# eligibility (orchestrator gating helper)
# ---------------------------------------------------------------------------
#: Providers for which the IMAP probe is the right fallback. M365 / Google /
#: Yahoo have dedicated, higher-signal provider checks and are excluded.
_IMAP_ELIGIBLE_PROVIDERS: frozenset[str] = frozenset(
    {"self_hosted", "shared_hosting", "unknown"}
)
#: SMTP statuses that already settle the question — do not re-probe over IMAP.
_SMTP_DEFINITIVE: frozenset[str] = frozenset({"verified", "not_found"})


def should_run_imap_probe(provider: object, smtp_status: str | None) -> bool:
    """Return ``True`` when the IMAP fallback should run for this candidate.

    Runs only for self-hosted / shared-hosting / unknown providers *and* only
    when SMTP left the address unresolved (not already verified or denied).
    """
    provider_value = str(getattr(provider, "value", provider) or "").strip().lower()
    if provider_value not in _IMAP_ELIGIBLE_PROVIDERS:
        return False
    return (smtp_status or "").strip().lower() not in _SMTP_DEFINITIVE


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
async def run_imap_existence_check(
    email: str,
    domain: str,
    *,
    timeout: float = 8.0,
    port_check_timeout: float = 5.0,
    mx_hosts: list[str] | None = None,
) -> ImapProbeResult:
    """Run one guarded IMAP existence probe for *email*.

    Resolves an IMAP host, verifies a port is reachable, sends a single
    invalid ``LOGIN`` and classifies the response.  Every failure path
    (guard, unreachable ports, TLS error, timeout, disconnect) resolves to an
    inconclusive result; the account is never probed twice per process.
    """
    cleaned = (email or "").strip().lower()
    if "@" not in cleaned:
        return _inconclusive(cleaned, error="invalid_email")
    if not _guard_one_probe(cleaned):
        return _inconclusive(cleaned, error="already_probed")

    resolved_mx = mx_hosts
    if resolved_mx is None:
        try:
            from ..core.mx_resolver import resolve_mx

            resolved_mx = [record.host for record in await resolve_mx(domain)]
        except Exception as exc:  # noqa: BLE001 - degrade to name-based hosts
            _LOG.debug("IMAP MX resolution failed for %s: %s", domain, exc)
            resolved_mx = []

    hosts = _candidate_hosts(domain, resolved_mx)
    if not hosts:
        return _inconclusive(cleaned, error="no_host")

    # Find the first reachable host/port. 993 (implicit TLS) is preferred; fall
    # back to 143 (STARTTLS) per host.
    chosen_host: str | None = None
    chosen_port: int | None = None
    use_ssl = True
    for host in hosts:
        if await _port_open(host, _IMAP_TLS_PORT, port_check_timeout):
            chosen_host, chosen_port, use_ssl = host, _IMAP_TLS_PORT, True
            break
        if await _port_open(host, _IMAP_STARTTLS_PORT, port_check_timeout):
            chosen_host, chosen_port, use_ssl = host, _IMAP_STARTTLS_PORT, False
            break

    if chosen_host is None or chosen_port is None:
        return _inconclusive(cleaned, error="port_unreachable")

    try:
        response, elapsed_ms = await _imap_probe(
            chosen_host,
            chosen_port,
            cleaned,
            timeout=timeout,
            use_ssl=use_ssl,
        )
    except asyncio.TimeoutError:
        return _inconclusive(
            cleaned, error="timeout", host=chosen_host, port=chosen_port
        )
    except ssl.SSLError as exc:
        return _inconclusive(
            cleaned, error=f"tls_error: {exc}", host=chosen_host, port=chosen_port
        )
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        return _inconclusive(
            cleaned,
            error=f"{type(exc).__name__}: {exc}",
            host=chosen_host,
            port=chosen_port,
        )

    status, confidence, detail = classify_imap_response(response, elapsed_ms)
    result = ImapProbeResult(
        email=cleaned,
        status=status,
        detail=detail,
        host=chosen_host,
        port=chosen_port,
        elapsed_ms=round(elapsed_ms, 2),
    )
    if status != "inconclusive":
        result.source_type = SOURCE_IMAP
        result.confidence = confidence
    return result


__all__ = [
    "ImapProbeResult",
    "SOURCE_IMAP",
    "classify_imap_response",
    "run_imap_existence_check",
    "should_run_imap_probe",
]
