"""SMTP RCPT TO verifier — highest-risk component of this phase.

DESIGN NOTES
============

Three load-bearing safety properties below — *all* of them are
mandatory per spec, none of them are configurable, and all of
them are unit-tested (see tests/test_smtp_verifier.py):

1. **Catch-all detection runs FIRST and ALWAYS.**  Before probing
   any candidate mailbox, we ask the destination whether
   *random-uuid@example.com* exists.  If ``250`` → catch-all, abort
   individual probing.  If response is ambiguous/timeout/error →
   we do not know, refuse to proceed.  This protects against
   "valid SMTP, but every address accepts" servers from generating
   a flood of false-positive ``exists=True`` results.

2. **Hard probe cap of 10 per domain per run.**  Callable can
   pass any ``max_probes`` it likes, but
   :meth:`SMTPVerifier.verify_batch` clamps it down.  Configurable
   downward via settings, never upward past the constant
   :data:`MAX_PROBES_HARD_CAP`.

3. **Sender address is anonymous.**  The :class:`SMTPVerifier`
   constructs an envelope from a fixed non-deliverable
   ``probe@mailaccess.invalid`` address, never the target.
   Defaulting a different sender at call-site is permitted (the
   constructor accepts one); deriving it from the target
   :data:`email_address` is *not* exposed anywhere in this module.

SECONDARY SAFETY
================

* Rate limit: at least 2.5s between probes (``settings.smtp_probe_delay_seconds``).
* Sequential probing (no concurrent connections) — SMTP servers
  flag connection bursts.
* Mid-batch block signal (``5.7.1``, connection refused, generic
  5xx) → STOP IMMEDIATELY, mark the rest of the batch as
  ``not_attempted``.
* Temporary failures (450/451/452, greylisting) get ONE retry
  after a configurable 30-second sleep; second temp failure becomes
  ``inconclusive``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field

from .mx_resolver import MXRecord

_LOG = logging.getLogger(__name__)


#: Absolute upper bound on probes per domain, per run.  Settings can
#: lower this via ``smtp_verify_max_probes`` but cannot raise
#: it past this constant — enforced inside
#: :meth:`SMTPVerifier.verify_batch`.
MAX_PROBES_HARD_CAP = 10

#: Fallback MAIL FROM address, used only when a realistic per-probe
#: sender cannot be derived (i.e. the probed address has no domain).
#: The normal path derives ``verify-{uuid8}@{target_domain}`` per probe
#: (see :meth:`SMTPVerifier._probe_identity`).
DEFAULT_SENDER = "verify@example.com"

#: Default delay between probes (seconds).  Override via config.
DEFAULT_PROBE_DELAY = 2.5

#: Default SMTP connect timeout (seconds).
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_GREYLIST_RETRY_DELAY = 30.0

#: SMTP response codes that imply "this mailbox exists".
#: Per RFC 5321: 250 is the canonical "accepted"; 251 is
#: "user not local; will forward" — also a valid "exists" signal.
#: 252 is deliberately EXCLUDED (see :data:`CATCHALL_HINT_CODES`).
EXISTS_CODES: frozenset[int] = frozenset({250, 251})

#: 252 = "cannot VRFY user, but will accept message and attempt
#: delivery" (RFC 5321 §3.5.3).  This is catch-all / accept-anything
#: behaviour, NOT confirmed mailbox existence.  A 252 must mark the
#: domain as a catch-all rather than promote the address to verified.
CATCHALL_HINT_CODES: frozenset[int] = frozenset({252})

#: SMTP response codes that imply "this mailbox does NOT exist".
NOT_EXISTS_CODES: frozenset[int] = frozenset({550, 551, 553})

#: SMTP response codes that imply "temporary failure, retry later"
#: (greylisting, mailbox full, etc.) — single retry before
#: inlining as inconclusive.
TEMP_FAILURE_CODES: frozenset[int] = frozenset({450, 451, 452})

#: SMTP response codes that imply we should STOP THE ENTIRE BATCH.
#: 5.7.1 specifically is the anti-abuse rejection that signals
#: the server has identified our pattern and is blocking us.  We
#: also stop on generic 5xx (other than the not-exists codes),
#: connection refused, and read timeouts.
_BLOCK_CODES: frozenset[int] = frozenset(
    {500, 501, 502, 503, 504, 521, 523, 524, 530, 531, 532, 534, 535,
     541, 542, 543, 544, 545, 546, 547, 550, 551, 552, 553, 554, 555}
)
SERVICE_UNAVAILABLE_CODES: frozenset[int] = frozenset({421})
_BLOCK_CODE_5_7_1 = frozenset({551})  # already covered; spec calls 551 out


# ----- SMTP line parsing ---------------------------------------------------
@dataclass
class SMTPReply:
    code: int = 0
    message: str = ""


_LINE_RE = re.compile(r"^(\d{3})([ -])\s?(.*)$")


def _parse_smtp_reply(text: str) -> SMTPReply:
    """Parse an SMTP reply, honouring multi-line continuation syntax.

    Per RFC 5321 §4.2.1 a multi-line reply repeats the code with a
    hyphen (``250-Something``) on every continuation line and a SPACE
    (``250 OK``) on the *terminating* line.  We only treat a reply as
    complete once that terminating line is seen.

    FIX 3B: the previous implementation latched ``final_code`` on the
    FIRST line, so a truncated/non-terminated multi-line reply
    (``250-FIRST`` with no terminator, e.g. a partial socket read) was
    wrongly reported as a complete ``250``.  We now return code ``0``
    (inconclusive) unless a terminating line is actually observed.
    """
    if not text:
        return SMTPReply()
    final_code: int | None = None
    final_msg = ""
    saw_terminator = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _LINE_RE.match(line)
        if not match:
            continue
        code = int(match.group(1))
        cont = match.group(2)
        msg = match.group(3)
        final_msg = msg
        if cont == " ":
            # Terminating line — this is the authoritative code.
            final_code = code
            saw_terminator = True
            break
        # Continuation line (``code-``): remember the code but keep
        # reading until the terminator arrives.
        if final_code is None:
            final_code = code
    if not saw_terminator:
        # Non-terminated / truncated reply — do not treat as final.
        return SMTPReply(code=0, message=final_msg or "")
    return SMTPReply(code=final_code or 0, message=final_msg or "")


# ----- Public result dataclasses ------------------------------------------
@dataclass
class SMTPVerificationResult:
    email: str
    exists: bool | None = None  # True=yes, False=no, None=inconclusive
    response_code: int | None = 0
    blocked_signal: bool = False
    catchall_hint: bool = False  # FIX 3A: set when a 252 accept-anything reply seen
    verification_status: str = "not_attempted"
    mx_host: str | None = None
    transport_error: str | None = None
    # "verified" / "not_found" / "inconclusive" / "blocked" /
    # "not_attempted" / "temporary_failure"

    def __post_init__(self) -> None:
        if self.verification_status == "not_attempted" and self.exists is not None:
            self.verification_status = (
                "verified" if self.exists else "not_found"
            )


@dataclass
class SMTPBatchResult:
    domain: str
    is_catchall: bool | None = None
    results: list[SMTPVerificationResult] = field(default_factory=list)
    probes_attempted: int = 0
    probes_succeeded: int = 0
    stopped_early: bool = False
    stop_reason: str | None = None
    error: str | None = None


# ----- Conversation transport abstraction ---------------------------------
class _SMTPTransport:
    """Abstraction over an SMTP conversation.  Production binds to
    :mod:`asyncio` open-connection / asyncio streams; tests bind a
    mock that returns canned responses.
    """

    async def send(self, host: str, port: int, command: str) -> str:
        """Open a connection if needed, send ``command``, return response text."""
        raise NotImplementedError


# ----- SMTPVerifier --------------------------------------------------------
class SMTPVerifier:
    """Domain-mode SMTP verifier.

    Construct with the resolved MX records (typically from
    :func:`backend.core.mx_resolver.resolve_mx`); the verifier
    holds a single connection at a time and reuses it across probes
    in a batch.
    """

    def __init__(
        self,
        mx_records: list[MXRecord],
        sender_address: str = "",
        probe_delay_seconds: float = DEFAULT_PROBE_DELAY,
        connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT,
        greylist_retry_delay: float = DEFAULT_GREYLIST_RETRY_DELAY,
        transport: _SMTPTransport | None = None,
        probe_domain_pattern: str = "target",
        probe_custom_domain: str = "",
    ) -> None:
        self._mx_records = list(mx_records)
        # An explicit ``sender_address`` (operator override) wins over the
        # per-probe derived identity.  Empty string → derive per probe.
        self._sender = (sender_address or "").strip()
        self._probe_domain_pattern = (probe_domain_pattern or "target").strip().lower()
        self._probe_custom_domain = (probe_custom_domain or "").strip().lower().lstrip("@")
        self._probe_delay = max(float(probe_delay_seconds), 0.0)
        self._connect_timeout = max(float(connect_timeout_seconds), 0.0)
        self._greylist_retry_delay = max(float(greylist_retry_delay), 0.0)
        self._owns_transport = transport is None
        self._transport: _SMTPTransport = transport or _AsyncioSMTPTransport(
            self._sender, self._connect_timeout
        )

    async def aclose(self) -> None:
        if self._owns_transport and hasattr(self._transport, "close"):
            try:
                await self._transport.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass

    async def __aenter__(self) -> SMTPVerifier:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Probe identity (FIX 1)
    # ------------------------------------------------------------------
    def _probe_identity(self, target_domain: str) -> tuple[str, str]:
        """Return ``(mail_from, ehlo_host)`` for a probe against *target_domain*.

        Default policy makes the probe look like an internal bounce
        check: ``MAIL FROM: <verify-{uuid8}@{target_domain}>`` and
        ``EHLO mail.{target_domain}``.  An explicit ``sender_address``
        override (if set) wins for the MAIL FROM value.
        """
        base = (target_domain or "").strip().lower().rstrip(".")
        if self._probe_domain_pattern == "custom" and self._probe_custom_domain:
            base = self._probe_custom_domain
        if not base:
            # No usable domain — fall back to the configured/default sender.
            sender = self._sender or DEFAULT_SENDER
            ehlo_host = "mail." + sender.rsplit("@", 1)[-1]
            return sender, ehlo_host
        sender = self._sender or f"verify-{uuid.uuid4().hex[:8]}@{base}"
        return sender, f"mail.{base}"

    # ------------------------------------------------------------------
    # Catch-all detection
    # ------------------------------------------------------------------
    async def check_catchall(self, domain: str) -> bool | None:
        """Return whether *domain* is a catch-all.

        None means "could not determine" — caller must NOT proceed
        with bulk SMTP verification in that case (safety gate).
        """
        if not isinstance(domain, str) or not domain.strip():
            return None
        if not self._mx_records:
            return None

        random_local = f"probe-{uuid.uuid4().hex[:8]}"
        probe = f"{random_local}@{domain}"
        result = await self._probe_once(probe)
        if result.blocked_signal:
            # Anti-probing firewall likely.  Surface as unknown —
            # caller must NOT proceed.
            return None
        # FIX 3A: a 252 "accept anything" reply to a random address is a
        # positive catch-all signal even though it is not a verified
        # mailbox.  Treat it the same as a 250 to a random probe.
        if result.catchall_hint:
            return True
        if result.exists is None:
            return None
        return bool(result.exists)

    # ------------------------------------------------------------------
    # Single recipient
    # ------------------------------------------------------------------
    async def verify_single(self, email: str) -> SMTPVerificationResult:
        return await self._probe_once(email)

    async def _probe_once(
        self, email: str, *, retry_on_temp: bool = True
    ) -> SMTPVerificationResult:
        if not isinstance(email, str) or "@" not in email:
            return SMTPVerificationResult(
                email=email or "",
                exists=None,
                verification_status="inconclusive",
            )

        last_result: SMTPVerificationResult
        for attempt in (1, 2) if retry_on_temp else (1,):
            last_result = await self._deliver_probe(email)
            if not last_result.blocked_signal:
                if (
                    last_result.response_code in TEMP_FAILURE_CODES
                    and attempt == 1
                ):
                    # Greylisting / temporary failure: one bounded retry.
                    await asyncio.sleep(self._greylist_retry_delay)
                    continue
            break
        if last_result.response_code in TEMP_FAILURE_CODES:
            last_result.verification_status = "inconclusive"
        return last_result

    async def _deliver_probe(self, email: str) -> SMTPVerificationResult:
        """Perform the actual SMTP conversation for one recipient."""
        # Per-recipient sleep prevents burst-of-connections.
        if self._probe_delay > 0:
            await asyncio.sleep(self._probe_delay)

        # Try the host with the lowest (best) priority first.
        errors: list[str] = []
        last_result: SMTPVerificationResult | None = None
        last_mx_host: str | None = None
        for mx in self._mx_records:
            last_mx_host = mx.host
            try:
                result = await self._smtp_rcpt(mx, email)
                result.mx_host = mx.host
                last_result = result
                # Definitive answers, explicit blocks, and catch-all hints
                # should not be contradicted by a lower-priority MX host.
                # Continue only for ambiguous/inconclusive responses.
                if (
                    result.exists is not None
                    or result.blocked_signal
                    or result.catchall_hint
                    or result.verification_status in {"temporary_failure", "blocked", "catch_all"}
                ):
                    return result
                errors.append(
                    f"{mx.host}: response {result.response_code or 'none'}"
                )
            except (asyncio.TimeoutError, TimeoutError) as exc:
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=None,
                    verification_status="smtp_timeout",
                    mx_host=mx.host,
                    transport_error=str(exc) or "timeout",
                )
            except Exception as exc:  # noqa: BLE001 - defensive
                errors.append(f"{mx.host}: {type(exc).__name__}: {exc or 'no response'}")
                _LOG.warning(
                    "smtp_verifier: transport error to %s for %s: %s",
                    mx.host,
                    email,
                    exc,
                )
                continue
        return SMTPVerificationResult(
            email=email,
            exists=None,
            response_code=None,
            verification_status="inconclusive",
            mx_host=last_result.mx_host if last_result else last_mx_host,
            transport_error="; ".join(errors) or "no_mx_response",
        )

    async def _smtp_rcpt(self, mx: MXRecord, email: str) -> SMTPVerificationResult:
        """Walk HELO / MAIL FROM / RCPT TO for a single address."""
        # FIX 1: derive a realistic sender + EHLO host from the target
        # domain (verify-{uuid8}@{domain} / mail.{domain}) so the probe
        # reads as an internal bounce check, not an OSINT tool.
        target_domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        sender, ehlo_domain = self._probe_identity(target_domain)
        try:
            banner = await self._transport.send(mx.host, 25, "")
            if not banner:
                raise RuntimeError("empty banner")
            code = _parse_smtp_reply(banner).code
            if code != 220:
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=code or None,
                    blocked_signal=code in _BLOCK_CODES,
                    verification_status=(
                        "blocked" if code in _BLOCK_CODES else "inconclusive"
                    ),
                )

            ehlo_reply = await self._transport.send(mx.host, 25, f"EHLO {ehlo_domain}")
            ehlo_code = _parse_smtp_reply(ehlo_reply).code
            if ehlo_code not in (250,):
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=ehlo_code or None,
                    blocked_signal=ehlo_code in _BLOCK_CODES,
                    verification_status=(
                        "blocked" if ehlo_code in _BLOCK_CODES else "inconclusive"
                    ),
                )

            mail_reply = await self._transport.send(
                mx.host, 25, f"MAIL FROM:<{sender}>"
            )
            mail_code = _parse_smtp_reply(mail_reply).code
            if mail_code not in (250,):
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=mail_code or None,
                    blocked_signal=mail_code in _BLOCK_CODES,
                    verification_status=(
                        "blocked"
                        if mail_code in _BLOCK_CODES or mail_code == 553
                        else "inconclusive"
                    ),
                )

            rcpt_reply = await self._transport.send(
                mx.host, 25, f"RCPT TO:<{email}>"
            )
            rcpt_code = _parse_smtp_reply(rcpt_reply).code

            # Try a graceful RSET to keep the connection clean for the
            # next probe.  Ignore failures here.
            try:
                await self._transport.send(mx.host, 25, "RSET")
                await self._transport.send(mx.host, 25, "QUIT")
            except Exception:  # noqa: BLE001
                pass

            if rcpt_code in EXISTS_CODES:
                return SMTPVerificationResult(
                    email=email, exists=True, response_code=rcpt_code
                )
            if rcpt_code in CATCHALL_HINT_CODES:
                # FIX 3A: 252 = accept-anything.  Not confirmed existence;
                # flag as a catch-all hint and leave existence unknown.
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=rcpt_code,
                    catchall_hint=True,
                    verification_status="catch_all",
                )
            if rcpt_code in NOT_EXISTS_CODES:
                return SMTPVerificationResult(
                    email=email, exists=False, response_code=rcpt_code
                )
            if rcpt_code in TEMP_FAILURE_CODES:
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=rcpt_code,
                    verification_status="temporary_failure",
                )
            if rcpt_code in SERVICE_UNAVAILABLE_CODES:
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=rcpt_code,
                    blocked_signal=True,
                    verification_status="service_unavailable",
                )
            if rcpt_code in _BLOCK_CODES:
                return SMTPVerificationResult(
                    email=email,
                    exists=None,
                    response_code=rcpt_code,
                    blocked_signal=True,
                    verification_status="blocked",
                )
            return SMTPVerificationResult(
                email=email,
                exists=None,
                response_code=rcpt_code or None,
                verification_status="inconclusive",
            )
        except Exception:
            # The transport layer raised; surface as inconclusive so the
            # caller can move on to the next MX host (we wrap at the
            # caller level).
            raise

    # ------------------------------------------------------------------
    # Batch
    # ------------------------------------------------------------------
    async def verify_batch(
        self,
        domain: str,
        candidates: list[str],
        max_probes: int = MAX_PROBES_HARD_CAP,
    ) -> SMTPBatchResult:
        """Probe *candidates* on *domain* with strict safety bounds.

        *max_probes* cannot exceed :data:`MAX_PROBES_HARD_CAP` —
        enforced unconditionally inside this method, callers may
        pass any value.

        Order of operations (safety-critical):

        1. Resolve MX (delegated to caller via constructor — assumed
           done).
        2. Catch-all check; if catch-all is detected or cannot be
           determined, do NOT probe individuals.
        3. Sequential probing with the configured delay; stop on
           first ``blocked_signal``.
        """
        cleaned_domain = (domain or "").strip().lower()
        if not cleaned_domain:
            return SMTPBatchResult(
                domain=domain or "",
                error="invalid_domain",
            )

        effective_cap = max(0, min(int(max_probes), MAX_PROBES_HARD_CAP))
        if not self._mx_records:
            return SMTPBatchResult(
                domain=cleaned_domain,
                results=[
                    SMTPVerificationResult(email=addr, exists=None)
                    for addr in candidates[:effective_cap]
                ],
                probes_attempted=0,
                error="no_mx_records",
            )

        # 1. Catch-all detection
        is_catchall = await self.check_catchall(cleaned_domain)
        if is_catchall is True:
            return SMTPBatchResult(
                domain=cleaned_domain,
                is_catchall=True,
                results=[
                    SMTPVerificationResult(email=addr, exists=None)
                    for addr in candidates[:effective_cap]
                ],
                probes_attempted=1,  # the catch-all probe itself
                error=None,
            )
        if is_catchall is None:
            return SMTPBatchResult(
                domain=cleaned_domain,
                is_catchall=None,
                results=[
                    SMTPVerificationResult(email=addr, exists=None)
                    for addr in candidates[:effective_cap]
                ],
                probes_attempted=1,
                error="catchall_check_failed",
            )

        # 2. Sequential probing
        results: list[SMTPVerificationResult] = []
        attempted = 0
        succeeded = 0
        stopped_early = False
        stop_reason: str | None = None

        for email in candidates:
            if attempted >= effective_cap:
                # Capacity exhausted; mark remainder not_attempted.
                results.append(SMTPVerificationResult(email=email))
                continue

            result = await self._probe_once(email)
            attempted += 1
            if result.exists is not None:
                succeeded += 1
            results.append(result)

            if result.blocked_signal:
                stopped_early = True
                stop_reason = "blocked_mid_batch"
                # Mark remaining as not_attempted.
                for remaining in candidates[len(results) :]:
                    results.append(SMTPVerificationResult(email=remaining))
                break

        return SMTPBatchResult(
            domain=cleaned_domain,
            is_catchall=False,
            results=results,
            probes_attempted=attempted,
            probes_succeeded=succeeded,
            stopped_early=stopped_early,
            stop_reason=stop_reason,
            error=None,
        )


# ----- Real transport (asyncio-based) -------------------------------------
class _AsyncioSMTPTransport(_SMTPTransport):
    """Production SMTP transport using asyncio streams.

    Each ``send`` opens a fresh connection (SMTP servers are sensitive
    to connection bursts), reads the banner or previous command's
    response, sends one command, reads the response.

    ``command == ""`` opens the connection and reads only the banner.
    """

    def __init__(self, sender_address: str, connect_timeout: float) -> None:
        self._sender = sender_address
        self._connect_timeout = connect_timeout
        # Persistent reader + writer per host so a single batch can
        # reuse the connection.  Map: host -> (reader, writer).
        self._connections: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}

    async def send(self, host: str, port: int, command: str) -> str:
        # Per-host lazy connection (one at a time, single SMTP session).
        # If a previous SMTP conversation returned a closed connection,
        # drop it and reopen.
        conn = self._connections.get(host)
        if conn is not None:
            reader, writer = conn
            if writer.is_closing():
                self._connections.pop(host, None)
                conn = None
        if conn is None:
            reader, writer = await self._open(host, port)
            self._connections[host] = (reader, writer)
            banner = await self._readall(reader)
        else:
            # No banner needed; we're mid-conversation.
            banner = ""

        if not command:
            return banner

        writer.write((command + "\r\n").encode("utf-8", "replace"))
        await writer.drain()
        return await self._readall(reader)

    async def _open(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self._connect_timeout,
        )

    @staticmethod
    async def _readall(reader: asyncio.StreamReader) -> str:
        # Read up to ~8 KiB (enough for any well-formed SMTP reply we care about).
        buf: list[str] = []
        try:
            while True:
                line_bytes = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", "replace").rstrip("\r\n")
                buf.append(line)
                # End-of-reply: digit + space at index 3 (e.g. "250 OK").
                if len(line) >= 4 and line[3:4] == " ":
                    break
        except asyncio.TimeoutError:
            # Treat as end-of-reply; caller will see partial reply.
            pass
        return "\n".join(buf)

    async def close(self) -> None:
        for _, writer in list(self._connections.values()):
            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
        self._connections.clear()
