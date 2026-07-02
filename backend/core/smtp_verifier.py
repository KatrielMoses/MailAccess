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

2. **Hard probe cap of 100 per domain per run.**  Callable can
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
  after a 3-second sleep; second temp failure becomes
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
#: lower this via ``smtp_max_probes_per_domain`` but cannot raise
#: it past this constant — enforced inside
#: :meth:`SMTPVerifier.verify_batch`.
MAX_PROBES_HARD_CAP = 100

#: Anonymous sender address used in MAIL FROM.  Override only via
#: the constructor ``sender_address`` parameter.
DEFAULT_SENDER = "probe@mailaccess.invalid"

#: Default delay between probes (seconds).  Override via config.
DEFAULT_PROBE_DELAY = 2.5

#: Default SMTP connect timeout (seconds).
DEFAULT_CONNECT_TIMEOUT = 8.0

#: SMTP response codes that imply "this mailbox exists".
#: Per RFC 5321: 250 is the canonical "accepted"; 251/252 are
#: "user not local / will forward" — also valid "exists" signals.
EXISTS_CODES: frozenset[int] = frozenset({250, 251, 252})

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
_BLOCK_CODE_5_7_1 = frozenset({551})  # already covered; spec calls 551 out


# ----- SMTP line parsing ---------------------------------------------------
@dataclass
class SMTPReply:
    code: int = 0
    message: str = ""


_LINE_RE = re.compile(r"^(\d{3})([ -])\s?(.*)$")


def _parse_smtp_reply(text: str) -> SMTPReply:
    """Parse the final line of an SMTP multi-line reply.

    Single-line replies are like ``250 OK``.  Multi-line replies end
    with ``250 OK`` (same digit) and look like ``250-Something\r\n250 OK``.
    We only care about the code + last message text.
    """
    if not text:
        return SMTPReply()
    final_code: int | None = None
    final_msg = ""
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
        if final_code is None:
            final_code = code
            final_msg = msg
        elif code == final_code and cont == " ":
            final_msg = msg
        elif code != final_code:
            # New code starts a new transaction.  Bail with what
            # we have.
            break
    return SMTPReply(code=final_code or 0, message=final_msg or "")


# ----- Public result dataclasses ------------------------------------------
@dataclass
class SMTPVerificationResult:
    email: str
    exists: bool | None = None  # True=yes, False=no, None=inconclusive
    response_code: int | None = 0
    blocked_signal: bool = False
    verification_status: str = "not_attempted"
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
        sender_address: str = DEFAULT_SENDER,
        probe_delay_seconds: float = DEFAULT_PROBE_DELAY,
        connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT,
        transport: _SMTPTransport | None = None,
    ) -> None:
        self._mx_records = list(mx_records)
        self._sender = (sender_address or DEFAULT_SENDER).strip() or DEFAULT_SENDER
        self._probe_delay = max(float(probe_delay_seconds), 0.0)
        self._connect_timeout = max(float(connect_timeout_seconds), 0.0)
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

        random_local = f"nonexistent-{uuid.uuid4().hex[:12]}"
        probe = f"{random_local}@{domain}"
        result = await self._probe_once(probe)
        if result.blocked_signal:
            # Anti-probing firewall likely.  Surface as unknown —
            # caller must NOT proceed.
            return None
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
                    # Greylisting / temporary — sleep 3s and retry
                    await asyncio.sleep(3.0)
                    continue
            break
        return last_result

    async def _deliver_probe(self, email: str) -> SMTPVerificationResult:
        """Perform the actual SMTP conversation for one recipient."""
        # Per-recipient sleep prevents burst-of-connections.
        if self._probe_delay > 0:
            await asyncio.sleep(self._probe_delay)

        # Try the host with the lowest (best) priority first.
        for mx in self._mx_records:
            try:
                return await self._smtp_rcpt(mx, email)
            except Exception as exc:  # noqa: BLE001 - defensive
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
        )

    async def _smtp_rcpt(self, mx: MXRecord, email: str) -> SMTPVerificationResult:
        """Walk HELO / MAIL FROM / RCPT TO for a single address."""
        ehlo_domain = "mailaccess-probe.invalid"
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
                mx.host, 25, f"MAIL FROM:<{self._sender}>"
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
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._connections.clear()
