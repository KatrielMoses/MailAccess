"""Domain Email Harvest CLI command — Phase C3.

The CLI entry point for ``mailaccess harvest-emails``.  All the
orchestration lives in :mod:`backend.core.domain_harvest_orchestrator`;
all the formatting lives in :mod:`backend.core.domain_harvest_report`.

This file is a thin Typer wrapper that:

* Resolves ``--export`` paths to ``./results/`` (matching the
  existing ``platform-audit --export`` convention).
* MUST-FIX M3: passes ``--lite`` and ``--max-cc-records`` as
  explicit kwargs to ``run_domain_harvest``. The CLI does NOT
  mutate ``settings.dork_lite_mode`` or ``settings.cc_max_records``
  — that was a race condition in any concurrent context.
* Prints the SMTP opt-in notice when ``--verify-smtp`` is set.
* Renders the live progress table for the five harvest modules,
  matching the visual pattern of the existing
  ``investigate``-command module-progress display.

CLI command vs flag-on-investigate decision:
    A NEW top-level command (``mailaccess harvest-emails``).  The
    investigation command is fundamentally email-centric; the
    harvest command is fundamentally domain-centric and produces
    output in a different shape.  Overloading ``investigate`` would
    require a runtime branch on output format that adds complexity
    without saving any keystrokes — ``mailaccess harvest-emails
    --domain example.com`` is just as ergonomic as
    ``mailaccess investigate --domain example.com --search-emails``
    and keeps both surfaces focused.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import time
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

from rich.console import Console
from rich.live import Live
from rich.table import Table

from backend.core.domain_harvest_orchestrator import run_domain_harvest
from backend.core.domain_harvest_report import (
    format_harvest_cli_output,
    serialise_harvest_for_export,
)


def _resolve_export_path(export: str) -> Path:
    """Route bare filenames into ``./results/`` to match the existing
    platform-audit convention (see ``cli/platform_audit.py``).
    """
    p = Path(export)
    if p.parent == Path("."):
        results_dir = Path(__file__).resolve().parent.parent / "results"
        results_dir.mkdir(exist_ok=True)
        return results_dir / p.name
    return p


def _format_progress_table(states: dict[str, str], started_at: float) -> Table:
    """Live progress table for the 5 harvest modules."""
    table = Table(title="Module Progress", box=None, header_style="bold cyan")
    table.add_column("Module", style="cyan")
    table.add_column("Status", justify="right")
    table.add_column("Time", justify="right", style="dim")
    elapsed = time.time() - started_at
    table.add_row("wall clock", "—", f"{elapsed:.1f}s")
    for name, status in states.items():
        color = {
            "queued": "dim",
            "running": "cyan",
            "success": "green",
            "failed": "red",
            "skipped": "dim",
            "partial": "yellow",
        }.get(status, "white")
        table.add_row(name, f"[{color}]{status.upper()}[/]", "—")
    return table


def _confidence_label_passes(min_confidence: str, label: str) -> bool:
    """Return True if *label* meets the *min_confidence* threshold.

    MUST-FIX S8: filtering helper. Order from laxest to strictest:
        low < medium < high
    A filter of ``"low"`` is a no-op (passes everything). A filter of
    ``"high"`` passes only HIGH-confidence emails. Unknown labels
    default to "low" (defensive — never silently drop unknown).
    """
    order = {"low": 0, "medium": 1, "high": 2}
    return order.get(str(label).lower(), 0) >= order.get(
        min_confidence.lower(), 0
    )


def _confidence_score_passes(min_score: float, score: float) -> bool:
    """Numeric counterpart of :func:`_confidence_label_passes`.

    W5: the numeric filter is purely score-based and is the
    more precise / expressive of the two. A score of 0.0 means
    "show everything" (the default). Negative scores are
    interpreted the same way as 0.0 (defensive — never silently
    drop when the caller passed a malformed value).
    """
    try:
        threshold = float(min_score)
    except (TypeError, ValueError):
        threshold = 0.0
    if threshold <= 0.0:
        return True
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = 0.0
    return value >= threshold


def _apply_filters(
    result: Any,
    *,
    min_confidence: str = "low",
    min_confidence_score: float = 0.0,
    exclude_domains: tuple[str, ...] = (),
    on_domain_only: bool = False,
    harvest_domain: str,
) -> Any:
    """Return a filtered *DomainHarvestResult* (immutable copy).

    MUST-FIX S8: post-processing filters. Operates on the
    already-aggregated ``unique_emails`` list and the per-email
    on_domain flag. Underlying harvest results are unchanged — only
    the displayed/exported view is filtered.

    W5: ``min_confidence_score`` adds a numeric filter that runs
    alongside the label-based ``min_confidence``. When BOTH are set,
    the MORE RESTRICTIVE of the two wins — i.e. an email must pass
    whichever threshold is higher. ``score=0.0`` (the default) is
    a no-op so the numeric filter never silently drops results when
    only the label filter is in use.

    Parameters
    ----------
    exclude_domains:
        Lowercased domains whose emails should be HIDDEN.
        E.g. ``("gmail.com",)`` removes all gmail mentions.
    on_domain_only:
        When True, only emails whose domain equals *harvest_domain*
        are shown (third-party mentions entirely suppressed).
    min_confidence:
        One of ``"high"``, ``"medium"``, ``"low"``. Filter accepts
        emails whose ``confidence_label`` is at or above the threshold.
    min_confidence_score:
        Numeric threshold. The label threshold maps to:
            high   ≈ score >= 0.8
            medium ≈ score >= 0.5
            low    ≈ score >= 0.0 (no-op)
        so the numeric filter is strictly more expressive than the
        label filter when used at non-aligned thresholds.
    """
    excluded = {d.lower().strip() for d in exclude_domains if d}
    target = (harvest_domain or "").lower().strip()

    filtered_emails = []
    for entry in result.unique_emails:
        # MUST-FIX S8: drop by domain membership (exclude + on-domain-only).
        if entry.email and "@" in entry.email:
            dom = entry.email.rsplit("@", 1)[-1].lower()
            if dom in excluded:
                continue
            if on_domain_only and dom != target:
                continue
        # W5: combine the two confidence filters with AND semantics —
        # the email must pass BOTH the label filter AND the numeric
        # filter. Numeric thresholds that fall BELOW the label
        # threshold are still applied (a stricter numeric floor wins).
        if not _confidence_label_passes(min_confidence, entry.confidence_label):
            continue
        if not _confidence_score_passes(
            min_confidence_score, entry.confidence_score
        ):
            continue
        filtered_emails.append(entry)

    # Construct a copy with the filtered emails and recomputed counts.
    # We re-use the same module_results so the per-module status table
    # in the CLI output still reflects what actually ran — only the
    # emails tier (HIGH / MEDIUM / LOW) is filtered.
    return type(result)(
        domain=result.domain,
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_seconds=result.duration_seconds,
        module_results=result.module_results,
        unique_emails=filtered_emails,
        total_unique_emails=len(filtered_emails),
        high_confidence_count=sum(
            1 for e in filtered_emails if e.confidence_label == "HIGH"
        ),
        medium_confidence_count=sum(
            1 for e in filtered_emails if e.confidence_label == "MEDIUM"
        ),
        low_confidence_count=sum(
            1 for e in filtered_emails if e.confidence_label == "LOW"
        ),
        role_account_count=sum(1 for e in filtered_emails if e.is_role),
        personal_email_count=sum(
            1 for e in filtered_emails if not e.is_role
        ),
        errors=result.errors,
        smtp_verification_used=result.smtp_verification_used,
        catchall_detected=result.catchall_detected,
        confirmed_pattern=result.confirmed_pattern,
        employee_names_processed=result.employee_names_processed,
    )


def run_harvest_emails(
    domain: str,
    verify_smtp: bool = False,
    lite: bool = False,
    export: str | None = None,
    max_cc_records: int | None = None,
    console: Console | None = None,
    *,
    min_confidence: str = "low",
    min_confidence_score: float = 0.0,
    exclude_domains: tuple[str, ...] = (),
    on_domain_only: bool = False,
) -> int:
    """Run the domain email harvest and render / export results.

    Returns a process-style exit code (0 on success, non-zero on
    validation error or total failure).
    """
    if console is None:
        console = Console()

    # ------------------------------------------------------------------
    # 1. Validate domain — explicit error, do NOT proceed.
    # ------------------------------------------------------------------
    try:
        cleaned_domain = domain.strip().lower()
        if not cleaned_domain:
            console.print(
                "[red]Error:[/] --domain must be a non-empty domain "
                "(e.g. --domain example.com)"
            )
            return 2
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] {exc}")
        return 2

    # ------------------------------------------------------------------
    # 2. MUST-FIX M3: per-invocation options are threaded as explicit
    #    kwargs to ``run_domain_harvest``. The CLI does NOT mutate the
    #    global settings object — that was a race condition in any
    #    concurrent context (web server, parallel investigation).
    # ------------------------------------------------------------------
    cli_dork_lite_mode = bool(lite) if lite else None
    cli_cc_max_records = (
        max(1, int(max_cc_records)) if max_cc_records is not None else None
    )

    # ------------------------------------------------------------------
    # 3. Print SMTP opt-in notice (only when --verify-smtp is set).
    # ------------------------------------------------------------------
    if verify_smtp:
        console.print(
            "[yellow]⚠ SMTP verification enabled — probing up to "
            "100 addresses via RCPT TO. This is a passive OSINT "
            "technique (no emails sent) but uses your network "
            "connection to contact target mail servers directly.[/yellow]"
        )

    # ------------------------------------------------------------------
    # 4. Run the orchestrator with a live progress display.
    # MUST-FIX S5: states are mutated INCREMENTALLY — each module's
    # final status is pushed by the orchestrator's
    # ``on_module_complete`` callback the moment the module's coroutine
    # resolves. Previously all five modules stayed at "running" for the
    # entire harvest duration because state was only mutated in bulk
    # once ``run_domain_harvest`` returned.
    # W5: now eight modules — three structured-source additions
    # (npm_email, pypi_email, pgp_domain_email) sit alongside the
    # existing Phase 1 sources and run concurrently.
    # ------------------------------------------------------------------
    module_states: dict[str, str] = {
        "commoncrawl_email": "queued",
        "code_and_cert_email": "queued",
        "email_search_dork": "queued",
        "employee_name_discovery": "queued",
        "npm_email": "queued",
        "pypi_email": "queued",
        "pgp_domain_email": "queued",
        "pattern_and_verify": "queued",
    }

    started = time.time()

    def _on_module_complete(name: str, status: str) -> None:
        """Update the module_states dict in-place when a module finishes.

        MUST-FIX S5: this is the callback that fixes the cosmetic-only
        progress display. It's intentionally *synchronous* —
        ``rich.live.Live`` re-renders its renderable on every refresh
        tick, so all the Live display needs is for the underlying
        ``module_states`` dict to mutate under it. The 2 Hz refresh on
        the Live context picks up the new value on the next tick.
        """
        # Normalise status to lowercase string — the report layer uses
        # ``status.value`` which is already lowercase, but we don't
        # want to assume that for tests that mock a plain string.
        module_states[name] = str(status).lower() if status else "failed"

    async def _drive() -> Any:
        # Mark all as running first so the first Live tick shows motion
        # even before any module has completed.
        for name in module_states:
            module_states[name] = "running"
        return await run_domain_harvest(
            cleaned_domain,
            enable_smtp=verify_smtp,
            dork_lite_mode=cli_dork_lite_mode,
            cc_max_records=cli_cc_max_records,
            on_module_complete=_on_module_complete,
        )

    try:
        with Live(
            _format_progress_table(module_states, started),
            console=console,
            refresh_per_second=4,
            transient=True,
        ):
            result = asyncio.run(_drive())
    except ValueError as exc:
        # Domain validation / free-provider rejection.
        console.print(f"[red]Error:[/] {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] harvest failed: {exc}")
        return 3
    # MUST-FIX M3: no settings restoration needed — we never mutated
    # settings in the first place.

    # ------------------------------------------------------------------
    # 5. Apply S8 post-processing filters (display + export only).
    #    The underlying harvest is unchanged; we render / export a
    #    filtered COPY of the result. W5 adds the numeric
    #    ``min_confidence_score`` filter alongside the existing label
    #    filter.
    # ------------------------------------------------------------------
    if (
        min_confidence != "low"
        or min_confidence_score > 0.0
        or exclude_domains
        or on_domain_only
    ):
        result = _apply_filters(
            result,
            min_confidence=min_confidence,
            min_confidence_score=min_confidence_score,
            exclude_domains=tuple(exclude_domains),
            on_domain_only=on_domain_only,
            harvest_domain=cleaned_domain,
        )

    # ------------------------------------------------------------------
    # 6. Render CLI output.
    # ------------------------------------------------------------------
    console.print(format_harvest_cli_output(result))

    # ------------------------------------------------------------------
    # 7. Export (if --export). Format inferred from extension (S11).
    #    schema_version lives inside the JSON (S12) and inside each
    #    NDJSON row (S12).
    # ------------------------------------------------------------------
    if export:
        export_path = _resolve_export_path(export)
        export_path.parent.mkdir(parents=True, exist_ok=True)

        text, err = serialise_harvest_for_export(result, export_path)
        if err is not None:
            console.print(f"[red]Error:[/] {err}")
            return 4
        export_path.write_text(text, encoding="utf-8")
        console.print(f"[green]✓ Exported harvest to:[/] {export_path}")

    return 0