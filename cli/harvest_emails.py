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
* Runs bounded SMTP verification by default; ``--no-verify`` opts out.
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
import json
import os
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from backend.config import settings
from backend.core.domain_harvest_orchestrator import run_domain_harvest
from backend.core.domain_harvest_report import (
    format_harvest_cli_output,
    format_harvest_json_export,
    serialise_harvest_for_export,
)
from backend.core.email_extraction import validate_domain
from backend.core.harvest_cache import HarvestCache
from backend.core.harvest_diff import compare_harvest_exports
from backend.core.harvest_history import load_latest, save_latest
from backend.core.harvest_results import (
    HarvestResultFiles,
    results_paths,
    timestamp_slug,
    write_harvest_results,
)
from backend.core.name_classifier import is_ml_available
from backend.core.stealth_client import _CFFI_AVAILABLE


def _resolve_export_path(export: str) -> Path:
    p = Path(export)
    if p.is_absolute():
        return p
    return Path(os.getcwd()) / p


def _write_cidr_file(result: Any, timestamp: str) -> Path:
    """Legacy thin wrapper that delegates to :mod:`harvest_results`.

    The 0.12.6 release wrote the CIDR file to
    ``~/.mailaccess/results/{domain}_{timestamp}_cidrs.txt`` — this
    helper stays so existing callers keep working, but the canonical
    writer now lives in :func:`harvest_results.write_harvest_results`
    and the file path is the same.
    """
    from backend.core.harvest_results import results_paths as _paths

    paths = _paths(result.domain, timestamp)
    payload = format_harvest_json_export(result)
    prefixes = {
        str(prefix)
        for row in (payload.get("infrastructure") or {}).get("asns", [])
        if isinstance(row, dict)
        for prefix in (row.get("prefixes") or row.get("cidrs") or [])
        if prefix
    }
    output = paths["cidrs"]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(f"{prefix}\n" for prefix in sorted(prefixes)), encoding="utf-8"
    )
    return output


def _is_proxy_fail(status: str, errors: list[str]) -> bool:
    """Return True if status is PARTIAL and any error mentions proxy failure."""
    return (
        status == "partial"
        and any(
            "proxy" in e.lower() or "ProxyConnectionError" in e
            for e in errors
        )
    )


def _format_progress_table(
    states: dict[str, tuple[str, list[str]]], started_at: float
) -> Table:
    """Live progress table for the 8 harvest modules.

    M2: when a module is PARTIAL and its errors indicate a proxy failure,
    show ``PROXY FAIL`` in red instead of ``PARTIAL`` in yellow so analysts
    know whether to re-run with ``--proxy-fallback-ok``.
    """
    table = Table(title="Module Progress", box=None, header_style="bold cyan")
    table.add_column("Module", style="cyan")
    table.add_column("Status", justify="right")
    table.add_column("Time", justify="right", style="dim")
    elapsed = time.time() - started_at
    table.add_row("wall clock", "—", f"{elapsed:.1f}s")
    for name, (status, errors) in states.items():
        if _is_proxy_fail(status, errors):
            display = "[red]PROXY FAIL[/red]"
        else:
            color = {
                "queued": "dim",
                "running": "cyan",
                "success": "green",
                "failed": "red",
                "skipped": "dim",
                "partial": "yellow",
            }.get(status, "white")
            display = f"[{color}]{status.upper()}[/]"
        table.add_row(name, display, "—")
    return table


def calculate_eta(elapsed: float, completed_modules: int, total_modules: int) -> str:
    """Estimate remaining wall time from completed module throughput."""
    if completed_modules <= 0:
        return "calculating..."
    remaining = max(0.0, (total_modules - completed_modules) * (elapsed / completed_modules))
    minutes, seconds = divmod(int(round(remaining)), 60)
    return f"~{minutes}m{seconds:02d}s"


class LiveHarvestDisplay:
    """Two-panel Rich renderable fed by module and signal callbacks."""

    def __init__(self, modules: list[str], started_at: float, log_path: Path) -> None:
        self.started_at = started_at
        self.log_path = log_path
        self.states = {
            name: {"status": "queued", "found": 0, "action": "—", "errors": []}
            for name in modules
        }
        self.latest_finds: deque[tuple[str, str, str, str]] = deque(maxlen=5)
        self.counts = {"email": 0, "name": 0, "subdomain": 0}
        # 0.12.7: track per-module start time so the [MODULE] completed
        # event can report "(N emails, 12.3s)" without re-deriving it
        # from the orchestrator.
        self._module_started_at: dict[str, float] = {}
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch(exist_ok=True)

    def _log(self, event: str, message: str) -> None:
        """Write one event line to the live log (HH:MM:SS prefix)."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"[{timestamp}] [{event.upper()}] {message}\n")
        except OSError:
            # Never let a logging error crash the harvest.
            pass

    def log_event(self, event: str, message: str) -> None:
        """Append a structured log event from the wider harvest flow.

        Used for [START], [SMTP], [CACHE], [WARN], [SAVED], [END]
        events that originate outside the module-progress callback.
        Writes are intentionally synchronous: this method runs from
        Rich's Live() render thread, not the asyncio loop, so an
        ``asyncio.to_thread`` indirection would be wasted overhead.
        File I/O for one line append is sub-millisecond on a local
        disk and never observed to block the harvest.
        """
        self._log(event, message)

    async def alog_event(self, event: str, message: str) -> None:
        """Async sibling of :meth:`log_event`.

        Used by callers that already hold the asyncio event loop
        (e.g. the post-harvest export / cleanup flow).  The file I/O
        is dispatched through :func:`asyncio.to_thread` so the
        harvest's coroutines are never blocked waiting for the log
        write to drain — this is the spec's
        "log writes must never block the harvest" requirement.
        """
        line = f"[{datetime.now().strftime('%H:%M:%S')}] [{event.upper()}] {message}\n"
        try:
            await asyncio.to_thread(self._append_line, line)
        except OSError:
            pass

    def _append_line(self, line: str) -> None:
        try:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            pass

    def progress(self, module: str, action: str) -> None:
        state = self.states.setdefault(
            module,
            {"status": "running", "found": 0, "action": "—", "errors": []},
        )
        state["status"] = "running"
        state["action"] = action
        if module not in self._module_started_at:
            self._module_started_at[module] = time.monotonic()
        self._log("MODULE", f"{module} started")

    def complete(self, module: str, status: str, errors: list[str] | None = None) -> None:
        state = self.states.setdefault(
            module,
            {"status": "queued", "found": 0, "action": "—", "errors": []},
        )
        normalized = str(status or "failed").lower()
        state.update(status=normalized, action="—", errors=list(errors or []))
        # [MODULE] completed (N emails, 12.3s) — N is the per-module
        # `found` counter, duration is wall time since the module
        # started running.
        started = self._module_started_at.pop(module, None)
        if started is None:
            duration_text = "0.0s"
        else:
            duration_text = f"{time.monotonic() - started:.1f}s"
        count = state.get("found", 0)
        self._log(
            "MODULE",
            f"{module} completed ({count} items, {duration_text})",
        )

    def signal(self, signal: Any) -> None:
        kind = str(getattr(signal, "kind", "finding"))
        source = str(getattr(signal, "source", "unknown"))
        value = str(getattr(signal, "value", ""))
        metadata = getattr(signal, "metadata", {}) or {}
        if kind in self.counts:
            self.counts[kind] += 1
        if source in self.states:
            self.states[source]["found"] += 1
        confidence = str(
            metadata.get("confidence_label")
            or metadata.get("tier")
            or metadata.get("confidence")
            or "unverified"
        )
        self.latest_finds.append((kind, value, source, confidence))
        # [FOUND] is the spec's per-event log line for every email /
        # name / subdomain added to the signal pool.
        self._log("FOUND", f"{kind} {value} (source={source}, confidence={confidence})")

    def __rich__(self) -> Layout:
        table = Table(box=None, header_style="bold cyan", expand=True)
        table.add_column("Module")
        table.add_column("Status")
        table.add_column("Found", justify="right")
        table.add_column("Current action", overflow="ellipsis")
        icons = {
            "success": "✓ done",
            "done": "✓ done",
            "running": "⠋ running",
            "failed": "✗ failed",
            "partial": "✗ blocked",
            "skipped": "— skipped",
            "queued": "· queued",
        }
        for module, state in self.states.items():
            table.add_row(
                module,
                icons.get(state["status"], state["status"]),
                str(state["found"]),
                str(state["action"]),
            )

        elapsed = max(0.0, time.monotonic() - self.started_at)
        completed = sum(
            state["status"] in {"success", "done", "failed", "partial", "skipped"}
            for state in self.states.values()
        )
        eta = calculate_eta(elapsed, completed, len(self.states))
        ticker = Text()
        ticker.append(
            f"Emails found: {self.counts['email']}  ·  Names: {self.counts['name']}  ·  "
            f"Subdomains: {self.counts['subdomain']}  ·  Elapsed: {int(elapsed // 60)}m"
            f"{int(elapsed % 60):02d}s  ·  ETA: {eta}\n\n"
        )
        ticker.append("Latest finds:\n", style="bold")
        for kind, value, source, confidence in self.latest_finds:
            marker = "✓" if kind == "email" else ("?" if kind == "subdomain" else "≈")
            ticker.append(f"  {marker} {value:<32} [{source} · {confidence}]\n")
        layout = Layout()
        layout.split_column(
            Layout(Panel(table, title="Module status"), ratio=3),
            Layout(Panel(ticker, title="Live ticker"), ratio=2),
        )
        return layout

    def __rich_console__(self, console: Console, options: Any):
        yield self.__rich__()


def _confidence_label_passes(min_confidence: str, label: str) -> bool:
    """Return True if *label* meets the *min_confidence* threshold.

    MUST-FIX S8: filtering helper. Order from laxest to strictest:
        low < medium < likely < confirmed
    A filter of ``"low"`` is a no-op (passes everything). A filter of
    ``"confirmed"`` passes only the top tier. Unknown labels default
    to ``"low"`` (defensive — never silently drop unknown).

    P7: the legacy ``"high"`` and ``"medium"`` tokens are still
    accepted for backward compatibility — ``"high"`` is a synonym
    for the new ``"confirmed"`` (the most conservative mapping —
    the legacy 3-tier HIGH bucket = the 4-tier CONFIRMED bucket);
    ``"medium"`` is a synonym for the new ``"likely"`` (any
    actionable-but-not-confirmed hit).
    """
    # Tier order, highest first.  Legacy aliases are mapped to
    # their new-tier equivalents BEFORE the order lookup so the
    # rest of the function never has to think about the old
    # vocabulary.
    legacy_aliases = {
        "high": "confirmed",
        "medium": "likely",
    }
    resolved_min = legacy_aliases.get(min_confidence.lower(), min_confidence.lower())
    resolved_label = legacy_aliases.get(str(label).lower(), str(label).lower())
    order = {
        "low": 0,
        "medium": 1,
        "likely": 2,
        "confirmed": 3,
    }
    return order.get(resolved_label, 0) >= order.get(resolved_min, 0)


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
    # emails tier (CONFIRMED / LIKELY / MEDIUM / LOW) is filtered.
    return type(result)(
        domain=result.domain,
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_seconds=result.duration_seconds,
        module_results=result.module_results,
        unique_emails=filtered_emails,
        total_unique_emails=len(filtered_emails),
        # P7: tier counts are PERSONAL-only — match the
        # orchestrator's semantics so the filtered summary stays
        # consistent with the unfiltered one.  We use the 4-tier
        # label set here; the *-confidence_count field names are
        # kept for backward compatibility with the
        # DomainHarvestResult dataclass — the new
        # ``likely_confidence_count`` field gives downstream
        # consumers the LIKELY-tier count.
        high_confidence_count=sum(
            1
            for e in filtered_emails
            if e.confidence_label == "CONFIRMED" and not e.is_role
        ),
        likely_confidence_count=sum(
            1
            for e in filtered_emails
            if e.confidence_label == "LIKELY" and not e.is_role
        ),
        medium_confidence_count=sum(
            1
            for e in filtered_emails
            if e.confidence_label in {"LIKELY", "MEDIUM"} and not e.is_role
        ),
        low_confidence_count=sum(
            1
            for e in filtered_emails
            if e.confidence_label == "LOW" and not e.is_role
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
        fetch_cache_stats=result.fetch_cache_stats,
        metadata=dict(getattr(result, "metadata", {}) or {}),
    )


def run_harvest_emails(
    domain: str | None,
    no_verify: bool = False,
    verify_m365: bool = False,
    verify_yahoo: bool = False,
    use_proxies: bool = False,
    proxy_fallback_ok: bool = False,
    lite: bool = False,
    export: str | None = None,
    compare_to: str | None = None,
    skip_modules: tuple[str, ...] = (),
    max_cc_records: int | None = None,
    cc_max_collections: int | None = None,
    console: Console | None = None,
    *,
    min_confidence: str = "low",
    min_confidence_score: float = 0.0,
    exclude_domains: tuple[str, ...] = (),
    on_domain_only: bool = False,
    show_low: bool = False,
    hide_low: bool = False,
    enable_ml: bool = False,
    show_unverified_patterns: bool = False,
    show_role: bool = False,
    show_personal: bool = False,
    full: bool = False,
    aggressive: bool = False,
    timeout_seconds: int | None = None,
    with_subdomains: bool = False,
    subdomain_deep: bool = False,
    no_subdomains: bool = False,
    subdomain_calibrate: bool = False,
    force: bool = False,
    clear_cache: bool = False,
    clear_all_cache: bool = False,
    no_export: bool = False,
    no_extras: bool = False,
) -> int:
    """Run the domain email harvest and render / export results.

    Returns a process-style exit code (0 on success, non-zero on
    validation error or total failure).
    """
    if console is None:
        console = Console()

    cache = HarvestCache()
    if clear_all_cache:
        cache.invalidate_all()
        console.print("[green]✓ Cleared all harvest cache entries.[/green]")
        return 0

    # ------------------------------------------------------------------
    # 1. Validate domain — explicit error, do NOT proceed.
    # ------------------------------------------------------------------
    try:
        if not domain:
            console.print("[red]Error:[/] --domain is required for this operation.")
            return 2
        cleaned_domain = domain.strip().lower()
        from backend.modules.domain_intel import _FREE_PROVIDERS

        if cleaned_domain in _FREE_PROVIDERS:
            console.print(
                f"[red]Error:[/] {cleaned_domain} is a free email provider; "
                "use a corporate or organizational domain."
            )
            return 2
        if not validate_domain(cleaned_domain, reject_free_provider=True):
            console.print(
                "[red]Error:[/] --domain must be a valid non-free domain "
                "(e.g. --domain example.com)"
            )
            return 2
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] {exc}")
        return 2

    if clear_cache:
        cache.invalidate(cleaned_domain)
        console.print(f"[green]✓ Cleared harvest cache for {cleaned_domain}.[/green]")
        return 0
    if force:
        cache.invalidate(cleaned_domain)

    if not _CFFI_AVAILABLE:
        console.print(
            "harvest-emails requires the harvest extra. Run: "
            "pip install 'mailaccess[harvest]' then retry.",
            markup=False,
        )
        return 2

    # ML is strictly opt-in per invocation. A persisted profile preference
    # must not make the first run interactive or enable a heavyweight model.
    ml_enabled_for_run = bool(enable_ml)
    if enable_ml and not is_ml_available():
        console.print("[red]ML name classifier is unavailable.[/] Install it with:")
        console.print("  pip install mailaccess[ml]", markup=False)
        console.print("  python -m spacy download en_core_web_md", markup=False)
        return 2

    original_ml_pref = settings.ml_name_classifier
    if enable_ml:
        settings.ml_name_classifier = "on"

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
    # 0.11.1 Phase 5: aggressive mode bumps CC collections to 24.
    if aggressive and cc_max_collections is None:
        cli_cc_max_collections = 24
    else:
        cli_cc_max_collections = cc_max_collections

    # ------------------------------------------------------------------
    enable_smtp = bool(getattr(settings, "smtp_verify_default", True)) and not no_verify

    # 3. Explain the default-on SMTP behavior and its bounded safety limits.
    # ------------------------------------------------------------------
    if enable_smtp:
        console.print(
            "[yellow]⚠ SMTP verification runs by default — probing up to "
            "10 addresses via RCPT TO. This is a passive OSINT "
            "technique (no emails sent) but uses your network "
            "connection to contact target mail servers directly.[/yellow]"
        )
    # 0.11.1 Phase 2: surface aggressive mode visibly so analysts
    # know the harvest is using looser thresholds.
    if aggressive:
        console.print(
            "[yellow]⚠ Aggressive harvest mode — body-text name "
            "extraction enabled. Expect more LOW-quality findings.[/yellow]"
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
    module_names = [
        "commoncrawl_email", "code_and_cert_email", "email_search_dork",
        "employee_name_discovery", "npm_email", "pypi_email",
        "pgp_domain_email", "github_domain_commits", "pattern_and_verify",
        "subdomain_intel", "persona_email_pivot",
    ]
    started = time.monotonic()
    timestamp = timestamp_slug()
    live_log = results_paths(cleaned_domain, timestamp)["live_log"]
    # 0.12.7: --no-export skips BOTH the JSON and the live log file
    # (per spec).  When the user opts out, we render the progress
    # display without a backing log file and skip the [START] event
    # so nothing is written to disk.
    if no_export:
        display = LiveHarvestDisplay(module_names, started, Path(os.devnull))
    else:
        display = LiveHarvestDisplay(module_names, started, live_log)
    # 0.12.7: emit [START] event to the live log so analysts can
    # `tail -f` the file from the moment the harvest begins.  The
    # command line is the spec's "what was actually invoked" view,
    # and the version comes from the same source the CLI banner uses.
    from backend.config import APP_VERSION as _APP_VERSION

    display.log_event(
        "START",
        f"harvest-emails --domain {cleaned_domain} v{_APP_VERSION}",
    )
    console.print(f"[dim]Live log: {live_log}[/dim]")
    effective_skip_modules = tuple(skip_modules) + (("subdomain_intel",) if no_subdomains else ())

    def _on_module_complete(
        name: str, status: str, errors: list[str] | None = None
    ) -> None:
        """Update the module_states dict in-place when a module finishes.

        MUST-FIX S5: this is the callback that fixes the cosmetic-only
        progress display. It's intentionally *synchronous* —
        ``rich.live.Live`` re-renders its renderable on every refresh
        tick, so all the Live display needs is for the underlying
        ``module_states`` dict to mutate under it.

        M2: errors are stored alongside status so the live table can
        render ``PROXY FAIL`` for modules whose PARTIAL was caused by a
        proxy connection failure.
        """
        display.complete(name, status, errors)

    async def _drive() -> Any:
        return await run_domain_harvest(
            cleaned_domain,
            enable_smtp=enable_smtp,
            enable_m365=verify_m365,
            enable_yahoo=verify_yahoo,
            use_proxies=use_proxies,
            proxy_fallback_ok=proxy_fallback_ok,
            dork_lite_mode=cli_dork_lite_mode,
            cc_max_records=cli_cc_max_records,
            cc_max_collections=cli_cc_max_collections,
            on_module_complete=_on_module_complete,
            timeout_seconds=timeout_seconds,
            skip_modules=effective_skip_modules,
            with_subdomains=with_subdomains,
            subdomain_deep=subdomain_deep,
            subdomain_calibrate=subdomain_calibrate,
            progress_callback=display.progress,
            display_subscriber=display.signal,
            force=force,
        )

    try:
        try:
            with Live(
                display,
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
    finally:
        settings.ml_name_classifier = original_ml_pref
    # MUST-FIX M3: no settings restoration needed — we never mutated
    # settings in the first place.

    if result.from_cache:
        age_minutes = max(0, int(result.cache_age_seconds // 60))
        age_text = (
            "just now" if age_minutes == 0 else f"{age_minutes} minute"
            + ("" if age_minutes == 1 else "s")
            + " ago"
        )
        display.log_event("CACHE", f"hit ({age_text})")
        console.print(
            f"[bold cyan]⚡ Cached result ({age_text}) — use --force to re-run[/bold cyan]"
        )
    else:
        display.log_event("CACHE", "miss")

    # SMTP log lines — one [SMTP] event per probe outcome.  We pull
    # the per-email smtp_validation metadata out of the module's
    # result; if SMTP was disabled, we emit a single [SMTP] disabled
    # line so analysts can see the gate decision in the log.
    try:
        smtp_meta = ((result.module_results or {}).get("pattern_and_verify") or _Empty()).metadata
    except Exception:
        smtp_meta = None
    if not enable_smtp:
        display.log_event("SMTP", "disabled (--no-verify)")
    else:
        smtp_validation_meta: dict[str, Any] = {}
        for module_result in (result.module_results or {}).values():
            meta = module_result.metadata if module_result else None
            if isinstance(meta, dict) and "smtp_email_verification" in meta:
                smtp_validation_meta = meta.get("smtp_email_verification") or {}
                break
        # Walk findings to emit per-email [SMTP] events.
        probe_count = 0
        for module_result in (result.module_results or {}).values():
            for finding in module_result.findings or []:
                meta = finding.get("metadata") or {}
                if not isinstance(meta, dict):
                    continue
                smtp_validation = meta.get("smtp_validation")
                if not isinstance(smtp_validation, dict):
                    continue
                probe_count += 1
                email = str(smtp_validation.get("email") or finding.get("metadata", {}).get("email") or "").strip().lower()
                code = smtp_validation.get("response_code") or "?"
                status = smtp_validation.get("status") or "inconclusive"
                if email:
                    if status == "verified" or smtp_validation.get("exists") is True:
                        display.log_event("SMTP", f"probing {email} → confirmed ({code})")
                    elif status == "not_found" or smtp_validation.get("exists") is False:
                        display.log_event("SMTP", f"probing {email} → not found ({code})")
                    else:
                        display.log_event("SMTP", f"probing {email} → {status} ({code})")
        if probe_count == 0 and not smtp_validation_meta:
            display.log_event("SMTP", "no candidates to probe")

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
    # 6. Render CLI output.  Phase 1 of 4: pass the four display flags
    #    through to ``format_harvest_cli_output``.  ``full`` is the
    #    restore-legacy alias and is handled inside the formatter itself.
    # ------------------------------------------------------------------
    console.print(
        format_harvest_cli_output(
            result,
            show_low=show_low,
            hide_low=hide_low,
            show_unverified_patterns=show_unverified_patterns,
            show_role=show_role,
            show_personal=show_personal,
            full=full,
            with_subdomains=with_subdomains,
        )
    )
    if result.employee_names_processed and not ml_enabled_for_run:
        console.print(
            "[dim]Tip: run with --enable-ml for improved name filtering\n"
            "  (requires: pip install mailaccess[ml] + "
            "python -m spacy download en_core_web_md)[/dim]"
        )

    # M2: if any module had a proxy failure, show a hint.
    proxy_failed = any(
        _is_proxy_fail(str(state["status"]), list(state["errors"]))
        for state in display.states.values()
    )
    if proxy_failed:
        console.print(
            "[dim]One or more modules failed to connect via ScrapingAnt proxy. "
            "Run with --proxy-fallback-ok to allow direct fallback.[/dim]"
        )

    # ------------------------------------------------------------------
    # 7. Export (default JSON + supplementary + optional --export).
    #    0.12.7: the default export is ALWAYS written unless
    #    --no-export; the legacy --export flag is honoured by writing
    #    BOTH the default path AND the explicit path.
    # ------------------------------------------------------------------
    comparison: dict[str, Any] | None = None
    previous_payload: dict[str, Any] | None = None
    if compare_to:
        try:
            previous = json.loads(Path(compare_to).read_text(encoding="utf-8"))
            previous_payload = previous if isinstance(previous, dict) else None
        except Exception as exc:
            console.print(f"[yellow]Harvest comparison skipped:[/] {exc}")
    elif getattr(settings, "enable_harvest_history_cache", True):
        previous_payload = load_latest(cleaned_domain)

    if previous_payload:
        try:
            current = json.loads(serialise_harvest_for_export(result, "comparison.json")[0])
            comparison = compare_harvest_exports(previous_payload, current)
            console.print(
                f"[cyan]Harvest diff:[/] +{len(comparison['emails']['new'])} new emails, "
                f"-{len(comparison['emails']['removed'])} removed, "
                f"{comparison['emails']['unchanged']} unchanged"
            )
        except Exception as exc:
            console.print(f"[yellow]Harvest comparison skipped:[/] {exc}")

    # Resolve the explicit --export target (when provided).
    extra_export_path: Path | None = None
    if export:
        extra_export_path = _resolve_export_path(export)
        text, err = serialise_harvest_for_export(result, extra_export_path, comparison=comparison)
        if err is not None:
            console.print(f"[red]Error:[/] {err}")
            return 4
        extra_export_path.parent.mkdir(parents=True, exist_ok=True)
        extra_export_path.write_text(text, encoding="utf-8")
        console.print(f"[green]✓ Exported harvest to:[/] {extra_export_path}")

    # Always-on default export + supplementary files (gated by
    # ``harvest_auto_export`` setting and ``--no-export`` / ``--no-extras``).
    auto_export_enabled = bool(getattr(settings, "harvest_auto_export", True)) and not no_export
    written = HarvestResultFiles()
    if auto_export_enabled:
        written = asyncio.run(
            write_harvest_results(
                result,
                timestamp=timestamp,
                no_export=False,
                no_extras=no_extras,
                extra_export_path=extra_export_path,
            )
        )
        # 0.12.7 — print every written file.  The legacy
        # ``Results saved:`` style header is preserved for grep-friendly
        # log scraping.
        if written.all_written():
            console.print("[green]Results saved:[/green]")
            for path in written.all_written():
                console.print(f"  {path}")
                display.log_event("SAVED", str(path))
    elif extra_export_path is None:
        console.print(
            "[dim]Default JSON export skipped (--no-export or HARVEST_AUTO_EXPORT=false)[/dim]"
        )

    # Emit the [END] event on the live log now that all exports are
    # done.  The summary numbers mirror the orchestrator's counts so
    # analysts can grep the live log for harvest completion.
    duration_seconds = max(0.001, time.monotonic() - started)
    minutes, seconds = divmod(int(duration_seconds), 60)
    duration_text = f"{minutes}m{seconds:02d}s"
    n_emails = int(getattr(result, "total_unique_emails", 0) or 0)
    n_names = int(getattr(result, "employee_names_processed", 0) or 0)
    n_subdomains = 0
    for module_result in (result.module_results or {}).values():
        for finding in module_result.findings or []:
            if isinstance(finding, dict) and (
                finding.get("subdomain") is not None
                or (isinstance(finding.get("metadata"), dict)
                    and finding["metadata"].get("subdomain") is not None)
            ):
                n_subdomains += 1
    display.log_event(
        "END",
        f"harvest complete: {n_emails} emails, {n_names} names, "
        f"{n_subdomains} subdomains ({duration_text})",
    )

    if getattr(settings, "enable_harvest_history_cache", True):
        try:
            latest = json.loads(serialise_harvest_for_export(result, "history.json")[0])
            if save_latest(cleaned_domain, latest):
                console.print("[dim]Saved latest harvest baseline.[/dim]")
        except Exception as exc:
            console.print(f"[dim]Harvest history cache unavailable: {exc}[/dim]")

    return 0


class _Empty:
    """Sentinel object whose ``metadata`` is an empty dict.

    Used as the fallback when a module is missing from
    ``result.module_results`` so the SMTP-log loop does not have to
    branch on ``None``.
    """

    metadata: dict[str, Any] = {}


# The default-JSON + supplementary export + END-event emission is
# performed by the unified block in :func:`run_harvest_emails` so the
# analyst always sees a consistent ``Results saved:`` footer and a
# ``[END]`` entry on the live log.  Anything written before this point
# (e.g. an explicit ``--export`` path) is also surfaced in that footer
# via :data:`written` / :data:`extra_export_path`.
