"""Phase 5A — CLI driver for bulk / list harvest mode.

``mailaccess harvest-emails --file domains.csv`` (or ``--file -`` for stdin)
fans the domain list through the governed, resumable bulk orchestrator
(:mod:`backend.core.bulk_harvest`) and renders a batch progress/summary. The
per-domain option resolution here mirrors the single-domain
:func:`cli.harvest_emails.run_harvest_emails` exactly so a domain harvested in a
batch yields the same result it would solo (Phase 5A parity requirement).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from rich.console import Console

from backend.config import settings
from backend.core.bulk_harvest import (
    BulkHarvestReport,
    DomainOutcome,
    parse_domain_list,
    run_bulk_harvest,
)


def _read_domain_source(file_arg: str, console: Console) -> str | None:
    """Return the raw text of the domain list, from ``-`` (stdin) or a path."""
    if file_arg == "-":
        return sys.stdin.read()
    path = Path(file_arg)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        console.print(f"[red]Error:[/] domain list file not found: {path}")
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] could not read {path}: {exc}")
        return None


def run_bulk_harvest_emails(
    file_arg: str,
    *,
    no_verify: bool = False,
    verify_m365: bool = False,
    verify_yahoo: bool = False,
    use_proxies: bool = False,
    proxy_fallback_ok: bool = False,
    lite: bool = False,
    skip_modules: tuple[str, ...] = (),
    max_cc_records: int | None = None,
    cc_max_collections: int | None = None,
    aggressive: bool = False,
    timeout_seconds: int | None = None,
    with_subdomains: bool = False,
    subdomain_deep: bool = False,
    no_subdomains: bool = False,
    subdomain_calibrate: bool = False,
    enable_ml: bool = False,
    force: bool = False,
    no_export: bool = False,
    mode: str | None = None,
    concurrency: int | None = None,
    checkpoint: str | None = None,
    merged_export: str | None = None,
    resume: bool = True,
    tech_filters: tuple[str, ...] = (),
    console: Console | None = None,
) -> int:
    """Drive a bulk harvest run. Returns a process-style exit code."""
    if console is None:
        console = Console()

    raw = _read_domain_source(file_arg, console)
    if raw is None:
        return 2

    domains, rejected = parse_domain_list(raw)
    if rejected:
        console.print(
            f"[yellow]⚠ Skipped {len(rejected)} invalid/free-provider "
            f"line(s):[/] {', '.join(rejected[:8])}"
            + (" …" if len(rejected) > 8 else "")
        )
    if not domains:
        console.print("[red]Error:[/] no valid domains found in the list.")
        return 2

    # ML is strictly opt-in; mutate once for the whole batch (restored below),
    # mirroring the single-domain path's per-run behaviour.
    from backend.core.name_classifier import is_ml_available

    if enable_ml and not is_ml_available():
        console.print("[red]ML name classifier is unavailable.[/] Install it with:")
        console.print("  pip install mailaccess[ml]", markup=False)
        return 2
    original_ml_pref = settings.ml_name_classifier
    if enable_ml:
        settings.ml_name_classifier = "on"

    # --- resolve per-domain options exactly as run_harvest_emails does -----
    enable_smtp = bool(getattr(settings, "smtp_verify_default", True)) and not no_verify
    dork_lite_mode = bool(lite) if lite else None
    cc_max = max(1, int(max_cc_records)) if max_cc_records is not None else None
    if aggressive and cc_max_collections is None:
        cc_collections = 24
    else:
        cc_collections = cc_max_collections
    effective_skip = tuple(skip_modules) + (("subdomain_intel",) if no_subdomains else ())

    options = {
        "enable_smtp": enable_smtp,
        "enable_m365": verify_m365,
        "enable_yahoo": verify_yahoo,
        "use_proxies": use_proxies,
        "proxy_fallback_ok": proxy_fallback_ok,
        "dork_lite_mode": dork_lite_mode,
        "cc_max_records": cc_max,
        "cc_max_collections": cc_collections,
        "timeout_seconds": timeout_seconds,
        "skip_modules": effective_skip,
        "with_subdomains": with_subdomains,
        "subdomain_deep": subdomain_deep,
        "subdomain_calibrate": subdomain_calibrate,
    }

    conc = max(1, int(concurrency or getattr(settings, "bulk_max_concurrent_domains", 3)))
    console.print(
        f"[bold cyan]Bulk harvest[/] — {len(domains)} domain(s), "
        f"concurrency {conc}, mode {mode or settings.product_mode}"
    )
    if enable_smtp:
        console.print(
            "[yellow]⚠ SMTP verification runs by default across the batch "
            "(--no-verify to skip).[/yellow]"
        )

    checkpoint_path = None
    if checkpoint:
        checkpoint_path = Path(checkpoint)
        if not checkpoint_path.is_absolute():
            checkpoint_path = Path.cwd() / checkpoint_path
    merged_export_path = None
    if merged_export:
        merged_export_path = Path(merged_export)
        if not merged_export_path.is_absolute():
            merged_export_path = Path.cwd() / merged_export_path

    def _progress(outcome: DomainOutcome, counts: dict[str, int]) -> None:
        done = counts.get("total", 0)
        marker = {
            "done": "✓",
            "cached": "⚡",
            "skipped": "↷",
            "failed": "✗",
        }.get(outcome.status, "•")
        colour = "green" if outcome.status in {"done", "cached"} else (
            "red" if outcome.status == "failed" else "yellow"
        )
        detail = (
            f"{outcome.emails} emails" if outcome.status in {"done", "cached"}
            else (outcome.error or outcome.status)
        )
        console.print(
            f"[{colour}]{marker}[/] [{done}/{len(domains)}] {outcome.domain} — {detail}"
        )

    try:
        report = asyncio.run(
            run_bulk_harvest(
                domains,
                options=options,
                mode=mode,
                concurrency=conc,
                checkpoint_path=checkpoint_path,
                merged_export_path=merged_export_path,
                no_export=no_export,
                force=force,
                resume=resume,
                tech_filters=list(tech_filters),
                progress_callback=_progress,
            )
        )
    except KeyboardInterrupt:
        console.print(
            "[yellow]Bulk harvest interrupted — progress saved to the checkpoint; "
            "re-run the same file to resume.[/]"
        )
        return 130
    finally:
        settings.ml_name_classifier = original_ml_pref

    _render_summary(report, console)
    counts = report.counts
    # Non-zero only if every domain failed (a partial batch is still a success).
    if counts.get("failed", 0) == counts.get("total", 0) and counts.get("total", 0) > 0:
        return 3
    return 0


def _render_summary(report: BulkHarvestReport, console: Console) -> None:
    from rich.table import Table

    counts = report.counts
    table = Table(title=f"Bulk harvest {report.bulk_run_id}", show_edge=True)
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("domains", str(counts.get("total", 0)))
    table.add_row("harvested", str(counts.get("done", 0)))
    table.add_row("cached", str(counts.get("cached", 0)))
    table.add_row("skipped (resumed)", str(counts.get("skipped", 0)))
    table.add_row("failed", str(counts.get("failed", 0)))
    table.add_row("unique contacts", str(counts.get("contacts", 0)))
    table.add_row("duration", f"{report.duration_seconds:.1f}s")
    console.print(table)
    console.print(f"[dim]Checkpoint: {report.checkpoint_path}[/dim]")
    if report.merged_export_path:
        console.print(f"[green]Merged export:[/] {report.merged_export_path}")
