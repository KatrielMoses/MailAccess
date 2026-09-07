"""Phase 5C — CLI driver for the company discovery pipeline.

``mailaccess discover --industry X [--geo Y] [--size Z]`` turns a market segment
into a ranked list of candidate company domains (its own discovery confidence,
never contact confidence), and — with ``--output`` — writes a CSV that
``harvest-emails --file`` consumes directly (the 5C→5A hand-off).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from rich.console import Console

from backend.core.company_discovery import (
    DiscoveryQuery,
    discover_companies,
    discovery_to_csv,
)


def run_discover(
    industry: str,
    *,
    geo: str = "",
    size: str = "",
    limit: int = 25,
    mode: str | None = None,
    output: str | None = None,
    json_output: str | None = None,
    console: Console | None = None,
) -> int:
    """Run discovery and render/export the ranked candidate list."""
    if console is None:
        console = Console()

    if not industry or not industry.strip():
        console.print("[red]Error:[/] --industry is required.")
        return 2

    query = DiscoveryQuery(
        industry=industry.strip(), geo=geo.strip(), size=size.strip(), limit=limit
    )
    console.print(
        f"[bold cyan]Company discovery[/] — industry={query.industry!r} "
        f"geo={query.geo or '-'} size={query.size or '-'} "
        f"(mode {mode or 'public-business-contact'})"
    )

    try:
        result = asyncio.run(discover_companies(query, mode=mode))
    except ValueError as exc:  # bad --mode
        console.print(f"[red]Error:[/] {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] discovery failed: {exc}")
        return 3

    _render(result, console)

    if output:
        out_path = Path(output)
        if not out_path.is_absolute():
            out_path = Path.cwd() / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(discovery_to_csv(result), encoding="utf-8")
        console.print(
            f"[green]Wrote {len(result.candidates)} domain(s):[/] {out_path}\n"
            f"[dim]Feed the harvester: mailaccess harvest-emails --file {out_path}[/dim]"
        )
    if json_output:
        jpath = Path(json_output)
        if not jpath.is_absolute():
            jpath = Path.cwd() / jpath
        jpath.parent.mkdir(parents=True, exist_ok=True)
        jpath.write_text(json.dumps(result.as_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Wrote discovery JSON:[/] {jpath}")

    if not result.candidates:
        console.print("[yellow]No candidate domains found for this segment.[/]")
    return 0


def _render(result, console: Console) -> None:
    from rich.table import Table

    table = Table(title=f"Candidate companies ({len(result.candidates)})", show_edge=True)
    table.add_column("#", justify="right")
    table.add_column("domain")
    table.add_column("company")
    table.add_column("discovery conf.", justify="right")
    table.add_column("label")
    table.add_column("sources")
    for i, c in enumerate(result.candidates, 1):
        colour = (
            "green" if c.discovery_confidence_label == "STRONG"
            else "yellow" if c.discovery_confidence_label == "MODERATE"
            else "dim"
        )
        table.add_row(
            str(i), c.domain, (c.company_name or "—")[:32],
            f"{c.discovery_confidence:.2f}",
            f"[{colour}]{c.discovery_confidence_label}[/{colour}]",
            ", ".join(c.discovery_sources),
        )
    console.print(table)
    # per-stage review line (each stage independently reviewable)
    stage_bits = [
        f"{s.stage}={s.domains_found}" + (f" (err: {s.error[:40]})" if s.error else "")
        for s in result.stages
    ]
    console.print(f"[dim]Stages: {'  '.join(stage_bits)}[/dim]")
    console.print(
        "[dim]discovery_confidence is a segment-match claim — NOT contact/email "
        "deliverability.[/dim]"
    )
